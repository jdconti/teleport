/*
Copyright 2018-2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
)

// ForAuth sets up watch configuration for the auth server
func ForAuth(cfg Config) Config {
	cfg.target = "auth"
	cfg.Watches = []services.WatchKind{
		{Kind: services.KindCertAuthority, LoadSecrets: true},
		{Kind: services.KindClusterName},
		{Kind: services.KindClusterConfig},
		{Kind: services.KindStaticTokens},
		{Kind: services.KindToken},
		{Kind: services.KindUser},
		{Kind: services.KindRole},
		{Kind: services.KindNamespace},
		{Kind: services.KindNode},
		{Kind: services.KindProxy},
		{Kind: services.KindAuthServer},
		{Kind: services.KindReverseTunnel},
		{Kind: services.KindTunnelConnection},
		{Kind: services.KindAccessRequest},
	}
	cfg.QueueSize = defaults.AuthQueueSize
	return cfg
}

// ForProxy sets up watch configuration for proxy
func ForProxy(cfg Config) Config {
	cfg.target = "proxy"
	cfg.Watches = []services.WatchKind{
		{Kind: services.KindCertAuthority, LoadSecrets: false},
		{Kind: services.KindClusterName},
		{Kind: services.KindClusterConfig},
		{Kind: services.KindUser},
		{Kind: services.KindRole},
		{Kind: services.KindNamespace},
		{Kind: services.KindNode},
		{Kind: services.KindProxy},
		{Kind: services.KindAuthServer},
		{Kind: services.KindReverseTunnel},
		{Kind: services.KindTunnelConnection},
	}
	cfg.QueueSize = defaults.ProxyQueueSize
	return cfg
}

// ForNode sets up watch configuration for node
func ForNode(cfg Config) Config {
	cfg.target = "node"
	cfg.Watches = []services.WatchKind{
		{Kind: services.KindCertAuthority, LoadSecrets: false},
		{Kind: services.KindClusterName},
		{Kind: services.KindClusterConfig},
		{Kind: services.KindUser},
		{Kind: services.KindRole},
		// Node only needs to "know" about default
		// namespace events to avoid matching too much
		// data about other namespaces or node events
		{Kind: services.KindNamespace, Name: defaults.Namespace},
	}
	cfg.QueueSize = defaults.NodeQueueSize
	return cfg
}

// SetupConfigFn is a function that sets up configuration
// for cache
type SetupConfigFn func(c Config) Config

// Cache implements auth.AccessPoint interface and remembers
// the previously returned upstream value for each API call.
//
// This which can be used if the upstream AccessPoint goes offline
type Cache struct {
	Config

	// Entry is a logging entry
	*log.Entry

	// rw is used to prevent reads of invalid cache states.  From a
	// memory-safety perspective, this RWMutex is just used to protect
	// the `ok` field.  *However*, cache reads must hold the read lock
	// for the duration of the read, not just when checking the `ok`
	// field.  Since the write lock must be held in order to modify
	// the `ok` field, this serves to ensure that all in-progress reads
	// complete *before* a reset can begin.
	rw sync.RWMutex
	// ok indicates whether the cache is in a valid state for reads.
	// If `ok` is `false`, reads are forwarded directly to the backend.
	ok bool

	// initOnce protects initC and initErr.
	initOnce sync.Once
	// initC is closed on the first attempt to initialize the
	// cache, whether or not it is successful.  Once initC
	// has returned, initErr is safe to read.
	initC chan struct{}
	// initErr is set if the first attempt to initialize the cache
	// fails.
	initErr error

	// wrapper is a wrapper around cache backend that
	// allows to set backend into failure mode,
	// intercepting all calls and returning errors instead
	wrapper *backend.Wrapper
	// ctx is a cache exit context
	ctx context.Context
	// cancel triggers exit context closure
	cancel context.CancelFunc

	// collections is a map of registered collections by resource Kind
	collections map[string]collection

	trustCache         services.Trust
	clusterConfigCache services.ClusterConfiguration
	provisionerCache   services.Provisioner
	usersCache         services.UsersService
	accessCache        services.Access
	dynamicAccessCache services.DynamicAccessExt
	presenceCache      services.Presence
	eventsFanout       *services.Fanout

	// closedFlag is set to indicate that the services are closed
	closedFlag int32
}

func (c *Cache) setInitError(err error) {
	c.initOnce.Do(func() {
		c.initErr = err
		close(c.initC)
	})
}

// setReadOK updates Cache.ok, which determines whether the
// cache is accessible for reads.
func (c *Cache) setReadOK(ok bool) {
	c.rw.RLock()
	current := c.ok
	c.rw.RUnlock()
	if current == ok {
		return
	}
	c.rw.Lock()
	c.ok = ok
	c.rw.Unlock()
}

// read acquires the cache rw lock and selects the appropriate
// target for read operations.  The returned guard *must* be
// released to prevent deadlocks.
func (c *Cache) read() (readGuard, error) {
	if c.isClosed() {
		return readGuard{}, trace.Errorf("cache is closed")
	}
	c.rw.RLock()
	if c.ok {
		return readGuard{
			trust:         c.trustCache,
			clusterConfig: c.clusterConfigCache,
			provisioner:   c.provisionerCache,
			users:         c.usersCache,
			access:        c.accessCache,
			dynamicAccess: c.dynamicAccessCache,
			presence:      c.presenceCache,
			release:       c.rw.RUnlock,
		}, nil
	}
	c.rw.RUnlock()
	return readGuard{
		trust:         c.Config.Trust,
		clusterConfig: c.Config.ClusterConfig,
		users:         c.Config.Users,
		access:        c.Config.Access,
		dynamicAccess: c.Config.DynamicAccess,
		presence:      c.Config.Presence,
		release:       nil,
	}, nil
}

type readGuard struct {
	trust         services.Trust
	clusterConfig services.ClusterConfiguration
	provisioner   services.Provisioner
	users         services.UsersService
	access        services.Access
	dynamicAccess services.DynamicAccess
	presence      services.Presence
	release       func()
}

func (r *readGuard) Release() {
	if r.release != nil {
		r.release()
	}
}

// Config defines cache configuration parameters
type Config struct {
	// target is an identifying string that allows errors to
	// indicate the target presets used (e.g. "auth).
	target string
	// Context is context for parent operations
	Context context.Context
	// Watches provides a list of resources
	// for the cache to watch
	Watches []services.WatchKind
	// Events provides events watchers
	Events services.Events
	// Trust is a service providing information about certificate
	// authorities
	Trust services.Trust
	// ClusterConfig is a cluster configuration service
	ClusterConfig services.ClusterConfiguration
	// Provisioner is a provisioning service
	Provisioner services.Provisioner
	// Users is a users service
	Users services.UsersService
	// Access is an access service
	Access services.Access
	// DynamicAccess is a dynamic access service
	DynamicAccess services.DynamicAccess
	// Presence is a presence service
	Presence services.Presence
	// Backend is a backend for local cache
	Backend backend.Backend
	// RetryPeriod is a period between cache retries on failures
	RetryPeriod time.Duration
	// EventsC is a channel for event notifications,
	// used in tests
	EventsC chan CacheEvent
	// OnlyRecent configures cache behavior that always uses
	// recent values, see OnlyRecent for details
	OnlyRecent OnlyRecent
	// PreferRecent configures cache behavior that prefer recent values
	// when available, but falls back to stale data, see PreferRecent
	// for details
	PreferRecent PreferRecent
	// Clock can be set to control time,
	// uses runtime clock by default
	Clock clockwork.Clock
	// Component is a component used in logs
	Component string
	// MetricComponent is a component used in metrics
	MetricComponent string
	// QueueSize is a desired queue Size
	QueueSize int
}

// OnlyRecent defines cache behavior always
// using recent data and failing otherwise.
// Used by auth servers and other systems
// having direct access to the backend.
type OnlyRecent struct {
	// Enabled enables cache behavior
	Enabled bool
}

// PreferRecent defined cache behavior
// that always prefers recent data, but will
// serve stale data in case if disconnect is detected
type PreferRecent struct {
	// Enabled enables cache behavior
	Enabled bool
	// MaxTTL sets maximum TTL the cache keeps the value
	// in case if there is no connection to auth servers
	MaxTTL time.Duration
	// NeverExpires if set, never expires stale cache values
	NeverExpires bool
}

// CheckAndSetDefaults checks parameters and sets default values
func (p *PreferRecent) CheckAndSetDefaults() error {
	if p.MaxTTL == 0 {
		p.MaxTTL = defaults.CacheTTL
	}
	return nil
}

// CheckAndSetDefaults checks parameters and sets default values
func (c *Config) CheckAndSetDefaults() error {
	if c.Events == nil {
		return trace.BadParameter("missing Events parameter")
	}
	if c.Backend == nil {
		return trace.BadParameter("missing Backend parameter")
	}
	if c.OnlyRecent.Enabled && c.PreferRecent.Enabled {
		return trace.BadParameter("either one of OnlyRecent or PreferRecent should be enabled at a time")
	}
	if !c.OnlyRecent.Enabled && !c.PreferRecent.Enabled {
		c.OnlyRecent.Enabled = true
	}
	if err := c.PreferRecent.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if c.Context == nil {
		c.Context = context.Background()
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.RetryPeriod == 0 {
		c.RetryPeriod = defaults.HighResPollingPeriod
	}
	if c.Component == "" {
		c.Component = teleport.ComponentCache
	}
	return nil
}

// CacheEvent is event used in tests
type CacheEvent struct {
	// Type is event type
	Type string
	// Event is event processed
	// by the event cycle
	Event services.Event
}

const (
	// EventProcessed is emitted whenever event is processed
	EventProcessed = "event_processed"
	// WatcherStarted is emitted when a new event watcher is started
	WatcherStarted = "watcher_started"
	// WatcherFailed is emitted when event watcher has failed
	WatcherFailed = "watcher_failed"
)

// New creates a new instance of Cache
func New(config Config) (*Cache, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	wrapper := backend.NewWrapper(config.Backend)
	ctx, cancel := context.WithCancel(config.Context)
	cs := &Cache{
		wrapper:            wrapper,
		ctx:                ctx,
		cancel:             cancel,
		Config:             config,
		initC:              make(chan struct{}),
		trustCache:         local.NewCAService(wrapper),
		clusterConfigCache: local.NewClusterConfigurationService(wrapper),
		provisionerCache:   local.NewProvisioningService(wrapper),
		usersCache:         local.NewIdentityService(wrapper),
		accessCache:        local.NewAccessService(wrapper),
		dynamicAccessCache: local.NewDynamicAccessService(wrapper),
		presenceCache:      local.NewPresenceService(wrapper),
		eventsFanout:       services.NewFanout(),
		Entry: log.WithFields(log.Fields{
			trace.Component: config.Component,
		}),
	}
	collections, err := setupCollections(cs, config.Watches)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cs.collections = collections

	go cs.update(ctx)

	select {
	case <-cs.initC:
		if cs.initErr != nil && cs.OnlyRecent.Enabled {
			cs.Close()
			return nil, trace.Wrap(cs.initErr)
		}
	case <-ctx.Done():
		cs.Close()
		return nil, trace.Wrap(ctx.Err(), "context closed during cache init")
	case <-time.After(time.Second * 30):
		if cs.OnlyRecent.Enabled {
			cs.Close()
			return nil, trace.Errorf("timeout waiting for cache init")
		}
	}
	return cs, nil
}

// NewWatcher returns a new event watcher. In case of a cache
// this watcher will return events as seen by the cache,
// not the backend. This feature allows auth server
// to handle subscribers connected to the in-memory caches
// instead of reading from the backend.
func (c *Cache) NewWatcher(ctx context.Context, watch services.Watch) (services.Watcher, error) {
Outer:
	for _, requested := range watch.Kinds {
		for _, configured := range c.Config.Watches {
			if requested.Kind == configured.Kind {
				continue Outer
			}
		}
		return nil, trace.BadParameter("cache %q does not support watching resource %q", c.Config.target, requested.Kind)
	}
	return c.eventsFanout.NewWatcher(ctx, watch)
}

func (c *Cache) isClosed() bool {
	return atomic.LoadInt32(&c.closedFlag) == 1
}

func (c *Cache) setClosed() {
	atomic.StoreInt32(&c.closedFlag, 1)
}

func (c *Cache) update(ctx context.Context) {
	defer c.Close()
	retry, err := utils.NewLinear(utils.LinearConfig{
		Step: c.RetryPeriod / 10,
		Max:  c.RetryPeriod,
	})
	if err != nil {
		c.Errorf("Bad retry parameters: %v", err)
		return
	}
	for {
		err := c.fetchAndWatch(ctx, retry)
		c.setInitError(err)
		if err != nil && !c.isClosed() {
			c.Warningf("Re-init the cache on error: %v.", trace.Unwrap(err))
			if c.OnlyRecent.Enabled {
				c.setReadOK(false)
			}
		}
		// events cache should be closed as well
		c.Debugf("Reloading %v.", retry)
		select {
		case <-retry.After():
			retry.Inc()
		case <-c.ctx.Done():
			c.Debugf("Closed, returning from update loop.")
			return
		}
	}
}

// setTTL overrides TTL supplied by the resource
// based on the cache behavior:
// - for "only recent", does nothing
// - for "prefer recent", honors TTL set on the resource, otherwise
//   sets TTL to max TTL
func (c *Cache) setTTL(r services.Resource) {
	if c.OnlyRecent.Enabled || (c.PreferRecent.Enabled && c.PreferRecent.NeverExpires) {
		return
	}
	// honor expiry set in the resource
	if !r.Expiry().IsZero() {
		return
	}
	// set max TTL on the resources
	r.SetTTL(c.Clock, c.PreferRecent.MaxTTL)
}

func (c *Cache) notify(event CacheEvent) {
	if c.EventsC == nil {
		return
	}
	select {
	case c.EventsC <- event:
		return
	case <-c.ctx.Done():
		return
	}
}

// fetchAndWatch keeps cache up to date by replaying
// events and syncing local cache storage.
//
// Here are some thoughts on consistency in face of errors:
//
// 1. Every client is connected to the database fan-out
// system. This system creates a buffered channel for every
// client and tracks the channel overflow. Thanks to channels every client gets its
// own unique iterator over the event stream. If client looses connection
// or fails to keep up with the stream, the server will terminate
// the channel and client will have to re-initialize.
//
// 2. Replays of stale events. Etcd provides a strong
// mechanism to track the versions of the storage - revisions
// of every operation that are uniquely numbered and monothonically
// and consistently ordered thanks to Raft. Unfortunately, DynamoDB
// does not provide such a mechanism for its event system, so
// some tradeofs have to be made:
//   a. We assume that events are ordered in regards to the
//   individual key operations which is the guarantees both Etcd and DynamodDB
//   provide.
//   b. Thanks to the init event sent by the server on a successful connect,
//   and guarantees 1 and 2a, client assumes that once it connects and receives an event,
//   it will not miss any events, however it can receive stale events.
//   Event could be stale, if it relates to a change that happened before
//   the version read by client from the database, for example,
//   given the event stream: 1. Update a=1 2. Delete a 3. Put a = 2
//   Client could have subscribed before event 1 happened,
//   read the value a=2 and then received events 1 and 2 and 3.
//   The cache will replay all events 1, 2 and 3 and end up in the correct
//   state 3. If we had a consistent revision number, we could
//   have skipped 1 and 2, but in the absence of such mechanism in Dynamo
//   we assume that this cache will eventually end up in a correct state
//   potentially lagging behind the state of the database.
//
func (c *Cache) fetchAndWatch(ctx context.Context, retry utils.Retry) error {
	watcher, err := c.Events.NewWatcher(c.ctx, services.Watch{
		QueueSize:       c.QueueSize,
		Name:            c.Component,
		Kinds:           c.watchKinds(),
		MetricComponent: c.MetricComponent,
	})
	if err != nil {
		c.notify(CacheEvent{Type: WatcherFailed})
		return trace.Wrap(err)
	}
	defer watcher.Close()
	// before fetch, make sure watcher is synced by receiving init event,
	// to avoid the scenario:
	// 1. Cache process:   w = NewWatcher()
	// 2. Cache process:   c.fetch()
	// 3. Backend process: addItem()
	// 4. Cache process:   <- w.Events()
	//
	// If there is a way that NewWatcher() on line 1 could
	// return without subscription established first,
	// Code line 3 could execute and line 4 could miss event,
	// wrapping up with out of sync replica.
	// To avoid this, before doing fetch,
	// cache process makes sure the connection is established
	// by receiving init event first.
	select {
	case <-watcher.Done():
		return trace.ConnectionProblem(watcher.Error(), "watcher is closed")
	case <-c.ctx.Done():
		return trace.ConnectionProblem(c.ctx.Err(), "context is closing")
	case event := <-watcher.Events():
		if event.Type != backend.OpInit {
			return trace.BadParameter("expected init event, got %v instead", event.Type)
		}
	}
	apply, err := c.fetch(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// apply will mutate cache, and possibly leave it in an invalid state
	// if an error occurs, so ensure that cache is not read.
	c.setReadOK(false)
	err = apply()
	if err != nil {
		return trace.Wrap(err)
	}

	// apply was successful; cache is now readable.
	c.setReadOK(true)
	c.setInitError(nil)

	// watchers have been queuing up since the last time
	// the cache was in a healthy state; broadcast OpInit.
	// It is very important that OpInit is not broadcast until
	// after we've placed the cache into a readable state.  This ensures
	// that any derivative caches do not peform their fetch operations
	// until this cache has finished its apply operations.
	c.eventsFanout.SetInit()
	defer c.eventsFanout.Reset()

	retry.Reset()
	c.notify(CacheEvent{Type: WatcherStarted})
	for {
		select {
		case <-watcher.Done():
			return trace.ConnectionProblem(watcher.Error(), "watcher is closed")
		case <-c.ctx.Done():
			return trace.ConnectionProblem(c.ctx.Err(), "context is closing")
		case event := <-watcher.Events():
			err = c.processEvent(ctx, event)
			if err != nil {
				return trace.Wrap(err)
			}
			c.notify(CacheEvent{Event: event, Type: EventProcessed})
		}
	}
}

// eraseAll erases all the data from cache collections
func (c *Cache) eraseAll() error {
	var errors []error
	for _, collection := range c.collections {
		errors = append(errors, collection.erase())
	}
	return trace.NewAggregate(errors...)
}

func (c *Cache) watchKinds() []services.WatchKind {
	out := make([]services.WatchKind, 0, len(c.collections))
	for _, collection := range c.collections {
		out = append(out, collection.watchKind())
	}
	return out
}

// Close closes all outstanding and active cache operations
func (c *Cache) Close() error {
	c.cancel()
	c.eventsFanout.Close()
	c.setClosed()
	return nil
}

func (c *Cache) fetch(ctx context.Context) (apply func() error, err error) {
	applyfns := make([]func() error, 0, len(c.collections))
	for _, collection := range c.collections {
		applyfn, err := collection.fetch(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		applyfns = append(applyfns, applyfn)
	}
	return func() error {
		for _, applyfn := range applyfns {
			if err := applyfn(); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *Cache) processEvent(ctx context.Context, event services.Event) error {
	collection, ok := c.collections[event.Resource.GetKind()]
	if !ok {
		c.Warningf("Skipping unsupported event %v.", event.Resource.GetKind())
		return nil
	}
	if err := collection.processEvent(ctx, event); err != nil {
		return trace.Wrap(err)
	}
	c.eventsFanout.Emit(event)
	return nil
}

// GetCertAuthority returns certificate authority by given id. Parameter loadSigningKeys
// controls if signing keys are loaded
func (c *Cache) GetCertAuthority(id services.CertAuthID, loadSigningKeys bool, opts ...services.MarshalOption) (services.CertAuthority, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	ca, err := rg.trust.GetCertAuthority(id, loadSigningKeys, services.AddOptions(opts, services.SkipValidation())...)
	return ca, err
}

// GetCertAuthorities returns a list of authorities of a given type
// loadSigningKeys controls whether signing keys should be loaded or not
func (c *Cache) GetCertAuthorities(caType services.CertAuthType, loadSigningKeys bool, opts ...services.MarshalOption) ([]services.CertAuthority, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.trust.GetCertAuthorities(caType, loadSigningKeys, services.AddOptions(opts, services.SkipValidation())...)
}

// GetStaticTokens gets the list of static tokens used to provision nodes.
func (c *Cache) GetStaticTokens() (services.StaticTokens, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.clusterConfig.GetStaticTokens()
}

// GetTokens returns all active (non-expired) provisioning tokens
func (c *Cache) GetTokens(opts ...services.MarshalOption) ([]services.ProvisionToken, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.provisioner.GetTokens(services.AddOptions(opts, services.SkipValidation())...)
}

// GetToken finds and returns token by ID
func (c *Cache) GetToken(token string) (services.ProvisionToken, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.provisioner.GetToken(token)
}

// GetClusterConfig gets services.ClusterConfig from the backend.
func (c *Cache) GetClusterConfig(opts ...services.MarshalOption) (services.ClusterConfig, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.clusterConfig.GetClusterConfig(services.AddOptions(opts, services.SkipValidation())...)
}

// GetClusterName gets the name of the cluster from the backend.
func (c *Cache) GetClusterName(opts ...services.MarshalOption) (services.ClusterName, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.clusterConfig.GetClusterName(services.AddOptions(opts, services.SkipValidation())...)
}

// GetRoles is a part of auth.AccessPoint implementation
func (c *Cache) GetRoles() ([]services.Role, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.access.GetRoles()
}

// GetRole is a part of auth.AccessPoint implementation
func (c *Cache) GetRole(name string) (services.Role, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.access.GetRole(name)
}

// GetNamespace returns namespace
func (c *Cache) GetNamespace(name string) (*services.Namespace, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetNamespace(name)
}

// GetNamespaces is a part of auth.AccessPoint implementation
func (c *Cache) GetNamespaces() ([]services.Namespace, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetNamespaces()
}

// GetNodes is a part of auth.AccessPoint implementation
func (c *Cache) GetNodes(namespace string, opts ...services.MarshalOption) ([]services.Server, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetNodes(namespace, opts...)
}

// GetAuthServers returns a list of registered servers
func (c *Cache) GetAuthServers() ([]services.Server, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetAuthServers()
}

// GetReverseTunnels is a part of auth.AccessPoint implementation
func (c *Cache) GetReverseTunnels(opts ...services.MarshalOption) ([]services.ReverseTunnel, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetReverseTunnels(services.AddOptions(opts, services.SkipValidation())...)
}

// GetProxies is a part of auth.AccessPoint implementation
func (c *Cache) GetProxies() ([]services.Server, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetProxies()
}

// GetUser is a part of auth.AccessPoint implementation.
func (c *Cache) GetUser(name string, withSecrets bool) (user services.User, err error) {
	if withSecrets { // cache never tracks user secrets
		return c.Users.GetUser(name, withSecrets)
	}
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.users.GetUser(name, withSecrets)
}

// GetUsers is a part of auth.AccessPoint implementation
func (c *Cache) GetUsers(withSecrets bool) (users []services.User, err error) {
	if withSecrets { // cache never tracks user secrets
		return c.Users.GetUsers(withSecrets)
	}
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.users.GetUsers(withSecrets)
}

// GetTunnelConnections is a part of auth.AccessPoint implementation
// GetTunnelConnections are not using recent cache as they are designed
// to be called periodically and always return fresh data
func (c *Cache) GetTunnelConnections(clusterName string, opts ...services.MarshalOption) ([]services.TunnelConnection, error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetTunnelConnections(clusterName, opts...)
}

// GetAllTunnelConnections is a part of auth.AccessPoint implementation
// GetAllTunnelConnections are not using recent cache, as they are designed
// to be called periodically and always return fresh data
func (c *Cache) GetAllTunnelConnections(opts ...services.MarshalOption) (conns []services.TunnelConnection, err error) {
	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetAllTunnelConnections(opts...)
}
