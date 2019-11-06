// +build linux

/*
Copyright 2019 Gravitational, Inc.

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

package bpf

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
// #include <stdlib.h>
import "C"

import (
	"context"
	"sync"
	"unsafe"

	controlgroup "github.com/gravitational/teleport/lib/cgroup"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/coreos/go-semver/semver"
)

// Config holds configuration for the BPF service.
type Config struct {
	// Enabled is if this service will try and install BPF programs on this system.
	Enabled bool

	// PerfBufferPageCount is the size of the perf buffer.
	PerfBufferPageCount int

	// CgroupMountPath is where the cgroupv2 hierarchy is mounted.
	CgroupMountPath string
}

// CheckAndSetDefaults checks BPF configuration.
func (c *Config) CheckAndSetDefaults() error {
	if c.PerfBufferPageCount == 0 {
		c.PerfBufferPageCount = defaults.PerfBufferPageCount
	}
	if c.PerfBufferPageCount&(c.PerfBufferPageCount-1) != 0 {
		return trace.BadParameter("perf buffer page count must be multiple of 2")
	}
	if c.CgroupMountPath == "" {
		c.CgroupMountPath = defaults.CgroupMountPath
	}
	return nil
}

// Service manages BPF and control groups orchestration.
type Service struct {
	*Config

	// watch is a map of cgroup IDs that the BPF service is watching and
	// emitting events for.
	watch   map[uint64]*SessionContext
	watchMu sync.Mutex

	// closeContext is used to signal the BPF service is shutting down to all
	// goroutines.
	closeContext context.Context
	closeFunc    context.CancelFunc

	// cgroup is used to manage control groups.
	cgroup *controlgroup.Service

	// exec holds a BPF program that hooks execve.
	exec *exec

	// open holds a BPF program that hooks openat.
	open *open

	// conn is a BPF programs that hooks connect.
	conn *conn
}

// New creates a BPF service.
func New(config *Config) (*Service, error) {
	err := config.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Check if the host can run BPF programs.
	err := isHostCompatible()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create a cgroup controller to add/remote cgroups.
	cgroup, err := controlgroup.New(&controlgroup.Config{
		MountPath: c.CgroupMountPath,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	closeContext, closeFunc := context.WithCancel(context.Background())

	s := &Service{
		Config: config,

		watch: make(map[uint64]*SessionContext),

		closeContext: closeContext,
		closeFunc:    closeFunc,

		cgroup: cgroup,
	}

	// Load BPF programs.
	s.exec, err = newExec(closeContext)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.open, err = newOpen(closeContext)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.conn, err = newConn(closeContext)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Start pulling events off the perf buffers and emitting them to the audit log.
	go s.loop()

	return s, nil
}

// Close will stop any running BPF programs. Note this is only for a graceful
// shutdown, from the man page for BPF: "Generally, eBPF programs are loaded
// by the user process and automatically unloaded when the process exits."
func (s *Service) Close() error {
	// Unload the BPF programs.
	s.exec.close()
	s.open.close()
	s.conn.close()

	// Signal to the loop pulling events off the perf buffer to shutdown.
	s.closeFunc()

	return nil
}

func (s *Service) OpenSession(ctx *SessionContext) error {
	err := s.cgroup.Create(ctx.SessionID)
	if err != nil {
		return trace.Wrap(err)
	}

	cgroupID, err := controlgroup.ID(ctx.SessionID)
	if err != nil {
		return trace.Wrap(err)
	}

	// Start watching for any events that come from this cgroup.
	s.addWatch(cgroupID, ctx)

	// Place requested PID into cgroup.
	err = s.cgroup.Place(ctx.SessionID, ctx.PID)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (s *Service) CloseSession(ctx *SessionContext) error {
	cgroupID, err := controlgroup.ID(ctx.SessionID)
	if err != nil {
		return trace.Wrap(err)
	}

	// Stop watching for events from this PID.
	s.removeWatch(cgroupID)

	// Move all PIDs to the root cgroup and remove the cgroup created for this
	// session.
	err = s.cgroup.Remove(ctx.SessionID)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (s *Service) loop() {
	for {
		select {
		case event := <-s.exec.eventsCh():
			//	// TODO(russjones): Replace with ttlmap.
			//	args := make(map[uint64][]string)
			//
			//	for {
			//		select {
			//		case eventBytes := <-eventCh:
			//			var event rawExecEvent
			//
			//			err := binary.Read(bytes.NewBuffer(eventBytes), bcc.GetHostByteOrder(), &event)
			//			if err != nil {
			//				log.Debugf("Failed to read binary data: %v.", err)
			//				continue
			//			}
			//
			//			if eventArg == event.Type {
			//				buf, ok := args[event.PID]
			//				if !ok {
			//					buf = make([]string, 0)
			//				}
			//
			//				argv := (*C.char)(unsafe.Pointer(&event.Argv))
			//				buf = append(buf, C.GoString(argv))
			//				args[event.PID] = buf
			//			} else {
			//				// The args should have come in a previous event, find them by PID.
			//				argv, ok := args[event.PID]
			//				if !ok {
			//					log.Debugf("Got event with missing args: skipping.")
			//					continue
			//				}
			//
			//				// TODO(russjones): Who free's this C string?
			//				// Convert C string that holds the command name into a Go string.
			//				command := C.GoString((*C.char)(unsafe.Pointer(&event.Command)))
			//
			//				select {
			//				case e.events <- &execEvent{
			//					PID:        event.PPID,
			//					PPID:       event.PID,
			//					CgroupID:   event.CgroupID,
			//					Program:    command,
			//					Path:       argv[0],
			//					Argv:       argv[1:],
			//					ReturnCode: event.ReturnCode,
			//				}:
			//				case <-e.closeContext.Done():
			//					return
			//				default:
			//					log.Warnf("Dropping exec event %v/%v %v, events buffer full.", event.CgroupID, event.PID, argv)
			//				}
			//
			//				//// Remove, only for debugging.
			//				//fmt.Printf("--> Event=exec CgroupID=%v PID=%v PPID=%v Program=%v Path=%v Args=%v ReturnCode=%v.\n",
			//				//	event.CgroupID, event.PID, event.PPID, command, argv[0], argv[1:], event.ReturnCode)
			//			}

			ctx, ok := s.watch[event.CgroupID]
			if !ok {
				continue
			}

			// Emit "session.exec" event.
			eventFields := events.EventFields{
				// Common fields.
				events.EventNamespace:  ctx.Namespace,
				events.SessionEventID:  ctx.SessionID,
				events.SessionServerID: ctx.ServerID,
				events.EventLogin:      ctx.Login,
				events.EventUser:       ctx.User,
				// Exec fields.
				events.PID:        event.PPID,
				events.PPID:       event.PID,
				events.CgroupID:   event.CgroupID,
				events.Program:    event.Program,
				events.Path:       event.Path,
				events.Argv:       event.Argv,
				events.ReturnCode: event.ReturnCode,
			}
			ctx.AuditLog.EmitAuditEvent(events.SessionExec, eventFields)
		case event := <-s.open.eventsCh():
			//var event rawOpenEvent

			//err := binary.Read(bytes.NewBuffer(eventBytes), bcc.GetHostByteOrder(), &event)
			//if err != nil {
			//	log.Debugf("Failed to read binary data: %v.", err)
			//	return
			//}

			//// Convert C string that holds the command name into a Go string.
			//command := C.GoString((*C.char)(unsafe.Pointer(&event.Command)))

			//// Convert C string that holds the path into a Go string.
			//path := C.GoString((*C.char)(unsafe.Pointer(&event.Path)))

			//select {
			//case e.events <- &openEvent{
			//	PID:        event.PID,
			//	ReturnCode: event.ReturnCode,
			//	Program:    command,
			//	Path:       path,
			//	Flags:      event.Flags,
			//	CgroupID:   event.CgroupID,
			//}:
			//case <-e.closeContext.Done():
			//	return
			//default:
			//	log.Warnf("Dropping open event %v/%v %v %v, events buffer full.", event.CgroupID, event.PID, path, event.Flags)
			//}

			////// Remove, only for debugging.
			////fmt.Printf("Event=open CgroupID=%v PID=%v Command=%v ReturnCode=%v Flags=%#o Path=%v.\n",
			////	event.CgroupID, event.PID, command, event.ReturnCode, event.Flags, path)

			ctx, ok := s.watch[event.CgroupID]
			if !ok {
				continue
			}

			eventFields := events.EventFields{
				// Common fields.
				events.EventNamespace:  ctx.Namespace,
				events.SessionEventID:  ctx.SessionID,
				events.SessionServerID: ctx.ServerID,
				events.EventLogin:      ctx.Login,
				events.EventUser:       ctx.User,
				// Open fields.
				events.PID:        event.PID,
				events.CgroupID:   event.CgroupID,
				events.Program:    event.Program,
				events.Path:       event.Path,
				events.Flags:      event.Flags,
				events.ReturnCode: event.ReturnCode,
			}
			ctx.AuditLog.EmitAuditEvent(events.SessionOpen, eventFields)
		case event := <-s.conn.eventsCh():
			//var event rawConn4Event

			//err := binary.Read(bytes.NewBuffer(eventBytes), bcc.GetHostByteOrder(), &event)
			//if err != nil {
			//	log.Debugf("Failed to read binary data: %v.", err)
			//	continue
			//}

			//// Source.
			//src := make([]byte, 4)
			//binary.LittleEndian.PutUint32(src, uint32(event.SrcAddr))
			//srcAddr := net.IP(src)

			//// Destination.
			//dst := make([]byte, 4)
			//binary.LittleEndian.PutUint32(dst, uint32(event.DstAddr))
			//dstAddr := net.IP(dst)

			//// Convert C string that holds the command name into a Go string.
			//command := C.GoString((*C.char)(unsafe.Pointer(&event.Command)))

			//select {
			//case e.events <- &connEvent{
			//	PID:      event.PID,
			//	CgroupID: event.CgroupID,
			//	SrcAddr:  srcAddr,
			//	DstAddr:  dstAddr,
			//	Version:  4,
			//	DstPort:  event.DstPort,
			//	Program:  command,
			//}:
			//case <-e.closeContext.Done():
			//	return
			//default:
			//	log.Warnf("Dropping connect (IPv4) event %v/%v %v %v, buffer full.", event.CgroupID, event.PID, srcAddr, dstAddr)
			//}

			//// Remove, only for debugging.
			//fmt.Printf("--> Event=conn4 CgroupID=%v PID=%v Command=%v Src=%v Dst=%v:%v.\n",
			//	event.CgroupID, event.PID, command, srcAddr, dstAddr, event.DstPort)

			//// V6
			//var event rawConn6Event

			//err := binary.Read(bytes.NewBuffer(eventBytes), bcc.GetHostByteOrder(), &event)
			//if err != nil {
			//	log.Debugf("Failed to read binary data: %v.", err)
			//	continue
			//}

			//// Source.
			//src := make([]byte, 16)
			//binary.LittleEndian.PutUint32(src[0:], event.SrcAddr[0])
			//binary.LittleEndian.PutUint32(src[4:], event.SrcAddr[1])
			//binary.LittleEndian.PutUint32(src[8:], event.SrcAddr[2])
			//binary.LittleEndian.PutUint32(src[12:], event.SrcAddr[3])
			//srcAddr := net.IP(src)

			//// Destination.
			//dst := make([]byte, 16)
			//binary.LittleEndian.PutUint32(dst[0:], event.DstAddr[0])
			//binary.LittleEndian.PutUint32(dst[4:], event.DstAddr[1])
			//binary.LittleEndian.PutUint32(dst[8:], event.DstAddr[2])
			//binary.LittleEndian.PutUint32(dst[12:], event.DstAddr[3])
			//dstAddr := net.IP(dst)

			//// Convert C string that holds the command name into a Go string.
			//command := C.GoString((*C.char)(unsafe.Pointer(&event.Command)))

			//select {
			//case e.events <- &connEvent{
			//	PID:      event.PID,
			//	CgroupID: event.CgroupID,
			//	SrcAddr:  srcAddr,
			//	DstAddr:  dstAddr,
			//	Version:  6,
			//	DstPort:  event.DstPort,
			//	Program:  command,
			//}:
			//case <-e.closeContext.Done():
			//	return
			//default:
			//	log.Warnf("Dropping connect (IPv6) event %v/%v %v %v, buffer full.", event.CgroupID, event.PID, srcAddr, dstAddr)
			//}

			////// Remove, only for debugging.
			////fmt.Printf("--> Event=conn6 CgroupID=%v PID=%v Command=%v Src=%v Dst=%v:%v.\n",
			////	event.CgroupID, event.PID, command, srcAddr, dstAddr, event.DstPort)

			ctx, ok := s.watch[event.CgroupID]
			if !ok {
				continue
			}

			eventFields := events.EventFields{
				// Common fields.
				events.EventNamespace:  ctx.Namespace,
				events.SessionEventID:  ctx.SessionID,
				events.SessionServerID: ctx.ServerID,
				events.EventLogin:      ctx.Login,
				events.EventUser:       ctx.User,
				// Connect fields.
				events.PID:        event.PID,
				events.CgroupID:   event.CgroupID,
				events.Program:    event.Program,
				events.SrcAddr:    event.SrcAddr,
				events.DstAddr:    event.DstAddr,
				events.DstPort:    event.DstPort,
				events.TCPVersion: event.Version,
			}
			ctx.AuditLog.EmitAuditEvent(events.SessionConnect, eventFields)
		case <-s.closeContext.Done():
			return
		}
	}
}

func (s *Service) addWatch(cgroupID uint64, ctx *SessionContext) {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()

	s.watch[cgroupID] = ctx
}

func (s *Service) removeWatch(cgroupID uint64) {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()

	delete(s.watch, cgroupID)
}

// isHostCompatible checks that eBPF programs can run on this host.
func isHostCompatible() error {
	// To find the cgroup ID of a program, bpf_get_current_cgroup_id is needed
	// which was introduced in 4.18.
	// https://github.com/torvalds/linux/commit/bf6fa2c893c5237b48569a13fa3c673041430b6c
	minKernel := semver.New("4.18.0")
	version, err := utils.KernelVersion()
	if err != nil {
		return trace.Wrap(err)
	}
	if version.LessThan(*minKernel) {
		return trace.BadParameter("incompatible kernel found, minimum supported kernel is %v", minKernel)
	}

	// Check that libbcc is on the system.
	libraryName := C.CString("libbcc.so.0")
	defer C.free(unsafe.Pointer(libraryName))
	handle := C.dlopen(libraryName, C.RTLD_NOW)
	if handle == nil {
		return trace.BadParameter("libbcc.so not found")
	}

	return nil
}