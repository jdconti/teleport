/*
Copyright 2015 Gravitational, Inc.

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

package service

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/stretchr/testify/assert"

	"gopkg.in/check.v1"
)

func TestConfig(t *testing.T) { check.TestingT(t) }

type ConfigSuite struct {
}

var _ = check.Suite(&ConfigSuite{})

func (s *ConfigSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests()
}

func (s *ConfigSuite) TestDefaultConfig(c *check.C) {
	config := MakeDefaultConfig()
	c.Assert(config, check.NotNil)

	// all 3 services should be enabled by default
	c.Assert(config.Auth.Enabled, check.Equals, true)
	c.Assert(config.SSH.Enabled, check.Equals, true)
	c.Assert(config.Proxy.Enabled, check.Equals, true)

	localAuthAddr := utils.NetAddr{AddrNetwork: "tcp", Addr: "0.0.0.0:3025"}
	localProxyAddr := utils.NetAddr{AddrNetwork: "tcp", Addr: "0.0.0.0:3023"}

	// data dir, hostname and auth server
	c.Assert(config.DataDir, check.Equals, defaults.DataDir)
	if len(config.Hostname) < 2 {
		c.Error("default hostname wasn't properly set")
	}

	// crypto settings
	c.Assert(config.CipherSuites, check.DeepEquals, utils.DefaultCipherSuites())
	// Unfortunately the below algos don't have exported constants in
	// golang.org/x/crypto/ssh for us to use.
	c.Assert(config.Ciphers, check.DeepEquals, []string{
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
	})
	c.Assert(config.KEXAlgorithms, check.DeepEquals, []string{
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
	})
	c.Assert(config.MACAlgorithms, check.DeepEquals, []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-256",
	})
	c.Assert(config.CASignatureAlgorithm, check.IsNil)

	// auth section
	auth := config.Auth
	c.Assert(auth.SSHAddr, check.DeepEquals, localAuthAddr)
	c.Assert(auth.Limiter.MaxConnections, check.Equals, int64(defaults.LimiterMaxConnections))
	c.Assert(auth.Limiter.MaxNumberOfUsers, check.Equals, defaults.LimiterMaxConcurrentUsers)
	c.Assert(config.Auth.StorageConfig.Type, check.Equals, lite.GetName())
	c.Assert(auth.StorageConfig.Params[defaults.BackendPath], check.Equals, filepath.Join(config.DataDir, defaults.BackendDir))

	// SSH section
	ssh := config.SSH
	c.Assert(ssh.Limiter.MaxConnections, check.Equals, int64(defaults.LimiterMaxConnections))
	c.Assert(ssh.Limiter.MaxNumberOfUsers, check.Equals, defaults.LimiterMaxConcurrentUsers)

	// proxy section
	proxy := config.Proxy
	c.Assert(proxy.SSHAddr, check.DeepEquals, localProxyAddr)
	c.Assert(proxy.Limiter.MaxConnections, check.Equals, int64(defaults.LimiterMaxConnections))
	c.Assert(proxy.Limiter.MaxNumberOfUsers, check.Equals, defaults.LimiterMaxConcurrentUsers)
}

func TestKubeClusterNames(t *testing.T) {
	t.Parallel()

	kubeconfigFile, err := ioutil.TempFile("", "teleport")
	assert.NoError(t, err)
	kubeconfigPath := kubeconfigFile.Name()
	_, err = kubeconfigFile.Write([]byte(`
apiVersion: v1
kind: Config
preferences: {}
clusters:
- cluster:
    server: https://localhost:1
  name: kubeconfig-cluster-1
- cluster:
    server: https://localhost:2
  name: kubeconfig-cluster-2
contexts:
- context:
    cluster: kubeconfig-cluster-1
    user: user
  name: kubeconfig-cluster-1
- context:
    cluster: kubeconfig-cluster-2
    user: user
  name: kubeconfig-cluster-2
current-context: "kubeconfig-cluster-1"
users:
- name: user
  user:
`))
	assert.NoError(t, err)
	assert.NoError(t, kubeconfigFile.Close())

	tests := []struct {
		desc string
		cfg  KubeProxyConfig
		want []string
	}{
		{
			desc: "no ClusterName, Kubeconfig, not running in a pod",
			cfg: KubeProxyConfig{
				Enabled:      true,
				runningInPod: func() bool { return false },
			},
			want: nil,
		},
		{
			desc: "only ClusterName set",
			cfg: KubeProxyConfig{
				Enabled:      true,
				ClusterName:  "foo",
				runningInPod: func() bool { return false },
			},
			want: []string{"foo"},
		},
		{
			desc: "only Kubeconfig set",
			cfg: KubeProxyConfig{
				Enabled:        true,
				KubeconfigPath: kubeconfigPath,
				runningInPod:   func() bool { return false },
			},
			want: []string{"kubeconfig-cluster-1", "kubeconfig-cluster-2", "teleport-cluster-name"},
		},
		{
			desc: "no ClusterName and Kubeconfig, running in a pod",
			cfg: KubeProxyConfig{
				Enabled:      true,
				runningInPod: func() bool { return true },
			},
			want: []string{"teleport-cluster-name"},
		},
		{
			desc: "ClusterName, Kubeconfig set and running in a pod",
			cfg: KubeProxyConfig{
				Enabled:        true,
				ClusterName:    "foo",
				KubeconfigPath: kubeconfigPath,
				runningInPod:   func() bool { return true },
			},
			want: []string{"foo", "kubeconfig-cluster-1", "kubeconfig-cluster-2", "teleport-cluster-name"},
		},
		{
			desc: "Kubernetes support not enabled",
			cfg: KubeProxyConfig{
				Enabled:        false,
				ClusterName:    "foo",
				KubeconfigPath: kubeconfigPath,
				runningInPod:   func() bool { return true },
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := tt.cfg.ClusterNames("teleport-cluster-name")
			assert.NoError(t, err)
			assert.EqualValues(t, tt.want, got)
		})
	}
}
