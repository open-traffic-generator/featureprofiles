// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cfgplugins

import (
	"fmt"
	"testing"

	"github.com/openconfig/featureprofiles/internal/helpers"
	"github.com/openconfig/ondatra"
)

// IPSecTunnelCfg holds parameters for configuring an IPSec tunnel interface.
type IPSecTunnelCfg struct {
	TunnelName  string // e.g., "Tunnel1"
	Description string // tunnel interface description
	LocalFQDN   string // IKE local-id FQDN
	RemoteFQDN  string // IKE remote-id FQDN
	TunnelIPv4  string // CIDR, e.g., "192.0.2.5/30"
	TunnelIPv6  string // CIDR, e.g., "2001:db8:100:1::1/64"
	TunnelSrc   string // tunnel source address
	TunnelDst   string // tunnel destination address
	TunnelVRF   string // VRF the tunnel interface belongs to
	IKEPolicy   string // IKE policy name (defaults to IKE_POLICY_1)
	SAPolicy    string // SA policy name (defaults to SA_POLICY_1)
	Profile     string // IPSec profile name (defaults to IPSEC_PROFILE_1)
}

// ConfigureIPSecTunnel configures IPSec IKE/SA policies and a tunnel interface entirely
// via CLI. Arista does not accept OC configuration for tunnel interfaces (including IP
// address assignment), so all tunnel attributes are pushed through gNMI CLI.
func ConfigureIPSecTunnel(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg) {
	t.Helper()

	// Default to the per-tunnel policy/profile names so that each tunnel can use
	// an independent IKE policy, SA policy and IPSec profile. Sharing a single
	// profile across tunnels would cause a change (e.g. a key mismatch) on one
	// tunnel to affect every tunnel referencing the same profile.
	// TODO: Add deviation and OC command
	ikePolicy := cfg.IKEPolicy
	if ikePolicy == "" {
		ikePolicy = "IKE_POLICY_1"
	}
	saPolicy := cfg.SAPolicy
	if saPolicy == "" {
		saPolicy = "SA_POLICY_1"
	}
	profile := cfg.Profile
	if profile == "" {
		profile = "IPSEC_PROFILE_1"
	}

	// Build optional ip/ipv6 address lines for the tunnel interface.
	var addrLines string
	if cfg.TunnelIPv4 != "" {
		addrLines += fmt.Sprintf("   ip address %s\n", cfg.TunnelIPv4)
	}
	if cfg.TunnelIPv6 != "" {
		addrLines += fmt.Sprintf("   ipv6 address %s\n", cfg.TunnelIPv6)
	}

	tunnelCLI := fmt.Sprintf(`ip security
   ike policy %[1]s
      dh-group 24
      local-id fqdn %[2]s
      remote-id fqdn %[3]s
   !
   sa policy %[4]s
      esp encryption aes256gcm128
      pfs dh-group 14
   !
   profile %[5]s
      ike-policy %[1]s
      sa-policy %[4]s
      connection start
      shared-key 7 047F0E021A70
!
interface %[6]s
   description %[7]s
   mtu 9216
   vrf %[8]s
%[9]s   tunnel mode ipsec
   tunnel source %[10]s
   tunnel destination %[11]s
   tunnel path-mtu-discovery
   tunnel ipsec profile %[5]s
!`, ikePolicy, cfg.LocalFQDN, cfg.RemoteFQDN, saPolicy, profile, cfg.TunnelName, cfg.Description, cfg.TunnelVRF, addrLines, cfg.TunnelSrc, cfg.TunnelDst)
	helpers.GnmiCLIConfig(t, dut, tunnelCLI)
}
