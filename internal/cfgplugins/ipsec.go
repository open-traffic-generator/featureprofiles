// Copyright 2025 Google LLC
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
	"net"
	"testing"

	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/helpers"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygot/ygot"
)

// parseCIDRAddr splits a CIDR string such as "192.0.2.5/30" into the host
// address ("192.0.2.5") and the prefix length (30). It returns ok=false when
// the input is empty or not valid CIDR.
func parseCIDRAddr(cidr string) (addr string, prefixLen uint8, ok bool) {
	if cidr == "" {
		return "", 0, false
	}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", 0, false
	}
	ones, _ := ipNet.Mask.Size()
	return ip.String(), uint8(ones), true
}

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

// ConfigureIPSecTunnel configures IPSec IKE/SA policies and a tunnel interface.
// When the IpsecOcUnsupported deviation is set (e.g. Arista), all attributes are
// pushed via a single gNMI CLI block. Otherwise the tunnel interface is configured
// via OpenConfig; note that OC bindings do not yet model IKE/SA/profile, so those
// must be configured out-of-band on vendors using the OC path.
func ConfigureIPSecTunnel(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg) {
	t.Helper()

	// Default to the per-tunnel policy/profile names so that each tunnel can use
	// an independent IKE policy, SA policy and IPSec profile. Sharing a single
	// profile across tunnels would cause a change (e.g. a key mismatch) on one
	// tunnel to affect every tunnel referencing the same profile.
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
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
	} else {
		// OpenConfig path. The generated OC bindings do not model the IPSec
		// security association (IKE policy, SA policy or IPSec profile), so only
		// the tunnel interface attributes that OpenConfig does model are
		// configured here: description, MTU, admin state, IPv4/IPv6 addresses and
		// VRF membership. Vendors requiring the IKE/SA/profile binding must model
		// it natively until an OpenConfig IPSec model is available.
		d := gnmi.OC()

		i := &oc.Interface{Name: ygot.String(cfg.TunnelName)}
		if cfg.Description != "" {
			i.Description = ygot.String(cfg.Description)
		}
		i.Mtu = ygot.Uint16(9216)
		if deviations.InterfaceEnabled(dut) {
			i.Enabled = ygot.Bool(true)
		}

		s0 := i.GetOrCreateSubinterface(0)
		if addr, plen, ok := parseCIDRAddr(cfg.TunnelIPv4); ok {
			s4 := s0.GetOrCreateIpv4()
			if deviations.InterfaceEnabled(dut) {
				s4.Enabled = ygot.Bool(true)
			}
			s4.GetOrCreateAddress(addr).PrefixLength = ygot.Uint8(plen)
		}
		if addr, plen, ok := parseCIDRAddr(cfg.TunnelIPv6); ok {
			s6 := s0.GetOrCreateIpv6()
			if deviations.InterfaceEnabled(dut) {
				s6.Enabled = ygot.Bool(true)
			}
			s6.GetOrCreateAddress(addr).PrefixLength = ygot.Uint8(plen)
		}

		// Assign the tunnel to its VRF before programming IP addresses. On many
		// devices, moving an interface into a VRF after IP assignment clears the
		// addresses; doing the VRF assignment first avoids that.
		if cfg.TunnelVRF != "" {
			niIntf := &oc.NetworkInstance_Interface{
				Id:           ygot.String(cfg.TunnelName),
				Interface:    ygot.String(cfg.TunnelName),
				Subinterface: ygot.Uint32(0),
			}
			gnmi.Update(t, dut, d.NetworkInstance(cfg.TunnelVRF).Interface(cfg.TunnelName).Config(), niIntf)
		}

		gnmi.Update(t, dut, d.Interface(cfg.TunnelName).Config(), i)
	}
}

// SetShortSALifetime configures a short SA lifetime on the IPSec SA policy.
func SetShortSALifetime(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg, seconds int) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			saPolicy := cfg.SAPolicy
			if saPolicy == "" {
				saPolicy = "SA_POLICY_1"
			}
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf(`ip security
			sa policy %s
				sa lifetime %d minutes
			!`, saPolicy, seconds))
		}
	} else {
		t.Log("Setting short SA lifetime via OpenConfig is not supported on this DUT, skipping")
	}
}

// SetShortIKELifetime configures a short IKE lifetime on the IPSec IKE policy.
func SetShortIKELifetime(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg, seconds int) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			ikePolicy := cfg.IKEPolicy
			if ikePolicy == "" {
				ikePolicy = "IKE_POLICY_1"
			}
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf(`ip security
			ike policy %s
				ike-lifetime %d minutes
			!`, ikePolicy, seconds))
		}
	} else {
		t.Log("Setting short IKE lifetime via OpenConfig is not supported on this DUT, skipping")
	}
}

// ConfigureDPD configures Dead Peer Detection on the IPSec profile.
func ConfigureDPD(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg, intervalSec, holdSec int) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			profile := cfg.Profile
			if profile == "" {
				profile = "IPSEC_PROFILE_1"
			}
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf(`ip security
			profile %s
				dpd %d %d
			!`, profile, intervalSec, holdSec))
		}
	} else {
		t.Log("Configuring DPD via OpenConfig is not supported on this DUT, skipping")
	}
}

// SetMismatchedKey modifies the shared key on the IPSec profile to trigger a mismatch.
func SetMismatchedKey(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			profile := cfg.Profile
			if profile == "" {
				profile = "IPSEC_PROFILE_1"
			}
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf(`ip security
			profile %s
				shared-key 7 047F0E021A71
			!`, profile))
		}
	} else {
		t.Log("Setting mismatched key via OpenConfig is not supported on this DUT, skipping")
	}
}

// SetMismatchedCipher modifies the cipher on the IPSec SA policy to trigger a mismatch.
func SetMismatchedCipher(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			saPolicy := cfg.SAPolicy
			if saPolicy == "" {
				saPolicy = "SA_POLICY_1"
			}
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf(`ip security
			sa policy %s
				esp encryption aes128gcm128
			!`, saPolicy))
		}
	} else {
		t.Log("Setting mismatched cipher via OpenConfig is not supported on this DUT, skipping")
	}
}

// RotateSharedKey updates the shared key on the IPSec profile.
func RotateSharedKey(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg, key string) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			profile := cfg.Profile
			if profile == "" {
				profile = "IPSEC_PROFILE_1"
			}
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf(`ip security
			profile %s
				shared-key 7 %s
			!`, profile, key))
		}
	} else {
		t.Log("Rotating shared key via OpenConfig is not supported on this DUT, skipping")
	}
}

// DisableFlowLabelHash disables flow label hashing on the tunnel interface.
func DisableFlowLabelHash(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf(`interface %s
			tunnel flow-label hash disable
			!`, cfg.TunnelName))
		}
	} else {
		t.Log("Disabling flow label hash via OpenConfig is not supported on this DUT, skipping")
	}
}

// DeleteTunnelInterface deletes a tunnel interface via CLI.
func DeleteTunnelInterface(t *testing.T, dut *ondatra.DUTDevice, tunnelName string) {
	t.Helper()
	if deviations.IpsecOcUnsupported(dut) {
		switch dut.Vendor() {
		case ondatra.ARISTA:
			helpers.GnmiCLIConfig(t, dut, fmt.Sprintf("no interface %s", tunnelName))
		}
	}
}


