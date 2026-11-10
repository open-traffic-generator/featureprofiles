// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package bgp_fib_isolation_and_drain_test implements RT-1.107: BGP FIB
// Isolation and Peer Soft Drain.
package bgp_fib_isolation_and_drain_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/helpers"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/gnmi/oc/netinstbgp"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	"github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
)

var debugCLI = flag.Bool("debug_cli", false, "Log DUT show command output, prefixed with [DEBUG-CLI], after setup and after each failed subtest (Arista only)")

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// Testbed (TESTBED_DUT_ATE_4LINKS):
//
//	ATE:port1 (CE1, VLAN 100) <-eBGP-> DUT:port1.100 [VRF ce1]
//	ATE:port2 (CE2, VLAN 200) <-eBGP-> DUT:port2.200 [VRF ce2]
//	ATE:port3 (RR1)           <-iBGP-> DUT:port3     [VRF ce1]
//	ATE:port4 (RR2)           <-iBGP-> DUT:port4     [VRF ce2]

const (
	bgpName = "BGP"

	dutAS = 64500
	ce1AS = 65001
	ce2AS = 65002

	ce1VLAN = 100
	ce2VLAN = 200

	vrfCE1 = "ce1"
	vrfCE2 = "ce2"
	rdCE1  = "64500:100"
	rdCE2  = "64500:200"

	ce1V4Prefix = "198.51.100.0"
	ce1V6Prefix = "2001:db8:100::"
	ce2V4Prefix = "203.0.113.0"
	ce2V6Prefix = "2001:db8:200::"
	rr1V6Prefix = "2001:db8:300::"
	rr2V6Prefix = "2001:db8:400::"
	v4PrefixLen = 24
	v6PrefixLen = 64

	ipv4 = "IPv4"
	ipv6 = "IPv6"

	policyAllow      = "ALLOW-ALL"
	policyNoRoutes   = "NO-ROUTES"
	policyDrainCore  = "SOFT-DRAIN-CORE"
	policyDrainCE    = "SOFT-DRAIN-CE"
	installMapName   = "INSTALL-CORE-ONLY"
	suppressPfxV4    = "FIB-SUPPRESS-V4"
	suppressPfxV6    = "FIB-SUPPRESS-V6"
	drainLocalPref   = 10
	defaultLocalPref = 100
	drainPrependN    = 3

	flowPPS       = 100
	flowFrameSize = 512

	bgpTimeout         = 2 * time.Minute
	telemetryTimeout   = 30 * time.Second
	convergenceTimeout = 5 * time.Second
)

var (
	dutCE1 = attrs.Attributes{
		Desc:         "DUT to ATE CE1",
		IPv4:         "192.0.2.1",
		IPv4Len:      30,
		IPv6:         "2001:db8::1",
		IPv6Len:      126,
		Subinterface: ce1VLAN,
	}
	ateCE1 = attrs.Attributes{
		Name:    "ateCE1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: 30,
		IPv6:    "2001:db8::2",
		IPv6Len: 126,
	}
	dutCE2 = attrs.Attributes{
		Desc:         "DUT to ATE CE2",
		IPv4:         "192.0.2.5",
		IPv4Len:      30,
		IPv6:         "2001:db8::5",
		IPv6Len:      126,
		Subinterface: ce2VLAN,
	}
	ateCE2 = attrs.Attributes{
		Name:    "ateCE2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.6",
		IPv4Len: 30,
		IPv6:    "2001:db8::6",
		IPv6Len: 126,
	}
	dutRR1 = attrs.Attributes{
		Desc:    "DUT to ATE RR1",
		IPv6:    "2001:db8:3::1",
		IPv6Len: 64,
	}
	ateRR1 = attrs.Attributes{
		Name:    "ateRR1",
		MAC:     "02:00:03:01:01:01",
		IPv6:    "2001:db8:3::2",
		IPv6Len: 64,
	}
	dutRR2 = attrs.Attributes{
		Desc:    "DUT to ATE RR2",
		IPv6:    "2001:db8:4::1",
		IPv6Len: 64,
	}
	ateRR2 = attrs.Attributes{
		Name:    "ateRR2",
		MAC:     "02:00:04:01:01:01",
		IPv6:    "2001:db8:4::2",
		IPv6Len: 64,
	}
)

// tenant describes one customer VRF: the eBGP customer edge session and the
// iBGP core route reflector session.
type tenant struct {
	vrf       string
	rd        string
	routerID  string
	ceAS      uint32
	ceVLAN    uint16
	dutCE     *attrs.Attributes
	ateCE     *attrs.Attributes
	dutRR     *attrs.Attributes
	ateRR     *attrs.Attributes
	cePort    string
	rrPort    string
	ceV4      string
	ceV6      string
	corePfxV6 string
}

func (tn *tenant) bgpPath() *netinstbgp.NetworkInstance_Protocol_BgpPath {
	return gnmi.OC().NetworkInstance(tn.vrf).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, bgpName).Bgp()
}

func newTenants(t *testing.T, dut *ondatra.DUTDevice) (*tenant, *tenant) {
	t.Helper()
	ce1 := &tenant{
		vrf: vrfCE1, rd: rdCE1, routerID: dutCE1.IPv4, ceAS: ce1AS, ceVLAN: ce1VLAN,
		dutCE: &dutCE1, ateCE: &ateCE1, dutRR: &dutRR1, ateRR: &ateRR1,
		cePort: dut.Port(t, "port1").Name(), rrPort: dut.Port(t, "port3").Name(),
		ceV4: ce1V4Prefix, ceV6: ce1V6Prefix, corePfxV6: rr1V6Prefix,
	}
	ce2 := &tenant{
		vrf: vrfCE2, rd: rdCE2, routerID: dutCE2.IPv4, ceAS: ce2AS, ceVLAN: ce2VLAN,
		dutCE: &dutCE2, ateCE: &ateCE2, dutRR: &dutRR2, ateRR: &ateRR2,
		cePort: dut.Port(t, "port2").Name(), rrPort: dut.Port(t, "port4").Name(),
		ceV4: ce2V4Prefix, ceV6: ce2V6Prefix, corePfxV6: rr2V6Prefix,
	}
	return ce1, ce2
}

func cidr(prefix string, plen int) string {
	return fmt.Sprintf("%s/%d", prefix, plen)
}

// buildRoutingPolicies returns the routing policies used by the test.
func buildRoutingPolicies() map[string]*oc.RoutingPolicy_PolicyDefinition {
	root := &oc.Root{}
	rp := root.GetOrCreateRoutingPolicy()

	add := func(name string, result oc.E_RoutingPolicy_PolicyResultType, fn func(*oc.RoutingPolicy_PolicyDefinition_Statement_Actions)) {
		pd := rp.GetOrCreatePolicyDefinition(name)
		st, err := pd.AppendNewStatement("stmt-1")
		if err != nil {
			panic(fmt.Sprintf("AppendNewStatement(%s): %v", name, err))
		}
		actions := st.GetOrCreateActions()
		actions.PolicyResult = result
		if fn != nil {
			fn(actions)
		}
	}

	add(policyAllow, oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE, nil)
	add(policyNoRoutes, oc.RoutingPolicy_PolicyResultType_REJECT_ROUTE, nil)
	add(policyDrainCore, oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE, func(a *oc.RoutingPolicy_PolicyDefinition_Statement_Actions) {
		a.GetOrCreateBgpActions().SetLocalPref = ygot.Uint32(drainLocalPref)
	})
	add(policyDrainCE, oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE, func(a *oc.RoutingPolicy_PolicyDefinition_Statement_Actions) {
		p := a.GetOrCreateBgpActions().GetOrCreateSetAsPathPrepend()
		p.Asn = ygot.Uint32(dutAS)
		p.RepeatN = ygot.Uint8(drainPrependN)
	})
	return rp.PolicyDefinition
}

// applyPolicies sets the import/export policies on a BGP neighbor.
func applyPolicies(dut *ondatra.DUTDevice, nbr *oc.NetworkInstance_Protocol_Bgp_Neighbor, importPolicy, exportPolicy string) {
	if deviations.RoutePolicyUnderAFIUnsupported(dut) {
		ap := nbr.GetOrCreateApplyPolicy()
		ap.ImportPolicy = []string{importPolicy}
		ap.ExportPolicy = []string{exportPolicy}
		return
	}
	for _, afi := range []oc.E_BgpTypes_AFI_SAFI_TYPE{oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST, oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST} {
		af := nbr.GetOrCreateAfiSafi(afi)
		af.Enabled = ygot.Bool(true)
		ap := af.GetOrCreateApplyPolicy()
		ap.ImportPolicy = []string{importPolicy}
		ap.ExportPolicy = []string{exportPolicy}
	}
}

// buildNetworkInstance returns the tenant L3VRF with eBGP (CE) and iBGP (RR)
// neighbors, advertise-inactive-routes and RIB-to-FIB install suppression.
func buildNetworkInstance(dut *ondatra.DUTDevice, tn *tenant) *oc.NetworkInstance {
	root := &oc.Root{}
	ni := root.GetOrCreateNetworkInstance(tn.vrf)
	ni.Type = oc.NetworkInstanceTypes_NETWORK_INSTANCE_TYPE_L3VRF
	ni.Description = ygot.String("Tenant " + tn.vrf)
	ni.RouteDistinguisher = ygot.String(tn.rd)
	// TODO: Configure the per-VRF Route Targets once an OC path is available.

	for _, ref := range []struct {
		name string
		sub  uint32
	}{{tn.cePort, uint32(tn.ceVLAN)}, {tn.rrPort, 0}} {
		id := ref.name
		if ref.sub != 0 || deviations.InterfaceRefInterfaceIDFormat(dut) {
			id = fmt.Sprintf("%s.%d", ref.name, ref.sub)
		}
		niIntf := ni.GetOrCreateInterface(id)
		niIntf.Interface = ygot.String(ref.name)
		niIntf.Subinterface = ygot.Uint32(ref.sub)
	}

	proto := ni.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, bgpName)
	proto.Enabled = ygot.Bool(true)
	bgp := proto.GetOrCreateBgp()
	global := bgp.GetOrCreateGlobal()
	global.As = ygot.Uint32(dutAS)
	global.RouterId = ygot.String(tn.routerID)
	global.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Enabled = ygot.Bool(true)
	global.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).Enabled = ygot.Bool(true)
	global.GetOrCreateRouteSelectionOptions().AdvertiseInactiveRoutes = ygot.Bool(true)

	ce := bgp.GetOrCreateNeighbor(tn.ateCE.IPv4)
	ce.PeerAs = ygot.Uint32(tn.ceAS)
	ce.Enabled = ygot.Bool(true)
	ce.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Enabled = ygot.Bool(true)
	ce.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).Enabled = ygot.Bool(true)
	applyPolicies(dut, ce, policyAllow, policyAllow)

	rr := bgp.GetOrCreateNeighbor(tn.ateRR.IPv6)
	rr.PeerAs = ygot.Uint32(dutAS)
	rr.Enabled = ygot.Bool(true)
	rr.GetOrCreateTransport().LocalAddress = ygot.String(tn.dutRR.IPv6)
	rr.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Enabled = ygot.Bool(true)
	rr.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).Enabled = ygot.Bool(true)
	applyPolicies(dut, rr, policyAllow, policyAllow)

	// The OC model has no dedicated RIB-to-FIB install-suppression leaf. Customer
	// eBGP routes are kept out of the forwarding table with a table-connection
	// whose import policy rejects everything. Platforms that do not support it
	// use the CLI install-map instead (see configureInstallMap).
	if deviations.BgpInstallMapCLIRequired(dut) {
		return ni
	}
	for _, afi := range []oc.E_Types_ADDRESS_FAMILY{oc.Types_ADDRESS_FAMILY_IPV4, oc.Types_ADDRESS_FAMILY_IPV6} {
		tc := ni.GetOrCreateTableConnection(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, afi)
		tc.ImportPolicy = []string{policyNoRoutes}
		if !deviations.DefaultRoutePolicyUnsupported(dut) {
			tc.DefaultImportPolicy = oc.RoutingPolicy_DefaultPolicyType_REJECT_ROUTE
		}
	}
	return ni
}

func buildInterface(dut *ondatra.DUTDevice, name string, a *attrs.Attributes, vlan uint16) *oc.Interface {
	i := a.NewOCInterface(name, dut)
	if deviations.RequireRoutedSubinterface0(dut) {
		s0 := i.GetOrCreateSubinterface(0)
		s0.GetOrCreateIpv4().Enabled = ygot.Bool(true)
		s0.GetOrCreateIpv6().Enabled = ygot.Bool(true)
	}
	if vlan != 0 {
		s := i.GetOrCreateSubinterface(a.Subinterface)
		if deviations.DeprecatedVlanID(dut) {
			s.GetOrCreateVlan().VlanId = oc.UnionUint16(vlan)
		} else {
			s.GetOrCreateVlan().GetOrCreateMatch().GetOrCreateSingleTagged().VlanId = ygot.Uint16(vlan)
		}
	}
	return i
}

// buildDefaultVRFBGP returns the default VRF BGP instance, which some platforms
// require before BGP can be configured in a non-default VRF.
func buildDefaultVRFBGP() *oc.NetworkInstance_Protocol {
	root := &oc.Root{}
	proto := root.GetOrCreateNetworkInstance("").GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, bgpName)
	proto.Enabled = ygot.Bool(true)
	proto.GetOrCreateBgp().GetOrCreateGlobal().As = ygot.Uint32(dutAS)
	return proto
}

// configureInstallMap suppresses RIB-to-FIB installation of the customer eBGP
// prefixes in the tenant VRFs using a CLI install-map on platforms without BGP
// to BGP table-connection support. Only the customer prefixes are denied, so
// the core iBGP routes are still installed.
// TODO: Verify the CLI syntax on the target platform.
func configureInstallMap(t *testing.T, dut *ondatra.DUTDevice, tenants ...*tenant) {
	t.Helper()
	var cfg strings.Builder
	var v6Entries strings.Builder
	for i, tn := range tenants {
		seq := (i + 1) * 10
		fmt.Fprintf(&cfg, "ip prefix-list %s seq %d permit %s\n", suppressPfxV4, seq, cidr(tn.ceV4, v4PrefixLen))
		fmt.Fprintf(&v6Entries, "seq %d permit %s\n", seq, cidr(tn.ceV6, v6PrefixLen))
	}
	// An IPv6 prefix-list takes its entries in a sub-mode, not inline.
	fmt.Fprintf(&cfg, "ipv6 prefix-list %s\n%sexit\n", suppressPfxV6, v6Entries.String())
	fmt.Fprintf(&cfg, "route-map %s deny 10\nmatch ip address prefix-list %s\nexit\n", installMapName, suppressPfxV4)
	fmt.Fprintf(&cfg, "route-map %s deny 20\nmatch ipv6 address prefix-list %s\nexit\n", installMapName, suppressPfxV6)
	fmt.Fprintf(&cfg, "route-map %s permit 30\nexit\n", installMapName)
	fmt.Fprintf(&cfg, "router bgp %d\n", dutAS)
	for _, tn := range tenants {
		fmt.Fprintf(&cfg, "vrf %s\nbgp route install-map %s\nexit\n", tn.vrf, installMapName)
	}
	helpers.GnmiCLIConfig(t, dut, cfg.String())
}

// removeInstallMap deletes the route-map and prefix-lists of configureInstallMap.
func removeInstallMap(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	helpers.GnmiCLIConfig(t, dut, fmt.Sprintf("no route-map %s\nno ip prefix-list %s\nno ipv6 prefix-list %s\n", installMapName, suppressPfxV4, suppressPfxV6))
}

// configureDUT pushes the full DUT configuration and registers its removal.
func configureDUT(t *testing.T, dut *ondatra.DUTDevice, tenants ...*tenant) {
	t.Helper()
	defaultBGP := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, bgpName)
	// The default VRF BGP must be applied before the tenant VRFs are validated.
	gnmi.Replace(t, dut, defaultBGP.Config(), buildDefaultVRFBGP())
	// Registered first so it runs after the tenant cleanup below.
	t.Cleanup(func() { gnmi.Delete(t, dut, defaultBGP.Config()) })
	if deviations.BgpInstallMapCLIRequired(dut) {
		t.Cleanup(func() { removeInstallMap(t, dut) })
	}
	sb := &gnmi.SetBatch{}
	for _, tn := range tenants {
		gnmi.BatchReplace(sb, gnmi.OC().Interface(tn.cePort).Config(), buildInterface(dut, tn.cePort, tn.dutCE, tn.ceVLAN))
		gnmi.BatchReplace(sb, gnmi.OC().Interface(tn.rrPort).Config(), buildInterface(dut, tn.rrPort, tn.dutRR, 0))
	}
	policies := buildRoutingPolicies()
	for name, pd := range policies {
		gnmi.BatchReplace(sb, gnmi.OC().RoutingPolicy().PolicyDefinition(name).Config(), pd)
	}
	for _, tn := range tenants {
		gnmi.BatchReplace(sb, gnmi.OC().NetworkInstance(tn.vrf).Config(), buildNetworkInstance(dut, tn))
	}
	// Cleanups run last-in-first-out: VRFs, then policies, then interfaces,
	// then the install-map and default BGP registered above. Each is a separate
	// Set so that one failure does not leave the rest of the config behind.
	t.Cleanup(func() {
		ib := &gnmi.SetBatch{}
		for _, tn := range tenants {
			gnmi.BatchDelete(ib, gnmi.OC().Interface(tn.cePort).Subinterface(uint32(tn.ceVLAN)).Config())
			gnmi.BatchDelete(ib, gnmi.OC().Interface(tn.cePort).Subinterface(0).Config())
			gnmi.BatchDelete(ib, gnmi.OC().Interface(tn.rrPort).Subinterface(0).Config())
		}
		ib.Set(t, dut)
	})
	t.Cleanup(func() {
		pb := &gnmi.SetBatch{}
		for name := range policies {
			gnmi.BatchDelete(pb, gnmi.OC().RoutingPolicy().PolicyDefinition(name).Config())
		}
		pb.Set(t, dut)
	})
	t.Cleanup(func() {
		vb := &gnmi.SetBatch{}
		for _, tn := range tenants {
			gnmi.BatchDelete(vb, gnmi.OC().NetworkInstance(tn.vrf).Config())
		}
		vb.Set(t, dut)
	})

	sb.Set(t, dut)
	if deviations.BgpInstallMapCLIRequired(dut) {
		configureInstallMap(t, dut, tenants...)
	}
}

// addATEDevice adds an OTG device (optionally VLAN tagged) on the given port.
func addATEDevice(top gosnappi.Config, ap *ondatra.Port, a, gw *attrs.Attributes, vlan uint32) gosnappi.Device {
	dev := top.Devices().Add().SetName(a.Name)
	eth := dev.Ethernets().Add().SetName(a.Name + ".Eth").SetMac(a.MAC)
	eth.Connection().SetPortName(ap.ID())
	if vlan != 0 {
		eth.Vlans().Add().SetName(a.Name + ".VLAN").SetId(vlan)
	}
	if a.IPv4 != "" {
		eth.Ipv4Addresses().Add().SetName(a.Name + ".IPv4").
			SetAddress(a.IPv4).SetGateway(gw.IPv4).SetPrefix(uint32(a.IPv4Len))
	}
	if a.IPv6 != "" {
		eth.Ipv6Addresses().Add().SetName(a.Name + ".IPv6").
			SetAddress(a.IPv6).SetGateway(gw.IPv6).SetPrefix(uint32(a.IPv6Len))
	}
	return dev
}

func bgpV4PeerName(a *attrs.Attributes) string { return a.Name + ".BGP4.peer" }
func bgpV6PeerName(a *attrs.Attributes) string { return a.Name + ".BGP6.peer" }

// addCE adds a customer edge: an eBGP IPv4 session that advertises one IPv4
// and one IPv6 customer prefix.
func addCE(top gosnappi.Config, ap *ondatra.Port, tn *tenant) {
	dev := addATEDevice(top, ap, tn.ateCE, tn.dutCE, uint32(tn.ceVLAN))
	bgp := dev.Bgp().SetRouterId(tn.ateCE.IPv4)
	peer := bgp.Ipv4Interfaces().Add().SetIpv4Name(tn.ateCE.Name + ".IPv4").Peers().Add().SetName(bgpV4PeerName(tn.ateCE))
	peer.SetPeerAddress(tn.dutCE.IPv4).SetAsNumber(tn.ceAS).SetAsType(gosnappi.BgpV4PeerAsType.EBGP)
	peer.Capability().SetIpv4Unicast(true).SetIpv6Unicast(true)
	// Without the filter OTG does not report the prefixes it receives from the DUT.
	peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)

	v4 := peer.V4Routes().Add().SetName(tn.ateCE.Name + ".v4routes")
	v4.SetNextHopIpv4Address(tn.ateCE.IPv4).SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4)
	v4.Addresses().Add().SetAddress(tn.ceV4).SetPrefix(v4PrefixLen).SetCount(1)

	v6 := peer.V6Routes().Add().SetName(tn.ateCE.Name + ".v6routes")
	// The IPv6 routes are sent over an IPv4 session. In local_ip mode the next hop
	// is encoded as an IPv4-mapped address that the DUT cannot resolve.
	v6.SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL).
		SetNextHopIpv6Address(tn.ateCE.IPv6).SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6)
	v6.Addresses().Add().SetAddress(tn.ceV6).SetPrefix(v6PrefixLen).SetCount(1)
}

// addRR adds a core route reflector: an iBGP IPv6 session that advertises one
// IPv6 core prefix and accepts IPv4/IPv6 unicast.
func addRR(top gosnappi.Config, ap *ondatra.Port, tn *tenant, routerID string) {
	dev := addATEDevice(top, ap, tn.ateRR, tn.dutRR, 0)
	bgp := dev.Bgp().SetRouterId(routerID)
	peer := bgp.Ipv6Interfaces().Add().SetIpv6Name(tn.ateRR.Name + ".IPv6").Peers().Add().SetName(bgpV6PeerName(tn.ateRR))
	peer.SetPeerAddress(tn.dutRR.IPv6).SetAsNumber(dutAS).SetAsType(gosnappi.BgpV6PeerAsType.IBGP)
	peer.Capability().SetIpv4Unicast(true).SetIpv6Unicast(true)
	peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)

	v6 := peer.V6Routes().Add().SetName(tn.ateRR.Name + ".v6routes")
	v6.SetNextHopIpv6Address(tn.ateRR.IPv6).SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6)
	v6.Addresses().Add().SetAddress(tn.corePfxV6).SetPrefix(v6PrefixLen).SetCount(1)
}

type flowSpec struct {
	name   string
	txName string
	rxName string
	isV6   bool
	src    string
	dst    string
}

func addFlow(top gosnappi.Config, f flowSpec) {
	flow := top.Flows().Add().SetName(f.name)
	flow.Metrics().SetEnable(true)
	flow.TxRx().Device().SetTxNames([]string{f.txName}).SetRxNames([]string{f.rxName})
	flow.Rate().SetPps(flowPPS)
	flow.Size().SetFixed(flowFrameSize)
	flow.Packet().Add().Ethernet()
	if f.isV6 {
		ip := flow.Packet().Add().Ipv6()
		ip.Src().SetValue(f.src)
		ip.Dst().SetValue(f.dst)
		return
	}
	ip := flow.Packet().Add().Ipv4()
	ip.Src().SetValue(f.src)
	ip.Dst().SetValue(f.dst)
}

const (
	flowCE1toCE2v4 = "ce1_to_ce2_v4"
	flowCE1toCE2v6 = "ce1_to_ce2_v6"
	flowCE2toCE1v4 = "ce2_to_ce1_v4"
	flowCE2toCE1v6 = "ce2_to_ce1_v6"
	flowCE1toRR1   = "ce1_to_rr1_v6"
	flowCE2toRR2   = "ce2_to_rr2_v6"
)

// configureATE builds the OTG configuration, pushes it and starts the protocols.
func configureATE(t *testing.T, ate *ondatra.ATEDevice, ce1, ce2 *tenant) gosnappi.Config {
	t.Helper()
	top := gosnappi.NewConfig()
	for _, id := range []string{"port1", "port2", "port3", "port4"} {
		top.Ports().Add().SetName(ate.Port(t, id).ID())
	}
	addCE(top, ate.Port(t, "port1"), ce1)
	addCE(top, ate.Port(t, "port2"), ce2)
	addRR(top, ate.Port(t, "port3"), ce1, "192.0.2.17")
	addRR(top, ate.Port(t, "port4"), ce2, "192.0.2.21")

	ceName := func(tn *tenant, family string) string { return tn.ateCE.Name + "." + family }
	for _, f := range []flowSpec{
		{flowCE1toCE2v4, ceName(ce1, ipv4), ceName(ce2, ipv4), false, "198.51.100.1", "203.0.113.1"},
		{flowCE1toCE2v6, ceName(ce1, ipv6), ceName(ce2, ipv6), true, "2001:db8:100::1", "2001:db8:200::1"},
		{flowCE2toCE1v4, ceName(ce2, ipv4), ceName(ce1, ipv4), false, "203.0.113.1", "198.51.100.1"},
		{flowCE2toCE1v6, ceName(ce2, ipv6), ceName(ce1, ipv6), true, "2001:db8:200::1", "2001:db8:100::1"},
		{flowCE1toRR1, ceName(ce1, ipv6), ce1.ateRR.Name + ".IPv6", true, "2001:db8:100::1", "2001:db8:300::1"},
		{flowCE2toRR2, ceName(ce2, ipv6), ce2.ateRR.Name + ".IPv6", true, "2001:db8:200::1", "2001:db8:400::1"},
	} {
		addFlow(top, f)
	}

	ate.OTG().PushConfig(t, top)
	ate.OTG().StartProtocols(t)
	t.Cleanup(func() {
		ate.OTG().StopTraffic(t)
		ate.OTG().StopProtocols(t)
		ate.OTG().PushConfig(t, gosnappi.NewConfig())
	})
	return top
}

// setupEnvironment configures the DUT and ATE and waits for all BGP sessions.
func setupEnvironment(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) (gosnappi.Config, *tenant, *tenant) {
	t.Helper()
	ce1, ce2 := newTenants(t, dut)
	for _, id := range []string{"port1", "port2", "port3", "port4"} {
		if p := dut.Port(t, id); deviations.ExplicitPortSpeed(dut) {
			fptest.SetPortSpeed(t, p)
		}
	}
	configureDUT(t, dut, ce1, ce2)
	top := configureATE(t, ate, ce1, ce2)

	for _, tn := range []*tenant{ce1, ce2} {
		for _, addr := range []string{tn.ateCE.IPv4, tn.ateRR.IPv6} {
			if err := verifyBGPEstablished(t, dut, tn, addr); err != nil {
				t.Fatalf("Setup: %v", err)
			}
		}
	}
	otgutils.WaitForARP(t, ate.OTG(), top, ipv4)
	otgutils.WaitForARP(t, ate.OTG(), top, ipv6)
	return top, ce1, ce2
}

// verifyBGPEstablished waits for the DUT BGP session in the tenant VRF.
func verifyBGPEstablished(t *testing.T, dut *ondatra.DUTDevice, tn *tenant, nbr string) error {
	t.Helper()
	_, ok := gnmi.Watch(t, dut, tn.bgpPath().Neighbor(nbr).SessionState().State(), bgpTimeout, func(v *ygnmi.Value[oc.E_Bgp_Neighbor_SessionState]) bool {
		s, present := v.Val()
		return present && s == oc.Bgp_Neighbor_SessionState_ESTABLISHED
	}).Await(t)
	if !ok {
		return fmt.Errorf("VRF %s: BGP session to %s did not reach ESTABLISHED within %v", tn.vrf, nbr, bgpTimeout)
	}
	return nil
}

// awaitPrefix waits until the prefix is reported by the wildcard prefix query.
func awaitPrefix(t *testing.T, dut *ondatra.DUTDevice, desc string, q ygnmi.WildcardQuery[string], prefix string) error {
	t.Helper()
	_, ok := gnmi.WatchAll(t, dut, q, telemetryTimeout, func(v *ygnmi.Value[string]) bool {
		p, present := v.Val()
		return present && p == prefix
	}).Await(t)
	if !ok {
		return fmt.Errorf("%s: prefix %s not found within %v", desc, prefix, telemetryTimeout)
	}
	return nil
}

func locRibPrefix(t *testing.T, dut *ondatra.DUTDevice, tn *tenant, afi, prefix string) error {
	t.Helper()
	rib := tn.bgpPath().Rib()
	desc := fmt.Sprintf("VRF %s %s loc-rib", tn.vrf, afi)
	if afi == ipv4 {
		return awaitPrefix(t, dut, desc, rib.AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Ipv4Unicast().LocRib().RouteAny().Prefix().State(), prefix)
	}
	return awaitPrefix(t, dut, desc, rib.AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).Ipv6Unicast().LocRib().RouteAny().Prefix().State(), prefix)
}

func adjRibOutPostPrefix(t *testing.T, dut *ondatra.DUTDevice, tn *tenant, afi, nbr, prefix string) error {
	t.Helper()
	rib := tn.bgpPath().Rib()
	desc := fmt.Sprintf("VRF %s %s adj-rib-out-post to %s", tn.vrf, afi, nbr)
	if afi == ipv4 {
		return awaitPrefix(t, dut, desc, rib.AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Ipv4Unicast().Neighbor(nbr).AdjRibOutPost().RouteAny().Prefix().State(), prefix)
	}
	return awaitPrefix(t, dut, desc, rib.AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).Ipv6Unicast().Neighbor(nbr).AdjRibOutPost().RouteAny().Prefix().State(), prefix)
}

// aftEntryPresent reports whether the prefix has a forwarding entry in the VRF.
func aftEntryPresent(t *testing.T, dut *ondatra.DUTDevice, vrf, afi, prefix string) bool {
	t.Helper()
	afts := gnmi.OC().NetworkInstance(vrf).Afts()
	if afi == ipv4 {
		return gnmi.Lookup(t, dut, afts.Ipv4Entry(prefix).State()).IsPresent()
	}
	return gnmi.Lookup(t, dut, afts.Ipv6Entry(prefix).State()).IsPresent()
}

// verifyNoAFTEntries verifies that none of the prefixes is in the VRF AFT.
func verifyNoAFTEntries(t *testing.T, dut *ondatra.DUTDevice, vrf string, v4, v6 string) error {
	t.Helper()
	var errs []error
	if aftEntryPresent(t, dut, vrf, ipv4, cidr(v4, v4PrefixLen)) {
		errs = append(errs, fmt.Errorf("VRF %s: unexpected AFT entry for %s", vrf, cidr(v4, v4PrefixLen)))
	}
	if aftEntryPresent(t, dut, vrf, ipv6, cidr(v6, v6PrefixLen)) {
		errs = append(errs, fmt.Errorf("VRF %s: unexpected AFT entry for %s", vrf, cidr(v6, v6PrefixLen)))
	}
	return errors.Join(errs...)
}

// verifyInstallSuppression checks the table-connection import policy. Platforms
// that suppress the install with a CLI install-map have no table-connection, so
// the AFT checks of the callers verify the suppression there.
func verifyInstallSuppression(t *testing.T, dut *ondatra.DUTDevice, vrf string) error {
	t.Helper()
	if deviations.BgpInstallMapCLIRequired(dut) {
		return nil
	}
	var errs []error
	for _, afi := range []oc.E_Types_ADDRESS_FAMILY{oc.Types_ADDRESS_FAMILY_IPV4, oc.Types_ADDRESS_FAMILY_IPV6} {
		q := gnmi.OC().NetworkInstance(vrf).TableConnection(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, afi).ImportPolicy().State()
		got := gnmi.Get(t, dut, q)
		if !slices.Contains(got, policyNoRoutes) {
			errs = append(errs, fmt.Errorf("VRF %s %v table-connection import-policy = %v, want %q", vrf, afi, got, policyNoRoutes))
		}
	}
	return errors.Join(errs...)
}

func setFlows(t *testing.T, otg *otg.OTG, start bool, flows ...string) {
	t.Helper()
	state := gosnappi.StateTrafficFlowTransmitState.STOP
	if start {
		state = gosnappi.StateTrafficFlowTransmitState.START
	}
	cs := gosnappi.NewControlState()
	cs.Traffic().FlowTransmit().SetState(state).SetFlowNames(flows)
	otg.SetControlState(t, cs)
}

// verifyFlowLoss waits until the flow's loss percentage matches the expectation.
func verifyFlowLoss(t *testing.T, otg *otg.OTG, flow string, wantFullLoss bool) error {
	t.Helper()
	_, ok := gnmi.Watch(t, otg, gnmi.OTG().Flow(flow).Counters().State(), telemetryTimeout, func(v *ygnmi.Value[*otgtelemetry.Flow_Counters]) bool {
		c, present := v.Val()
		if !present || c.GetOutPkts() == 0 {
			return false
		}
		if wantFullLoss {
			return c.GetInPkts() == 0
		}
		return c.GetInPkts() == c.GetOutPkts()
	}).Await(t)
	if !ok {
		c := gnmi.Get(t, otg, gnmi.OTG().Flow(flow).Counters().State())
		return fmt.Errorf("flow %s: tx=%d rx=%d, want %s", flow, c.GetOutPkts(), c.GetInPkts(), map[bool]string{true: "100% loss", false: "0% loss"}[wantFullLoss])
	}
	return nil
}

// stopAndVerifyFlows stops the flows and checks their loss.
func stopAndVerifyFlows(t *testing.T, otg *otg.OTG, wantFullLoss bool, flows ...string) error {
	t.Helper()
	setFlows(t, otg, false, flows...)
	var errs []error
	for _, f := range flows {
		errs = append(errs, verifyFlowLoss(t, otg, f, wantFullLoss))
	}
	return errors.Join(errs...)
}

// awaitOTGPrefix waits for a prefix on an OTG BGP peer that satisfies check.
func awaitOTGPrefixV6(t *testing.T, otg *otg.OTG, peer, prefix string, timeout time.Duration, check func(*otgtelemetry.BgpPeer_UnicastIpv6Prefix) bool) error {
	t.Helper()
	_, ok := gnmi.WatchAll(t, otg, gnmi.OTG().BgpPeer(peer).UnicastIpv6PrefixAny().State(), timeout, func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv6Prefix]) bool {
		p, present := v.Val()
		return present && p.GetAddress() == prefix && p.GetPrefixLength() == v6PrefixLen && check(p)
	}).Await(t)
	if !ok {
		logOTGPrefixesV6(t, otg, peer)
		return fmt.Errorf("OTG peer %s: prefix %s with expected attributes not received within %v", peer, prefix, timeout)
	}
	return nil
}

// logOTGPrefixesV6 logs the IPv6 prefixes the OTG peer reports, to show which
// condition of a failed check was not met. It never changes the test result.
func logOTGPrefixesV6(t *testing.T, otg *otg.OTG, peer string) {
	t.Helper()
	vals := gnmi.LookupAll(t, otg, gnmi.OTG().BgpPeer(peer).UnicastIpv6PrefixAny().State())
	if len(vals) == 0 {
		t.Logf("[OTG-DIAG] peer %s reports no IPv6 prefixes", peer)
		return
	}
	for _, v := range vals {
		p, present := v.Val()
		if !present {
			continue
		}
		var asns []uint32
		for _, seg := range p.AsPath {
			asns = append(asns, seg.GetAsNumbers()...)
		}
		t.Logf("[OTG-DIAG] peer %s: prefix %s/%d local-pref=%d as-path=%v", peer, p.GetAddress(), p.GetPrefixLength(), p.GetLocalPreference(), asns)
	}
}

func hasLocalPref(want uint32) func(*otgtelemetry.BgpPeer_UnicastIpv6Prefix) bool {
	return func(p *otgtelemetry.BgpPeer_UnicastIpv6Prefix) bool { return p.GetLocalPreference() == want }
}

// hasPrepend reports whether the AS path starts with at least n copies of dutAS.
func hasPrepend(n int) func(*otgtelemetry.BgpPeer_UnicastIpv6Prefix) bool {
	return func(p *otgtelemetry.BgpPeer_UnicastIpv6Prefix) bool {
		if len(p.AsPath) == 0 {
			return false
		}
		asns := p.AsPath[0].GetAsNumbers()
		if len(asns) < n {
			return false
		}
		for _, as := range asns {
			if as != dutAS {
				return false
			}
		}
		return true
	}
}

func notPrepended(p *otgtelemetry.BgpPeer_UnicastIpv6Prefix) bool {
	return !hasPrepend(drainPrependN)(p)
}

// setSoftDrain applies (drain=true) or removes the soft drain policies of the tenant.
func setSoftDrain(t *testing.T, dut *ondatra.DUTDevice, tn *tenant, drain bool) {
	t.Helper()
	coreExport, ceExport := policyAllow, policyAllow
	if drain {
		coreExport, ceExport = policyDrainCore, policyDrainCE
	}
	root := &oc.Root{}
	bgp := root.GetOrCreateNetworkInstance(tn.vrf).GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, bgpName).GetOrCreateBgp()

	ce := bgp.GetOrCreateNeighbor(tn.ateCE.IPv4)
	applyPolicies(dut, ce, policyAllow, ceExport)
	rr := bgp.GetOrCreateNeighbor(tn.ateRR.IPv6)
	applyPolicies(dut, rr, policyAllow, coreExport)

	sb := &gnmi.SetBatch{}
	for _, n := range []struct {
		addr string
		nbr  *oc.NetworkInstance_Protocol_Bgp_Neighbor
	}{{tn.ateCE.IPv4, ce}, {tn.ateRR.IPv6, rr}} {
		path := tn.bgpPath().Neighbor(n.addr)
		// The apply-policy containers are replaced, not updated, so that the
		// previous export policy list is not merged with the new one.
		if deviations.RoutePolicyUnderAFIUnsupported(dut) {
			gnmi.BatchReplace(sb, path.ApplyPolicy().Config(), n.nbr.GetApplyPolicy())
			continue
		}
		for _, afi := range []oc.E_BgpTypes_AFI_SAFI_TYPE{oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST, oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST} {
			gnmi.BatchReplace(sb, path.AfiSafi(afi).ApplyPolicy().Config(), n.nbr.GetAfiSafi(afi).GetApplyPolicy())
		}
	}
	sb.Set(t, dut)
}

// establishedTransitions returns the neighbor's established-transitions counter.
func establishedTransitions(t *testing.T, dut *ondatra.DUTDevice, tn *tenant, nbr string) (uint64, bool) {
	t.Helper()
	v := gnmi.Lookup(t, dut, tn.bgpPath().Neighbor(nbr).EstablishedTransitions().State())
	got, ok := v.Val()
	return got, ok
}

// logDebugCLI logs the DUT output of show commands for debugging. It is a no-op
// unless -debug_cli is set and it never fails the test.
func logDebugCLI(t *testing.T, dut *ondatra.DUTDevice, when string, tenants ...*tenant) {
	t.Helper()
	if !*debugCLI {
		return
	}
	if dut.Vendor() != ondatra.ARISTA {
		t.Logf("[DEBUG-CLI] %s: show commands are only defined for Arista, skipping", when)
		return
	}
	cmds := []string{
		"show version",
		"show running-config | include routing",
		"show vrf",
		"show running-config section router bgp",
		fmt.Sprintf("show route-map %s", installMapName),
		fmt.Sprintf("show ip prefix-list %s", suppressPfxV4),
		fmt.Sprintf("show ipv6 prefix-list %s", suppressPfxV6),
	}
	for _, tn := range tenants {
		cmds = append(cmds,
			"show bgp summary vrf "+tn.vrf,
			"show bgp ipv4 unicast vrf "+tn.vrf,
			"show bgp ipv6 unicast vrf "+tn.vrf,
			"show ip route vrf "+tn.vrf,
			"show ipv6 route vrf "+tn.vrf,
			"show ipv6 neighbors vrf "+tn.vrf,
			"show bgp neighbors "+tn.ateRR.IPv6+" ipv4 unicast advertised-routes vrf "+tn.vrf,
			"show bgp neighbors "+tn.ateRR.IPv6+" ipv6 unicast advertised-routes vrf "+tn.vrf,
			"show interfaces counters",
			"show interfaces counters discards",
			"show interfaces counters errors",
			// The gNMI CLI path escapes "/", which EOS rejects, so the commands use no prefix length.
			fmt.Sprintf("show ipv6 route vrf %s %s1 detail", tn.vrf, tn.corePfxV6),
			fmt.Sprintf("show bgp ipv4 unicast %s detail vrf %s", tn.ceV4, tn.vrf))
	}
	client := dut.RawAPIs().GNMI(t)
	for _, cmd := range cmds {
		req := &gpb.GetRequest{
			Path:     []*gpb.Path{{Origin: "cli", Elem: []*gpb.PathElem{{Name: cmd}}}},
			Encoding: gpb.Encoding_ASCII,
			Type:     gpb.GetRequest_ALL,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		resp, err := client.Get(ctx, req)
		cancel()
		if err != nil {
			t.Logf("[DEBUG-CLI] %s: %q failed: %v", when, cmd, err)
			continue
		}
		var out strings.Builder
		for _, n := range resp.GetNotification() {
			for _, u := range n.GetUpdate() {
				if s := u.GetVal().GetAsciiVal(); s != "" {
					out.WriteString(s)
				} else {
					out.WriteString(u.GetVal().String())
				}
			}
		}
		t.Logf("[DEBUG-CLI] %s: %s\n%s", when, cmd, out.String())
	}
}

func TestBGPFIBIsolationAndDrain(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")
	_, ce1, ce2 := setupEnvironment(t, dut, ate)
	otgDev := ate.OTG()
	logDebugCLI(t, dut, "after setup", ce1, ce2)

	ce1V4 := cidr(ce1V4Prefix, v4PrefixLen)
	ce1V6 := cidr(ce1V6Prefix, v6PrefixLen)
	ce2V4 := cidr(ce2V4Prefix, v4PrefixLen)
	ce2V6 := cidr(ce2V6Prefix, v6PrefixLen)

	testCases := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "RT-1.107.1 - Multi-Tenant FIB Routing Isolation",
			run: func(t *testing.T) error {
				var errs []error
				t.Log("Step 1/2: customer prefixes are learned in their own VRFs")
				errs = append(errs,
					locRibPrefix(t, dut, ce1, ipv4, ce1V4), locRibPrefix(t, dut, ce1, ipv6, ce1V6),
					locRibPrefix(t, dut, ce2, ipv4, ce2V4), locRibPrefix(t, dut, ce2, ipv6, ce2V6))

				t.Log("Step 3: VRF ce1 has no forwarding entries for the ce2 prefixes")
				errs = append(errs, verifyInstallSuppression(t, dut, ce1.vrf), verifyNoAFTEntries(t, dut, ce1.vrf, ce2V4Prefix, ce2V6Prefix))

				t.Log("Step 4: VRF ce2 has no forwarding entries for the ce1 prefixes")
				errs = append(errs, verifyInstallSuppression(t, dut, ce2.vrf), verifyNoAFTEntries(t, dut, ce2.vrf, ce1V4Prefix, ce1V6Prefix))

				t.Log("Step 5: cross-VRF probes are dropped, with same-VRF flows as a positive control")
				leak := []string{flowCE1toCE2v4, flowCE1toCE2v6, flowCE2toCE1v4, flowCE2toCE1v6}
				control := []string{flowCE1toRR1, flowCE2toRR2}
				setFlows(t, otgDev, true, append(append([]string{}, leak...), control...)...)
				// A drop is only evidence of isolation when forwarding works in the same VRFs.
				errs = append(errs, stopAndVerifyFlows(t, otgDev, true, leak...), stopAndVerifyFlows(t, otgDev, false, control...))
				return errors.Join(errs...)
			},
		},
		{
			name: "RT-1.107.2 - FIB Suppression (No-Install to Forwarding Table)",
			run: func(t *testing.T) error {
				var errs []error
				t.Log("Step 1: customer prefixes are present in the BGP loc-rib")
				errs = append(errs, locRibPrefix(t, dut, ce1, ipv4, ce1V4), locRibPrefix(t, dut, ce1, ipv6, ce1V6))

				t.Log("Steps 2/3: customer prefixes are not installed in the AFT")
				errs = append(errs, verifyNoAFTEntries(t, dut, ce1.vrf, ce1V4Prefix, ce1V6Prefix))

				t.Log("Step 4: core transit traffic is still forwarded and not terminated locally")
				setFlows(t, otgDev, true, flowCE1toRR1)
				errs = append(errs, stopAndVerifyFlows(t, otgDev, false, flowCE1toRR1))
				return errors.Join(errs...)
			},
		},
		{
			name: "RT-1.107.3 - Advertise Inactive Routes to iBGP Peers",
			run: func(t *testing.T) error {
				var errs []error
				t.Log("Step 1: advertise-inactive-routes is enabled")
				if got := gnmi.Get(t, dut, ce1.bgpPath().Global().RouteSelectionOptions().AdvertiseInactiveRoutes().State()); !got {
					errs = append(errs, fmt.Errorf("VRF %s advertise-inactive-routes = %v, want true", ce1.vrf, got))
				}

				t.Log("Step 2: ATE RR1 receives the customer prefixes over iBGP")
				errs = append(errs, awaitOTGPrefixV6(t, otgDev, bgpV6PeerName(ce1.ateRR), ce1V6Prefix, telemetryTimeout, hasLocalPref(defaultLocalPref)))

				t.Log("Step 3: adj-rib-out-post and sent prefix counters reflect the advertisements")
				if !deviations.BgpAdjRibOcUnsupported(dut) {
					errs = append(errs,
						adjRibOutPostPrefix(t, dut, ce1, ipv4, ce1.ateRR.IPv6, ce1V4),
						adjRibOutPostPrefix(t, dut, ce1, ipv6, ce1.ateRR.IPv6, ce1V6))
				}
				for _, afi := range []oc.E_BgpTypes_AFI_SAFI_TYPE{oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST, oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST} {
					q := ce1.bgpPath().Neighbor(ce1.ateRR.IPv6).AfiSafi(afi).Prefixes().Sent().State()
					if _, ok := gnmi.Watch(t, dut, q, telemetryTimeout, func(v *ygnmi.Value[uint32]) bool {
						got, present := v.Val()
						return present && got >= 1
					}).Await(t); !ok {
						errs = append(errs, fmt.Errorf("VRF %s %v prefixes sent to %s is 0, want >= 1", ce1.vrf, afi, ce1.ateRR.IPv6))
					}
				}
				return errors.Join(errs...)
			},
		},
		{
			name: "RT-1.107.4 - Tenant eBGP Soft Drain",
			run: func(t *testing.T) error {
				var errs []error
				ceBefore, ceOK := establishedTransitions(t, dut, ce1, ce1.ateCE.IPv4)
				rrBefore, rrOK := establishedTransitions(t, dut, ce1, ce1.ateRR.IPv6)

				t.Log("Step 1: steady-state traffic CE1->RR1 and CE2->RR2")
				setFlows(t, otgDev, true, flowCE1toRR1, flowCE2toRR2)

				t.Log("Step 2: apply the soft drain policy for CE1")
				setSoftDrain(t, dut, ce1, true)

				t.Log("Step 3: RR1 sees local-pref 10, CE1 sees the prepended AS path")
				errs = append(errs,
					awaitOTGPrefixV6(t, otgDev, bgpV6PeerName(ce1.ateRR), ce1V6Prefix, telemetryTimeout, hasLocalPref(drainLocalPref)),
					awaitOTGPrefixV6(t, otgDev, bgpV4PeerName(ce1.ateCE), rr1V6Prefix, telemetryTimeout, hasPrepend(drainPrependN)))
				if _, ok := gnmi.WatchAll(t, dut, ce1.bgpPath().Rib().AttrSetAny().LocalPref().State(), telemetryTimeout, func(v *ygnmi.Value[uint32]) bool {
					got, present := v.Val()
					return present && got == drainLocalPref
				}).Await(t); !ok {
					errs = append(errs, fmt.Errorf("VRF %s attr-set local-pref %d not found", ce1.vrf, drainLocalPref))
				}

				t.Log("Step 4: tenant ce2 is unaffected")
				errs = append(errs, verifyBGPEstablished(t, dut, ce2, ce2.ateCE.IPv4), stopAndVerifyFlows(t, otgDev, false, flowCE2toRR2))
				setFlows(t, otgDev, false, flowCE1toRR1)

				t.Log("The CE1 and RR1 sessions were not reset by the drain")
				if ceOK {
					if got, _ := establishedTransitions(t, dut, ce1, ce1.ateCE.IPv4); got != ceBefore {
						errs = append(errs, fmt.Errorf("CE1 session established-transitions %d -> %d, want unchanged", ceBefore, got))
					}
				}
				if rrOK {
					if got, _ := establishedTransitions(t, dut, ce1, ce1.ateRR.IPv6); got != rrBefore {
						errs = append(errs, fmt.Errorf("RR1 session established-transitions %d -> %d, want unchanged", rrBefore, got))
					}
				}
				return errors.Join(errs...)
			},
		},
		{
			name: "RT-1.107.5 - Reconvergence on Undrain",
			run: func(t *testing.T) error {
				var errs []error
				ceBefore, ceOK := establishedTransitions(t, dut, ce1, ce1.ateCE.IPv4)

				t.Log("Step 1: remove the soft drain policy")
				start := time.Now()
				setSoftDrain(t, dut, ce1, false)

				t.Log("Step 2/3: attributes are restored on RR1 and CE1 within the convergence budget")
				errs = append(errs,
					awaitOTGPrefixV6(t, otgDev, bgpV6PeerName(ce1.ateRR), ce1V6Prefix, telemetryTimeout, hasLocalPref(defaultLocalPref)),
					awaitOTGPrefixV6(t, otgDev, bgpV4PeerName(ce1.ateCE), rr1V6Prefix, telemetryTimeout, notPrepended))
				if elapsed := time.Since(start); len(errs) > 0 {
					t.Logf("Skipping the convergence time check, the attributes were not restored (elapsed %v)", elapsed)
				} else if elapsed > convergenceTimeout {
					errs = append(errs, fmt.Errorf("undrain convergence took %v, want < %v", elapsed, convergenceTimeout))
				} else {
					t.Logf("Undrain convergence took %v", time.Since(start))
				}

				if ceOK {
					if got, _ := establishedTransitions(t, dut, ce1, ce1.ateCE.IPv4); got != ceBefore {
						errs = append(errs, fmt.Errorf("CE1 session flapped on undrain: established-transitions %d -> %d", ceBefore, got))
					}
				}
				return errors.Join(errs...)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(t); err != nil {
				t.Errorf("%s: %v", tc.name, err)
				logDebugCLI(t, dut, "after failure of "+tc.name, ce1, ce2)
			}
		})
	}
}
