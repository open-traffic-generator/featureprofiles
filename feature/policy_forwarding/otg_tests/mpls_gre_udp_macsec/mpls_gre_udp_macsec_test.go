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

// Package mpls_gre_udp_macsec verifies MACsec + MKA on an aggregate (LAG)
// customer link combined with MPLSoGRE encapsulation towards the core. It is a
// basic PF-1.17 test: it brings up the MACsec/MKA session over the customer
// LAG, forwards IPv4 and IPv6 traffic that the DUT encapsulates in MPLSoGRE
// towards the core, and in the reverse direction decapsulates MPLSoGRE traffic
// from the core and delivers the inner IPv4 to the customer over MACsec.
//
// MACsec-over-LAG configuration is modelled on
// feature/ipsec/otg_tests/ipsec_base/ipsec_base_test.go and the MPLSoGRE encap
// configuration on
// feature/policy_forwarding/otg_tests/mpls_gre_ipv4_encap_test/mpls_gre_ipv4_encap_test.go.
package mpls_gre_udp_macsec

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"

	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/cfgplugins"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/helpers"
	packetvalidationhelpers "github.com/openconfig/featureprofiles/internal/otg_helpers/packetvalidationhelpers"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/netutil"
)

const (
	// baseSubinterfaceIndex is the index for the base/management subinterface.
	baseSubinterfaceIndex = 0

	// OTG topology names.
	ateCustLagName = "Lag1"
	ateCoreLagName = "Lag2"
	ateCustDev     = "d1"
	ateCoreDev     = "d2"
	ateCustGUEDev  = "d3"

	// custVlan is the customer dual-stack subinterface / VLAN ID.
	custVlan = 20

	// OTG flow names.
	flowIPv4Fwd   = "Flow-IPv4-Encap"
	flowIPv6Fwd   = "Flow-IPv6-Encap"
	flowIPv4Decap = "Flow-IPv4-Decap"

	// OTG GUE (MPLS-in-UDP) flow names.
	flowGUEIPv4Fwd   = "Flow-GUE-IPv4-Encap"
	flowGUEIPv6Fwd   = "Flow-GUE-IPv6-Encap"
	flowGUEIPv4Decap = "Flow-GUE-IPv4-Decap"

	// custVlanGUE is the GUE customer dual-stack subinterface / VLAN ID.
	custVlanGUE = 30

	// Traffic parameters.
	trafficPPS      = 100
	trafficDuration = 15 * time.Second

	// lbTolerance is the allowed deviation from an even per-member share when
	// verifying decap traffic is load-balanced across the customer LAG members.
	lbTolerance = 0.2

	// Timeouts.
	sessionUpTimeout = 2 * time.Minute
	verifyTimeout    = 2 * time.Minute

	// MPLSoGRE encapsulation parameters (Arista mpls-over-gre next-hop-group).
	mplsGreNHGName       = "MPLSOGRE_NHG"
	mplsGreTrafficPolicy = "MPLSOGRE_TRAFFIC_POLICY"
	mplsGreLabel         = 16000
	mplsGreOuterTTL      = 64

	// MPLSoGRE decapsulation parameters (reverse direction: core -> customer). The
	// DUT matches GRE traffic to decapTunnelIP, pops decapLabel, and forwards the
	// inner IPv4 to the customer next-hop.
	decapGroupName = "gre-decap"
	decapTunnelIP  = "11.0.0.0/8"
	decapOuterDst  = "11.1.1.1"
	decapOuterSrc  = "100.64.0.1"
	decapLabel     = 99991
	decapInnerSrc  = "22.1.1.1"
	decapInnerDst  = "21.1.1.1"
	mplsEthertype  = 34887 // IANA MPLS unicast ethertype (0x8847), used as GRE protocol.

	// MPLSoGUE (MPLS-in-UDP) encapsulation parameters (Arista mpls-over-gre
	// next-hop-group converted to UDP via the RFC 7510 destination port 6635).
	mplsGueNHGName       = "MPLSOGUE_NHG"
	mplsGueTrafficPolicy = "MPLSOGUE_TRAFFIC_POLICY"
	mplsGueLabel         = 16001
	mplsGueOuterTTL      = 64
	mplsGueUDPDstPort    = 6635 // RFC 7510 standard MPLS-in-UDP port.
	mplsGueTunnelDst     = "10.99.1.2"

	// MPLSoGUE decapsulation parameters (reverse direction: core -> customer). The
	// DUT matches UDP/6635 traffic to gueDecapTunnelIP, pops gueDecapLabel, and
	// forwards the inner IPv4 to the GUE customer next-hop.
	gueDecapGroupName = "gue-decap"
	gueDecapTunnelIP  = "12.0.0.0/8"
	gueDecapOuterDst  = "12.1.1.1"
	gueDecapOuterSrc  = "100.64.0.2"
	gueDecapLabel     = 99992
	gueDecapInnerSrc  = "32.1.1.1"
	gueDecapInnerDst  = "31.1.1.1"
)

// SizeWeightPair defines a frame size and its relative weight for the IMIX.
type SizeWeightPair struct {
	Size   uint32
	Weight float32
}

var (
	// enableCustomerMACsec toggles MACsec/MKA on the customer LAG (DUT + ATE). Set
	// to false to isolate whether MACsec inline-crypto blocks data-flow generation.
	enableCustomerMACsec = true

	// enableGRE / enableGUE select the encapsulation path(s) exercised by the test.
	// Each is an independent, MACsec-protected customer subinterface on the same
	// customer LAG, so they can be run one at a time or together. By default only
	// MPLSoGRE runs; set enableGUE=true (and optionally enableGRE=false) to run the
	// MPLSoGUE path.
	enableGRE = true
	enableGUE = false

	// DUT/ATE port groupings.
	// custPorts is the customer-facing (MACsec) 2-member aggregate; corePorts
	// is the single-member core aggregate (MPLSoGRE egress, no MACsec).
	custPorts = []string{"port1", "port2"}
	corePorts = []string{"port3"}

	// macsecPeerNames holds the OTG MACsec secure-entity/peer name per customer LAG member port.
	macsecPeerNames = []string{"Peer A", "Peer B"}

	// MKA keys reused from the ipsec_base reference.
	cak         = "1234abcd1234abcd1234abcd1234abcd"
	ckn         = "12345678123456781234567812345678"
	fallbackCak = "1234abcd1234abcd1234abcd1234abce"
	fallbackCkn = "12345678123456781234567812345679"

	// DUT customer subinterface: a single dual-stack subinterface on custVlan.
	custIntf = attrs.Attributes{
		Desc:         "Customer dual-stack",
		MTU:          1500,
		IPv4:         "169.254.0.11",
		IPv4Len:      29,
		IPv6:         "2600:2d00:0:1:8000:10:0:ca31",
		IPv6Len:      125,
		Subinterface: custVlan,
	}
	// DUT GUE customer subinterface: a second dual-stack subinterface (on the same
	// customer LAG) used for the MPLSoGUE encap/decap path.
	custIntfGUE = attrs.Attributes{
		Desc:         "Customer dual-stack GUE",
		MTU:          1500,
		IPv4:         "169.254.1.11",
		IPv4Len:      29,
		IPv6:         "2600:2d00:0:2:8000:10:0:ca31",
		IPv6Len:      125,
		Subinterface: custVlanGUE,
	}
	// DUT core interface (MPLSoGRE egress).
	coreIntf = attrs.Attributes{
		Desc:    "Core interface",
		IPv4:    "194.0.2.1",
		IPv4Len: 24,
		IPv6:    "2001:10:1:6::1",
		IPv6Len: 126,
		MTU:     9202,
	}

	// MPLSoGRE tunnel endpoints: source is the DUT core interface, destination is
	// routed to the ATE core via the static route.
	mplsGreTunnelSrc = coreIntf.IPv4
	mplsGreTunnelDst = "10.99.1.1"

	// ATE customer addresses (single dual-stack device).
	ateCustV4   = "169.254.0.12"
	ateCustV6   = "2600:2d00:0:1:8000:10:0:ca32"
	ateCustV4Gw = custIntf.IPv4
	ateCustV6Gw = custIntf.IPv6
	ateCustMAC  = "00:00:11:01:01:01"
	// Per-member port MACs for the customer LAG.
	ateCustLagPMACs = []string{"00:16:01:00:00:02", "00:16:01:00:00:03"}

	// ATE GUE customer addresses (second dual-stack device on the customer LAG).
	ateCustGUEV4   = "169.254.1.12"
	ateCustGUEV6   = "2600:2d00:0:2:8000:10:0:ca32"
	ateCustGUEV4Gw = custIntfGUE.IPv4
	ateCustGUEV6Gw = custIntfGUE.IPv6
	ateCustGUEMAC  = "00:00:11:03:03:03"

	// ATE core addresses.
	ateCoreV4   = "194.0.2.2"
	ateCoreV6   = "2001:10:1:6::2"
	ateCoreV4Gw = coreIntf.IPv4
	ateCoreV6Gw = coreIntf.IPv6
	ateCoreMAC  = "00:00:12:02:02:03"
	// Per-member port MACs for the core LAG.
	ateCoreLagPMACs = []string{"00:17:01:00:00:01", "00:17:01:00:00:02"}

	// Inner (payload) destinations for the encapsulated flows.
	innerV4Dst = "11.1.1.1"
	innerV6Dst = "2000:1::1"

	// IMIX profile shared by all flows.
	sizeWeightProfile = []SizeWeightPair{
		{Size: 64, Weight: 20},
		{Size: 128, Weight: 20},
		{Size: 256, Weight: 20},
		{Size: 512, Weight: 10},
		{Size: 1024, Weight: 20},
		{Size: 1500, Weight: 10},
	}
)

// Encapsulated-packet validation on the core port. It confirms MPLSoGRE
// encapsulation by matching the pushed MPLS label (deterministic from the
// next-hop-group configuration).
var (
	encapValidations = []packetvalidationhelpers.ValidationType{
		packetvalidationhelpers.ValidateMPLSLayer,
	}
	encapPacketValidation = &packetvalidationhelpers.PacketValidation{
		PortName:    "port3",
		CaptureName: "encap-capture",
		MPLSLayer:   &packetvalidationhelpers.MPLSLayer{Label: mplsGreLabel, Tc: 0},
		Validations: encapValidations,
	}
)

// GUE-encapsulated-packet validation on the core port. MPLSoGUE encapsulation is
// confirmed by the outer UDP destination port (RFC 7510, 6635); the DUT derives
// the UDP source port from a flow hash, so it is not checked. It reuses the same
// core-port capture as the GRE encap validation.
var (
	gueEncapValidations = []packetvalidationhelpers.ValidationType{
		packetvalidationhelpers.ValidateUDPHeader,
	}
	gueEncapPacketValidation = &packetvalidationhelpers.PacketValidation{
		PortName:    "port3",
		CaptureName: "encap-capture",
		UDPLayer:    &packetvalidationhelpers.UDPLayer{DstPort: mplsGueUDPDstPort, SkipSrcPortCheck: true},
		Validations: gueEncapValidations,
	}
)

// Decapsulated-packet validation on the customer LAG member ports. In the
// reverse direction the DUT pops the MPLSoGRE header and delivers the inner
// IPv4 packet to the customer MACsec-encrypted, so on the wire it appears as a
// MACsec (802.1AE) frame. The decap flow hashes to a single LAG member, so we
// capture on every customer port and require the MACsec frame on at least one.
var (
	decapValidations = []packetvalidationhelpers.ValidationType{
		packetvalidationhelpers.ValidateMacsecHeader,
	}
	decapPacketValidations = []*packetvalidationhelpers.PacketValidation{
		{
			PortName:    "port1",
			CaptureName: "decap-capture-port1",
			MacsecLayer: &packetvalidationhelpers.MacsecLayer{},
			Validations: decapValidations,
		},
		{
			PortName:    "port2",
			CaptureName: "decap-capture-port2",
			MacsecLayer: &packetvalidationhelpers.MacsecLayer{},
			Validations: decapValidations,
		},
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// configureInterfaceAddress configures the IPv4/IPv6 addresses on a subinterface.
func configureInterfaceAddress(dut *ondatra.DUTDevice, s *oc.Interface_Subinterface, a *attrs.Attributes) {
	s4 := s.GetOrCreateIpv4()
	if deviations.InterfaceEnabled(dut) {
		s4.Enabled = ygot.Bool(true)
	}
	if a.IPv4 != "" {
		s4.GetOrCreateAddress(a.IPv4).PrefixLength = ygot.Uint8(a.IPv4Len)
	}
	s6 := s.GetOrCreateIpv6()
	if deviations.InterfaceEnabled(dut) {
		s6.Enabled = ygot.Bool(true)
	}
	if a.IPv6 != "" {
		s6.GetOrCreateAddress(a.IPv6).PrefixLength = ygot.Uint8(a.IPv6Len)
	}
}

// configDUTInterface builds the aggregate interface with its subinterfaces.
func configDUTInterface(i *oc.Interface, subinterfaces []*attrs.Attributes, dut *ondatra.DUTDevice) {
	for _, a := range subinterfaces {
		i.Description = ygot.String(a.Desc)
		if deviations.InterfaceEnabled(dut) {
			i.Enabled = ygot.Bool(true)
		}
		s0 := i.GetOrCreateSubinterface(baseSubinterfaceIndex)
		b4 := s0.GetOrCreateIpv4()
		b6 := s0.GetOrCreateIpv6()
		b4.Mtu = ygot.Uint16(a.MTU)
		b6.Mtu = ygot.Uint32(uint32(a.MTU))
		if deviations.InterfaceEnabled(dut) {
			b4.Enabled = ygot.Bool(true)
		}
		if a.Subinterface != 0 {
			s := i.GetOrCreateSubinterface(a.Subinterface)
			s.GetOrCreateVlan().GetOrCreateMatch().GetOrCreateSingleTagged().SetVlanId(uint16(a.Subinterface))
			configureInterfaceAddress(dut, s, a)
		} else {
			configureInterfaceAddress(dut, s0, a)
		}
	}
}

// configureInterfaces configures the aggregate (LAG) and its member ports.
func configureInterfaces(t *testing.T, dut *ondatra.DUTDevice, dutPorts []string, subinterfaces []*attrs.Attributes, aggID string) {
	t.Helper()
	d := gnmi.OC()
	dutAggPorts := []*ondatra.Port{}
	for _, port := range dutPorts {
		dutAggPorts = append(dutAggPorts, dut.Port(t, port))
	}
	if deviations.AggregateAtomicUpdate(dut) {
		cfgplugins.DeleteAggregate(t, dut, aggID, dutAggPorts)
		cfgplugins.SetupAggregateAtomically(t, dut, aggID, dutAggPorts)
	}

	lacp := &oc.Lacp_Interface{Name: ygot.String(aggID)}
	lacp.LacpMode = oc.Lacp_LacpActivityType_ACTIVE
	lacpPath := d.Lacp().Interface(aggID)
	gnmi.Replace(t, dut, lacpPath.Config(), lacp)

	agg := &oc.Interface{Name: ygot.String(aggID)}
	configDUTInterface(agg, subinterfaces, dut)
	agg.GetOrCreateAggregation().LagType = oc.IfAggregate_AggregationType_LACP
	agg.Type = oc.IETFInterfaces_InterfaceType_ieee8023adLag
	aggPath := d.Interface(aggID)
	gnmi.Replace(t, dut, aggPath.Config(), agg)
}

// configureStaticRoute configures the route to the GRE tunnel destination via the core next-hop.
func configureStaticRoute(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	b := &gnmi.SetBatch{}
	sV4 := &cfgplugins.StaticRouteCfg{
		NetworkInstance: deviations.DefaultNetworkInstance(dut),
		Prefix:          "10.99.1.0/24",
		NextHops: map[string]oc.NetworkInstance_Protocol_Static_NextHop_NextHop_Union{
			"0": oc.UnionString(ateCoreV4),
		},
	}
	if _, err := cfgplugins.NewStaticRouteCfg(b, sV4, dut); err != nil {
		t.Fatalf("Failed to configure IPv4 static route: %v", err)
	}
	b.Set(t, dut)
}

// configureMPLSoGREEncap configures a plain MPLSoGRE encapsulation: an
// mpls-over-gre next-hop-group plus a traffic-policy that redirects all customer
// IPv4/IPv6 traffic into it, applied on the customer subinterfaces.
func configureMPLSoGREEncap(t *testing.T, dut *ondatra.DUTDevice, custAggID string) {
	t.Helper()
	if dut.Vendor() != ondatra.ARISTA {
		t.Fatalf("MPLSoGRE encap CLI is only implemented for Arista, got vendor %v", dut.Vendor())
	}
	cfgplugins.MplsConfig(t, dut)
	cli := fmt.Sprintf(`
nexthop-group %[1]s type mpls-over-gre
   ttl %[2]d
   tunnel-source %[3]s
   fec hierarchical
   entry 0 push label-stack %[4]d tunnel-destination %[5]s tunnel-source %[3]s
!
traffic-policies
   traffic-policy %[6]s
      match ipv4-all-default ipv4
         actions
            count
            redirect next-hop group %[1]s
      !
      match ipv6-all-default ipv6
         actions
            count
            redirect next-hop group %[1]s
   !
!
interface %[7]s.%[8]d
   traffic-policy input %[6]s
!`,
		mplsGreNHGName, mplsGreOuterTTL, mplsGreTunnelSrc, mplsGreLabel,
		mplsGreTunnelDst, mplsGreTrafficPolicy, custAggID, custVlan)
	helpers.GnmiCLIConfig(t, dut, cli)
}

// configureMPLSoGREDecap configures the reverse-direction decapsulation: a GRE
// decap-group plus a static MPLS LSP that pops the label and forwards the inner
// IPv4 to the customer next-hop (which egresses MACsec-encrypted).
func configureMPLSoGREDecap(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	if dut.Vendor() != ondatra.ARISTA {
		t.Fatalf("MPLSoGRE decap CLI is only implemented for Arista, got vendor %v", dut.Vendor())
	}
	cli := fmt.Sprintf(`
ip decap-group %[1]s
   tunnel type gre
   tunnel decap-ip %[2]s
   tunnel overlay mpls qos map mpls-traffic-class to traffic-class
!
mpls static top-label %[3]d %[4]s pop payload-type ipv4 access-list bypass
!`,
		decapGroupName, decapTunnelIP, decapLabel, ateCustV4)
	helpers.GnmiCLIConfig(t, dut, cli)
}

// configureMPLSoGUEEncap configures a plain MPLSoGUE (MPLS-in-UDP) encapsulation:
// an mpls-over-gre next-hop-group converted to UDP (RFC 7510 port 6635) plus a
// traffic-policy that redirects the GUE customer subinterface IPv4/IPv6 traffic
// into it.
func configureMPLSoGUEEncap(t *testing.T, dut *ondatra.DUTDevice, custAggID string) {
	t.Helper()
	if dut.Vendor() != ondatra.ARISTA {
		t.Fatalf("MPLSoGUE encap CLI is only implemented for Arista, got vendor %v", dut.Vendor())
	}
	cfgplugins.MplsConfig(t, dut)
	cli := fmt.Sprintf(`
nexthop-group %[1]s type mpls-over-gre
   ttl %[2]d
   tunnel-source %[3]s
   tunnel type mpls-over-udp udp destination port %[9]d
   fec hierarchical
   entry 0 push label-stack %[4]d tunnel-destination %[5]s tunnel-source %[3]s
!
traffic-policies
   traffic-policy %[6]s
      match ipv4-all-default ipv4
         actions
            count
            redirect next-hop group %[1]s
      !
      match ipv6-all-default ipv6
         actions
            count
            redirect next-hop group %[1]s
   !
!
interface %[7]s.%[8]d
   traffic-policy input %[6]s
!`,
		mplsGueNHGName, mplsGueOuterTTL, mplsGreTunnelSrc, mplsGueLabel,
		mplsGueTunnelDst, mplsGueTrafficPolicy, custAggID, custVlanGUE, mplsGueUDPDstPort)
	helpers.GnmiCLIConfig(t, dut, cli)
}

// configureMPLSoGUEDecap configures the reverse-direction decapsulation: a UDP
// decap-group (RFC 7510 port 6635) plus a static MPLS LSP that pops the label and
// forwards the inner IPv4 to the GUE customer next-hop (which egresses
// MACsec-encrypted).
func configureMPLSoGUEDecap(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	if dut.Vendor() != ondatra.ARISTA {
		t.Fatalf("MPLSoGUE decap CLI is only implemented for Arista, got vendor %v", dut.Vendor())
	}
	cli := fmt.Sprintf(`
ip decap-group type udp destination port %[5]d payload mpls
!
ip decap-group %[1]s
   tunnel type udp
   tunnel decap-ip %[2]s
   tunnel overlay mpls qos map mpls-traffic-class to traffic-class
!
mpls static top-label %[3]d %[4]s pop payload-type ipv4 access-list bypass
!`,
		gueDecapGroupName, gueDecapTunnelIP, gueDecapLabel, ateCustGUEV4, mplsGueUDPDstPort)
	helpers.GnmiCLIConfig(t, dut, cli)
}

// configureDUT sets up the customer LAG (with MACsec), the core LAG, static
// routing, and the enabled MPLSoGRE and/or MPLSoGUE encap (customer -> core) and
// decap (core -> customer) paths.
func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	fptest.ConfigureDefaultNetworkInstance(t, dut)

	// Customer aggregate (MACsec edge) with one dual-stack subinterface per
	// enabled encapsulation path.
	custSubs := []*attrs.Attributes{}
	if enableGRE {
		custSubs = append(custSubs, &custIntf)
	}
	if enableGUE {
		custSubs = append(custSubs, &custIntfGUE)
	}
	custAggID := netutil.NextAggregateInterface(t, dut)
	configureInterfaces(t, dut, custPorts, custSubs, custAggID)

	// Enable MACsec on both customer aggregate member ports.
	if enableCustomerMACsec {
		for _, portName := range custPorts {
			batchMACsec := cfgplugins.ConfigureMACsec(t, dut, cfgplugins.MACsecCfg{
				IntfName:    dut.Port(t, portName).Name(),
				ProfileName: "macSecProfile",
				CKN:         ckn,
				CAK:         cak,
				FallbackCKN: fallbackCkn,
				FallbackCAK: fallbackCak,
			})
			batchMACsec.Set(t, dut)
		}
	}

	// Core aggregate (MPLSoGRE/MPLSoGUE egress).
	coreAggID := netutil.NextAggregateInterface(t, dut)
	configureInterfaces(t, dut, corePorts, []*attrs.Attributes{&coreIntf}, coreAggID)

	configureStaticRoute(t, dut)
	if enableGRE {
		configureMPLSoGREEncap(t, dut, custAggID)
		configureMPLSoGREDecap(t, dut)
	}
	if enableGUE {
		configureMPLSoGUEEncap(t, dut, custAggID)
		configureMPLSoGUEDecap(t, dut)
	}
}

// configureATE builds the OTG topology: a MACsec-enabled customer LAG and a core LAG, plus encap flows.
func configureATE(t *testing.T) gosnappi.Config {
	t.Helper()
	top := gosnappi.NewConfig()

	// Customer LAG with MACsec + MKA on every member port (2 members).
	custLag := top.Lags().Add().SetName(ateCustLagName)
	custLag.Protocol().Lacp().SetActorSystemId("00:00:00:00:00:01").SetActorSystemPriority(0).SetActorKey(1)
	for i, portName := range custPorts {
		p := top.Ports().Add().SetName(portName)
		lagPort := custLag.Ports().Add().SetPortName(p.Name())
		lagPort.Lacp().SetActorActivity("active").SetActorPortNumber(uint32(i + 1))
		lagPort.Ethernet().SetName(fmt.Sprintf("lag1Eth%d", i+1)).SetMac(ateCustLagPMACs[i]).SetMtu(uint32(custIntf.MTU))

		if !enableCustomerMACsec {
			continue
		}
		macsec := lagPort.Macsec()
		secy := macsec.SecureEntity().SetName(macsecPeerNames[i])
		secy.DataPlane().Encapsulation().CryptoEngine().EncryptDecrypt().HardwareAcceleration().InlineCrypto()
		mka := secy.KeyGenerationProtocol().Mka().SetName(fmt.Sprintf("Peer%d-Mka", i+1))
		mka.Basic().KeySource().Psk()
		mka.Basic().SetKeyDerivationFunction(gosnappi.MkaBasicKeyDerivationFunctionEnum("aes_cmac_128"))
		mka.Basic().SetSendIcvIndicatiorInMkpdu(false)
		mka.Basic().SetMkaVersion(2)
		scs := mka.Basic().SupportedCipherSuites()
		scs.SetGcmAes256(false)
		scs.SetGcmAesXpn256(false)
		onePsk := mka.Basic().KeySource().Psks().Add()
		onePsk.SetCakValue(cak)
		onePsk.SetCakName(ckn)
		mka.Tx().SecureChannels().Add().SetName(fmt.Sprintf("SecureChannel%d", i+1)).SetSystemId(lagPort.Ethernet().Mac())
	}

	// Core LAG and its dual-stack device.
	d2 := top.Devices().Add().SetName(ateCoreDev)
	coreLag := top.Lags().Add().SetName(ateCoreLagName)
	coreLag.Protocol().Lacp().SetActorSystemId("00:00:00:00:00:02").SetActorSystemPriority(0).SetActorKey(1)
	for i, portName := range corePorts {
		p := top.Ports().Add().SetName(portName)
		lagPort := coreLag.Ports().Add().SetPortName(p.Name())
		lagPort.Lacp().SetActorActivity("active").SetActorPortNumber(uint32(i + 1))
		lagPort.Ethernet().SetName(fmt.Sprintf("lag2Eth%d", i+1)).SetMac(ateCoreLagPMACs[i]).SetMtu(uint32(coreIntf.MTU))
	}

	d2Eth := d2.Ethernets().Add().SetName("d2Eth").SetMac(ateCoreMAC)
	d2Eth.Connection().SetLagName(coreLag.Name())
	d2v4 := d2Eth.Ipv4Addresses().Add().SetName("p2d2ipv4").SetAddress(ateCoreV4).SetGateway(ateCoreV4Gw).SetPrefix(uint32(coreIntf.IPv4Len))
	d2v6 := d2Eth.Ipv6Addresses().Add().SetName("p2d2ipv6").SetAddress(ateCoreV6).SetGateway(ateCoreV6Gw).SetPrefix(uint32(coreIntf.IPv6Len))

	if enableGRE {
		// Customer dual-stack device (VLAN custVlan) on the MACsec LAG.
		d1 := top.Devices().Add().SetName(ateCustDev)
		d1Eth := d1.Ethernets().Add().SetName("d1Eth").SetMac(ateCustMAC)
		d1Eth.Connection().SetLagName(custLag.Name())
		d1Eth.Vlans().Add().SetName("d1Vlan").SetId(custVlan)
		d1v4ip := d1Eth.Ipv4Addresses().Add().SetName("p1d1ipv4").SetAddress(ateCustV4).SetGateway(ateCustV4Gw).SetPrefix(uint32(custIntf.IPv4Len))
		d1v6ip := d1Eth.Ipv6Addresses().Add().SetName("p1d1ipv6").SetAddress(ateCustV6).SetGateway(ateCustV6Gw).SetPrefix(uint32(custIntf.IPv6Len))

		addEncapFlows(top, encapFlowSet{
			v4Name: flowIPv4Fwd, v6Name: flowIPv6Fwd,
			txV4: d1v4ip.Name(), txV6: d1v6ip.Name(), rxV4: d2v4.Name(), rxV6: d2v6.Name(),
			srcMAC: ateCustMAC, vlan: custVlan,
			srcV4: ateCustV4, dstV4: innerV4Dst, srcV6: ateCustV6, dstV6: innerV6Dst,
		})
		// Reverse MPLSoGRE decap flow: core -> customer. The DUT decapsulates the
		// GRE/MPLS packet and forwards the inner IPv4 to the customer, which egresses
		// MACsec-encrypted (the ATE customer secure entity decrypts it).
		flowDecap := top.Flows().Add().SetName(flowIPv4Decap)
		flowDecap.TxRx().Device().SetTxNames([]string{d2v4.Name()}).SetRxNames([]string{d1v4ip.Name()})
		for _, sw := range sizeWeightProfile {
			flowDecap.Size().WeightPairs().Custom().Add().SetSize(sw.Size).SetWeight(sw.Weight)
		}
		flowDecap.Rate().SetPps(trafficPPS)
		flowDecap.Duration().Continuous()
		flowDecap.Metrics().SetEnable(true)
		flowDecap.Packet().Add().Ethernet().Src().SetValue(ateCoreMAC)
		dOuter := flowDecap.Packet().Add().Ipv4()
		dOuter.Src().SetValue(decapOuterSrc)
		dOuter.Dst().SetValue(decapOuterDst)
		flowDecap.Packet().Add().Gre().Protocol().SetValue(mplsEthertype)
		flowDecap.Packet().Add().Mpls().Label().SetValue(decapLabel)
		dInner := flowDecap.Packet().Add().Ipv4()
		// Vary the inner source so the DUT hashes the decapped packets across the
		// customer LAG member ports.
		dInner.Src().Increment().SetStart(decapInnerSrc).SetStep("0.0.0.1").SetCount(100)
		dInner.Dst().SetValue(decapInnerDst)
	}

	if enableGUE {
		// Second customer dual-stack device (VLAN custVlanGUE) on the same MACsec LAG.
		d3 := top.Devices().Add().SetName(ateCustGUEDev)
		d3Eth := d3.Ethernets().Add().SetName("d3Eth").SetMac(ateCustGUEMAC)
		d3Eth.Connection().SetLagName(custLag.Name())
		d3Eth.Vlans().Add().SetName("d3Vlan").SetId(custVlanGUE)
		d3v4ip := d3Eth.Ipv4Addresses().Add().SetName("p1d3ipv4").SetAddress(ateCustGUEV4).SetGateway(ateCustGUEV4Gw).SetPrefix(uint32(custIntfGUE.IPv4Len))
		d3v6ip := d3Eth.Ipv6Addresses().Add().SetName("p1d3ipv6").SetAddress(ateCustGUEV6).SetGateway(ateCustGUEV6Gw).SetPrefix(uint32(custIntfGUE.IPv6Len))

		addEncapFlows(top, encapFlowSet{
			v4Name: flowGUEIPv4Fwd, v6Name: flowGUEIPv6Fwd,
			txV4: d3v4ip.Name(), txV6: d3v6ip.Name(), rxV4: d2v4.Name(), rxV6: d2v6.Name(),
			srcMAC: ateCustGUEMAC, vlan: custVlanGUE,
			srcV4: ateCustGUEV4, dstV4: innerV4Dst, srcV6: ateCustGUEV6, dstV6: innerV6Dst,
		})
		// Reverse MPLSoGUE decap flow: core -> customer. The DUT decapsulates the
		// UDP/MPLS packet and forwards the inner IPv4 to the GUE customer, which
		// egresses MACsec-encrypted.
		flowGueDecap := top.Flows().Add().SetName(flowGUEIPv4Decap)
		flowGueDecap.TxRx().Device().SetTxNames([]string{d2v4.Name()}).SetRxNames([]string{d3v4ip.Name()})
		for _, sw := range sizeWeightProfile {
			flowGueDecap.Size().WeightPairs().Custom().Add().SetSize(sw.Size).SetWeight(sw.Weight)
		}
		flowGueDecap.Rate().SetPps(trafficPPS)
		flowGueDecap.Duration().Continuous()
		flowGueDecap.Metrics().SetEnable(true)
		flowGueDecap.Packet().Add().Ethernet().Src().SetValue(ateCoreMAC)
		gOuter := flowGueDecap.Packet().Add().Ipv4()
		gOuter.Src().SetValue(gueDecapOuterSrc)
		gOuter.Dst().SetValue(gueDecapOuterDst)
		gUDP := flowGueDecap.Packet().Add().Udp()
		gUDP.SrcPort().SetValue(49152)
		gUDP.DstPort().SetValue(mplsGueUDPDstPort)
		flowGueDecap.Packet().Add().Mpls().Label().SetValue(gueDecapLabel)
		gInner := flowGueDecap.Packet().Add().Ipv4()
		// Vary the inner source so the DUT hashes the decapped packets across the
		// customer LAG member ports.
		gInner.Src().Increment().SetStart(gueDecapInnerSrc).SetStep("0.0.0.1").SetCount(100)
		gInner.Dst().SetValue(gueDecapInnerDst)
	}

	return top
}

// encapFlowSet parameterizes the pair of IPv4/IPv6 customer -> core encap flows.
type encapFlowSet struct {
	v4Name, v6Name             string
	txV4, txV6, rxV4, rxV6     string
	srcMAC                     string
	vlan                       uint32
	srcV4, dstV4, srcV6, dstV6 string
}

// addEncapFlows adds the IPv4 and IPv6 customer -> core encap flows for one
// customer subinterface (MACsec header included when enabled).
func addEncapFlows(top gosnappi.Config, f encapFlowSet) {
	flowV4 := top.Flows().Add().SetName(f.v4Name)
	flowV4.TxRx().Device().SetTxNames([]string{f.txV4}).SetRxNames([]string{f.rxV4})
	for _, sw := range sizeWeightProfile {
		flowV4.Size().WeightPairs().Custom().Add().SetSize(sw.Size).SetWeight(sw.Weight)
	}
	flowV4.Rate().SetPps(trafficPPS)
	flowV4.Duration().Continuous()
	flowV4.Metrics().SetEnable(true)
	flowV4.Packet().Add().Ethernet().Src().SetValue(f.srcMAC)
	if enableCustomerMACsec {
		flowV4.Packet().Add().Macsec()
	}
	flowV4.Packet().Add().Vlan().Id().SetValue(f.vlan)
	v4 := flowV4.Packet().Add().Ipv4()
	v4.Src().Increment().SetStart(f.srcV4).SetStep("0.0.0.1").SetCount(100)
	v4.Dst().SetValue(f.dstV4)

	flowV6 := top.Flows().Add().SetName(f.v6Name)
	flowV6.TxRx().Device().SetTxNames([]string{f.txV6}).SetRxNames([]string{f.rxV6})
	for _, sw := range sizeWeightProfile {
		flowV6.Size().WeightPairs().Custom().Add().SetSize(sw.Size).SetWeight(sw.Weight)
	}
	flowV6.Rate().SetPps(trafficPPS)
	flowV6.Duration().Continuous()
	flowV6.Metrics().SetEnable(true)
	flowV6.Packet().Add().Ethernet().Src().SetValue(f.srcMAC)
	if enableCustomerMACsec {
		flowV6.Packet().Add().Macsec()
	}
	flowV6.Packet().Add().Vlan().Id().SetValue(f.vlan)
	v6 := flowV6.Packet().Add().Ipv6()
	v6.Src().Increment().SetStart(f.srcV6).SetStep("::1").SetCount(100)
	v6.Dst().SetValue(f.dstV6)
}

// verifyTraffic waits until the named flow forwards without loss.
func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, cfg gosnappi.Config, flowName string) error {
	t.Helper()
	flowPath := gnmi.OTG().Flow(flowName).State()
	watch := gnmi.Watch(t, ate.OTG(), flowPath, verifyTimeout, func(val *ygnmi.Value[*otgtelemetry.Flow]) bool {
		metric, ok := val.Val()
		if !ok || metric == nil {
			return false
		}
		tx := metric.GetCounters().GetOutPkts()
		rx := metric.GetCounters().GetInPkts()
		return tx > 0 && rx == tx
	})
	last, ok := watch.Await(t)
	if !ok {
		m := gnmi.Get(t, ate.OTG(), flowPath)
		tx := m.GetCounters().GetOutPkts()
		rx := m.GetCounters().GetInPkts()
		otgutils.LogFlowMetrics(t, ate.OTG(), cfg)
		return fmt.Errorf("%s: traffic verification failed: FramesTx=%d FramesRx=%d, want FramesRx==FramesTx and FramesTx>0", flowName, tx, rx)
	}
	m, _ := last.Val()
	otgutils.LogFlowMetrics(t, ate.OTG(), cfg)
	t.Logf("%s: traffic verification passed: FramesTx=%d FramesRx=%d", flowName, m.GetCounters().GetOutPkts(), m.GetCounters().GetInPkts())
	return nil
}

// validateDecapMACsec validates that the DUT delivers the decapped inner IPv4
// packet to the customer MACsec-encrypted. The decap flow hashes to a single
// customer LAG member, so the capture is validated on every customer port and
// the check passes if at least one port carries the MACsec frame.
func validateDecapMACsec(t *testing.T, ate *ondatra.ATEDevice) error {
	t.Helper()
	var errs []error
	for _, dv := range decapPacketValidations {
		if err := packetvalidationhelpers.CaptureAndValidatePackets(t, ate, dv); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", dv.PortName, err))
			continue
		}
		t.Logf("Validated decapped MACsec traffic on %s", dv.PortName)
		return nil
	}
	return fmt.Errorf("no customer port carried the decapped MACsec frame: %v", errs)
}

// readMemberOutPkts reads the egress packet counters for the given DUT ports.
func readMemberOutPkts(t *testing.T, dut *ondatra.DUTDevice, memberPorts []string) map[string]uint64 {
	t.Helper()
	vals := make(map[string]uint64)
	for _, p := range memberPorts {
		vals[p] = gnmi.Get(t, dut, gnmi.OC().Interface(dut.Port(t, p).Name()).Counters().OutPkts().State())
	}
	return vals
}

// verifyLAGLoadBalance confirms the decap traffic egressing the customer LAG is
// distributed across all member ports within tolerance of an even share.
func verifyLAGLoadBalance(t *testing.T, dut *ondatra.DUTDevice, memberPorts []string, baseline map[string]uint64, tolerance float64) error {
	t.Helper()
	after := readMemberOutPkts(t, dut, memberPorts)
	delta := make(map[string]uint64)
	var total uint64
	active := 0
	for _, p := range memberPorts {
		if after[p] > baseline[p] {
			delta[p] = after[p] - baseline[p]
		}
		total += delta[p]
		if delta[p] > 0 {
			active++
		}
	}
	if total == 0 {
		return fmt.Errorf("no egress packets observed on customer LAG member ports")
	}
	var errs []error
	if active != len(memberPorts) {
		errs = append(errs, fmt.Errorf("active members got %d, want %d", active, len(memberPorts)))
	}
	evenShare := 1.0 / float64(len(memberPorts))
	for _, p := range memberPorts {
		share := float64(delta[p]) / float64(total)
		t.Logf("customer LAG member %s: out-pkts delta=%d share=%.3f", p, delta[p], share)
		if math.Abs(share-evenShare) > tolerance {
			errs = append(errs, fmt.Errorf("member %s share got %.3f, want %.3f +/- %.3f", p, share, evenShare, tolerance))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("customer LAG load-balance verification failed: %v", errs)
	}
	return nil
}

// waitForOTGMACSecUp waits for the OTG MACsec session to become UP.
func waitForOTGMACSecUp(t *testing.T, ate *ondatra.ATEDevice, ifName string, timeout time.Duration) {
	t.Helper()
	otg := ate.OTG()
	t.Logf("Waiting for OTG MACsec session on %s to be UP", ifName)
	watch := gnmi.Watch(t, otg, gnmi.OTG().Macsec().Interface(ifName).SessionState().State(), timeout,
		func(val *ygnmi.Value[otgtelemetry.E_Interface_SessionState]) bool {
			state, ok := val.Val()
			return ok && state == otgtelemetry.Interface_SessionState_UP
		})
	if _, ok := watch.Await(t); !ok {
		finalState := gnmi.Get(t, otg, gnmi.OTG().Macsec().Interface(ifName).SessionState().State())
		t.Fatalf("MACsec session on %s did not come UP within %v, final state=%v", ifName, timeout, finalState)
	}
}

// waitForOTGLAGUp waits for the named OTG LAG to be UP with the expected member count.
func waitForOTGLAGUp(t *testing.T, ate *ondatra.ATEDevice, lagName string, wantMembersUp uint64, timeout time.Duration) {
	t.Helper()
	otg := ate.OTG()
	t.Logf("Waiting for OTG LAG %s to be UP with %d member(s)", lagName, wantMembersUp)
	watch := gnmi.Watch(t, otg, gnmi.OTG().Lag(lagName).State(), timeout,
		func(val *ygnmi.Value[*otgtelemetry.Lag]) bool {
			lag, ok := val.Val()
			if !ok || lag == nil {
				return false
			}
			return lag.GetOperStatus() == otgtelemetry.Lag_OperStatus_UP && lag.GetCounters().GetMemberPortsUp() == wantMembersUp
		})
	if _, ok := watch.Await(t); !ok {
		finalOper := gnmi.Get(t, otg, gnmi.OTG().Lag(lagName).OperStatus().State())
		t.Fatalf("OTG LAG %s did not become ready within %v: final oper-status=%v", lagName, timeout, finalOper)
	}
}

// bringUpOTG pushes the OTG config, starts protocols, and waits for the
// MACsec/MKA sessions, both LAGs, and ARP/ND to come up.
func bringUpOTG(t *testing.T, ate *ondatra.ATEDevice, top gosnappi.Config) {
	t.Helper()
	otg := ate.OTG()
	otg.PushConfig(t, top)
	otg.StartProtocols(t)
	if enableCustomerMACsec {
		// One MACsec secure entity per customer member port.
		for i := range custPorts {
			waitForOTGMACSecUp(t, ate, macsecPeerNames[i], sessionUpTimeout)
		}
	}
	waitForOTGLAGUp(t, ate, ateCustLagName, uint64(len(custPorts)), sessionUpTimeout)
	waitForOTGLAGUp(t, ate, ateCoreLagName, uint64(len(corePorts)), sessionUpTimeout)
	otgutils.WaitForARP(t, otg, top, "IPv4")
	otgutils.WaitForARP(t, otg, top, "IPv6")
}

// TestPFMPLSoGREMACsecBaseForwarding is the basic PF-1.17 test: MACsec/MKA over a
// customer LAG plus MPLSoGRE encapsulation of IPv4 and IPv6 traffic towards the core.
func TestPFMPLSoGREMACsecBaseForwarding(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	// Step 1: configure the DUT (customer LAG + MACsec, core LAG, MPLSoGRE/MPLSoGUE encap).
	configureDUT(t, dut)

	// Step 2: configure the ATE topology, flows and capture.
	top := configureATE(t)
	packetvalidationhelpers.ConfigurePacketCapture(t, top, encapPacketValidation)
	for _, dv := range decapPacketValidations {
		packetvalidationhelpers.ConfigurePacketCapture(t, top, dv)
	}

	// Step 3: bring up protocols and verify MACsec/MKA sessions and both LAGs.
	bringUpOTG(t, ate, top)

	// Step 5: run a single traffic window for the enabled encap/decap flows.
	lbBaseline := readMemberOutPkts(t, dut, custPorts)
	cs := packetvalidationhelpers.StartCapture(t, ate)
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	otg.StopTraffic(t)
	packetvalidationhelpers.StopCapture(t, ate, cs)

	if enableGRE {
		if err := verifyTraffic(t, ate, top, flowIPv4Fwd); err != nil {
			t.Errorf("MPLSoGRE IPv4 traffic verification failed: %v", err)
		}
		if err := verifyTraffic(t, ate, top, flowIPv6Fwd); err != nil {
			t.Errorf("MPLSoGRE IPv6 traffic verification failed: %v", err)
		}
		if err := verifyTraffic(t, ate, top, flowIPv4Decap); err != nil {
			t.Errorf("MPLSoGRE IPv4 decap traffic verification failed: %v", err)
		}
		if err := packetvalidationhelpers.CaptureAndValidatePackets(t, ate, encapPacketValidation); err != nil {
			t.Errorf("MPLSoGRE encap validation failed: %v", err)
		}
	}
	if enableGUE {
		if err := verifyTraffic(t, ate, top, flowGUEIPv4Fwd); err != nil {
			t.Errorf("MPLSoGUE IPv4 traffic verification failed: %v", err)
		}
		if err := verifyTraffic(t, ate, top, flowGUEIPv6Fwd); err != nil {
			t.Errorf("MPLSoGUE IPv6 traffic verification failed: %v", err)
		}
		if err := verifyTraffic(t, ate, top, flowGUEIPv4Decap); err != nil {
			t.Errorf("MPLSoGUE IPv4 decap traffic verification failed: %v", err)
		}
		if err := packetvalidationhelpers.CaptureAndValidatePackets(t, ate, gueEncapPacketValidation); err != nil {
			t.Errorf("MPLSoGUE encap validation failed: %v", err)
		}
	}
	if err := validateDecapMACsec(t, ate); err != nil {
		t.Errorf("decap MACsec validation failed: %v", err)
	}
	if err := verifyLAGLoadBalance(t, dut, custPorts, lbBaseline, lbTolerance); err != nil {
		t.Errorf("customer LAG load-balance verification failed: %v", err)
	}
	packetvalidationhelpers.ClearCapture(t, top, ate)
}
