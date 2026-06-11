package ipsec_base_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"

	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/helpers"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/netutil"
)

const (
	vlanID = 10

	// ATE OTG topology names.
	ate1LagName = "Lag1"
	ate2LagName = "Lag2"
	ate1DevName = "d1"
	ate2DevName = "d2"

	// VRF names.
	ateVRF    = "ATE_VRF"
	tunnelVRF = "TUNNEL_VRF"

	// Interface names.
	tunnelIfName   = "Tunnel1"
	loopbackIfName = "Loopback0"

	// IKE FQDN identities.
	dut1FQDN = "dut1.test.local"
	dut2FQDN = "dut2.test.local"

	// Loopback IPv6 addresses used as IPSec tunnel endpoints.
	dut1LoopbackIPv6  = "2003:db8:1::1"
	dut2LoopbackIPv6  = "2003:db8:2::1"
	loopbackPrefixLen = 128

	// Tunnel interface addresses in CIDR notation.
	dut1TunnelIPv4CIDR = "10.0.1.1/30"
	dut2TunnelIPv4CIDR = "10.0.1.2/30"
	dut1TunnelIPv6CIDR = "2001:db8:100:1::1/64"
	dut2TunnelIPv6CIDR = "2001:db8:100:1::2/64"

	// Tunnel next-hop addresses used in static routes (no prefix length).
	dut1TunnelIPv4NH = "10.0.1.1"
	dut2TunnelIPv4NH = "10.0.1.2"
	dut1TunnelIPv6NH = "2001:db8:100:1::1"
	dut2TunnelIPv6NH = "2001:db8:100:1::2"

	// Static route destination prefixes.
	ate1IPv4Prefix  = "192.0.2.0/30"
	ate2IPv4Prefix  = "203.0.113.0/30"
	ate1IPv6Prefix  = "2001:db8:1::0/126"
	ate2IPv6Prefix  = "2001:db8:2::0/126"
	dut1LoopbackPfx = "2003:db8:1::1/128"
	dut2LoopbackPfx = "2003:db8:2::1/128"

	// OTG MACsec peer name.
	macsecPeerName = "Peer A"

	// OTG flow names.
	flowIPv4 = "Flow-IPv4"
	flowIPv6 = "Flow-IPv6"

	// Traffic generation parameters.
	trafficPPS  = 100
	trafficPkts = 1000

	// Timeout durations.
	lagUpTimeout          = 2 * time.Minute
	trafficStartWaitTime  = 30 * time.Second
	counterSettleWaitTime = 30 * time.Second
)

type SizeWeightPair struct {
    Size   uint32
    Weight float32
}

var (
	// MKA keys.
	cak = "1234abcd1234abcd1234abcd1234abcd"
	ckn = "12345678123456781234567812345678"

	// ATE LAG configurations (RFC 5737 test networks).
	ate1LagConfig = attrs.Attributes{
		Desc:    "ATE LAG1 configuration",
		IPv4:    "192.0.2.2",
		IPv4Len: 30,
		IPv6:    "2001:db8:1::2",
		IPv6Len: 126,
		MAC:     "00:00:11:01:01:01",
		MTU:     1500,
	}
	ate2LagConfig = attrs.Attributes{
		Desc:    "ATE LAG2 configuration",
		IPv4:    "203.0.113.2",
		IPv4Len: 30,
		IPv6:    "2001:db8:2::2",
		IPv6Len: 126,
		MAC:     "00:00:12:02:02:02",
		MTU:     1500,
	}

	// DUT LAG3 configurations (RFC 5737 test networks) - ATE-facing interfaces
	// DUT1: VLAN 10 with MACsec
	dut1Lag3Config = attrs.Attributes{
		Desc:    "DUT LAG3 configuration",
		IPv4:    "192.0.2.1",
		IPv4Len: 30,
		IPv6:    "2001:db8:1::1",
		IPv6Len: 126,
		MAC:     "00:00:11:01:01:03",
		MTU:     9216,
		ID:      10,
	}
	// DUT2: No VLAN
	dut2Lag3Config = attrs.Attributes{
		Desc:    "DUT LAG3 configuration",
		IPv4:    "203.0.113.1",
		IPv4Len: 30,
		IPv6:    "2001:db8:2::1",
		IPv6Len: 126,
		MAC:     "00:00:12:02:02:03",
		MTU:     9216,
		ID:      0,
	}

	// DUT LAG configurations (IPv6-only for DUT-to-DUT links per RFC 5737 test networks)
	dut1Lag1Config = attrs.Attributes{
		Desc:    "DUT1 LAG1 configuration",
		IPv6:    "2001:db8:200:1::1",
		IPv6Len: 126,
		MAC:     "02:00:10:01:01:01",
		MTU:     9216,
	}
	dut1Lag2Config = attrs.Attributes{
		Desc:    "DUT1 LAG2 configuration",
		IPv6:    "2001:db8:200:2::1",
		IPv6Len: 126,
		MAC:     "02:00:10:02:01:01",
		MTU:     9216,
	}
	dut2Lag1Config = attrs.Attributes{
		Desc:    "DUT2 LAG1 configuration",
		IPv6:    "2001:db8:200:1::2",
		IPv6Len: 126,
		MAC:     "02:00:20:01:01:01",
		MTU:     9216,
	}
	dut2Lag2Config = attrs.Attributes{
		Desc:    "DUT2 LAG2 configuration",
		IPv6:    "2001:db8:200:2::2",
		IPv6Len: 126,
		MAC:     "02:00:20:02:01:01",
		MTU:     9216,
	}

	// ATE LAG port MAC addresses.
	ate1LagPortMac = "00:16:01:00:00:01"
	ate2LagPortMac = "00:17:01:00:00:01"

	sizeWeightProfile = []SizeWeightPair{
		{Size: 64, Weight: 20},
		{Size: 128, Weight: 10},
		{Size: 256, Weight: 10},
		{Size: 512, Weight: 10},
		{Size: 1024, Weight: 10},
		{Size: 1500, Weight: 10},
		{Size: 4500, Weight: 10},
		{Size: 9088, Weight: 10},
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// configDUTInterface configures the DUT interface with the given attributes and applies necessary deviations.
func configDUTInterface(t *testing.T, i *oc.Interface, a *attrs.Attributes, dut *ondatra.DUTDevice) {
	t.Helper()

	i.Description = ygot.String(a.Desc)
	// i.Mtu = ygot.Uint16(a.MTU)
	if deviations.InterfaceEnabled(dut) {
		i.Enabled = ygot.Bool(true)
	}

	// Keep subinterface 0 present with MTU enabled. Some devices require this
	// base subinterface to exist even when traffic is configured on a tagged subinterface.
	s0 := i.GetOrCreateSubinterface(0)
	ipv4 := s0.GetOrCreateIpv4()
	ipv6 := s0.GetOrCreateIpv6()
	ipv4.Mtu = ygot.Uint16(a.MTU)
	ipv6.Mtu = ygot.Uint32(uint32(a.MTU))
	if deviations.InterfaceEnabled(dut) {
		ipv4.Enabled = ygot.Bool(true)
		ipv6.Enabled = ygot.Bool(true)
	}

	s := i.GetOrCreateSubinterface(a.ID)
	s4 := s.GetOrCreateIpv4()
	s6 := s.GetOrCreateIpv6()
	s4.Mtu = ygot.Uint16(a.MTU)
	s6.Mtu = ygot.Uint32(uint32(a.MTU))
	if deviations.InterfaceEnabled(dut) {
		s4.Enabled = ygot.Bool(true)
		s6.Enabled = ygot.Bool(true)
	}
	if a.ID != 0 {
		s.GetOrCreateVlan().
			GetOrCreateMatch().
			GetOrCreateSingleTagged().
			SetVlanId(uint16(vlanID))
	}
	configureInterfaceAddress(dut, s, a)
}

// configureInterfaceAddress configures the IP addresses on the given subinterface based on the provided attributes.
func configureInterfaceAddress(dut *ondatra.DUTDevice, s *oc.Interface_Subinterface, a *attrs.Attributes) {
	s4 := s.GetOrCreateIpv4()
	if deviations.InterfaceEnabled(dut) {
		s4.Enabled = ygot.Bool(true)
	}
	if a.IPv4 != "" {
		a4 := s4.GetOrCreateAddress(a.IPv4)
		a4.PrefixLength = ygot.Uint8(a.IPv4Len)
	}
	s6 := s.GetOrCreateIpv6()
	if deviations.InterfaceEnabled(dut) {
		s6.Enabled = ygot.Bool(true)
	}
	if a.IPv6 != "" {
		s6.GetOrCreateAddress(a.IPv6).PrefixLength = ygot.Uint8(a.IPv6Len)
	}

	if a.IPv6Sec != "" {
		s62 := s.GetOrCreateIpv6()
		if deviations.InterfaceEnabled(dut) {
			s62.Enabled = ygot.Bool(true)
		}
		s62.GetOrCreateAddress(a.IPv6Sec).PrefixLength = ygot.Uint8(a.IPv6Len)
	}
}

// aggregateSubinterfaceName returns the interface name to use for CLI-based VRF assignment.
func aggregateSubinterfaceName(lagName string, subinterfaceID uint32) string {
	if subinterfaceID == 0 {
		return lagName
	}
	return fmt.Sprintf("%s.%d", lagName, subinterfaceID)
}

// assignAggregateToVRF assigns an aggregate/subinterface to the requested VRF using CLI.
// This keeps VRF assignment separate from interface modelling and avoids helper
// failures when vendor-specific network-instance inputs are incomplete.
func assignAggregateToVRF(t *testing.T, dut *ondatra.DUTDevice, lagName string, subinterfaceID uint32, vrfName string) {
	t.Helper()
	if vrfName == "" {
		return
	}

	intfName := aggregateSubinterfaceName(lagName, subinterfaceID)
	vrfConfig := fmt.Sprintf(`interface %s
   vrf %s
!`, intfName, vrfName)
	t.Logf("Applying CLI VRF assignment on %s into VRF %s", intfName, vrfName)
	helpers.GnmiCLIConfig(t, dut, vrfConfig)
}

// configureLAGInterface sets up the LAG aggregate interface, LACP, member ports, subinterfaces, and optional VRF assignment.
func configureLAGInterface(t *testing.T, dut *ondatra.DUTDevice, lagName string, ports []*ondatra.Port, a *attrs.Attributes, vrfName string) {
	t.Helper()
	d := gnmi.OC()

	// Configure aggregate interface first (some devices validate that the
	// interface exists before accepting LACP config), then LACP, then members.
	lacp := &oc.Lacp_Interface{Name: ygot.String(lagName)}
	lacp.LacpMode = oc.Lacp_LacpActivityType_ACTIVE

	agg := &oc.Interface{Name: ygot.String(lagName)}
	// Only set high-level interface fields here; avoid creating subinterfaces
	// or assigning IPs until the aggregate and members exist.
	agg.Description = ygot.String(a.Desc)
	// agg.Mtu = ygot.Uint16(a.MTU)
	if deviations.InterfaceEnabled(dut) {
		agg.Enabled = ygot.Bool(true)
	}
	// Ensure lag-type is present so member ports can reference this aggregate.
	agg.GetOrCreateAggregation().LagType = oc.IfAggregate_AggregationType_LACP
	agg.Type = oc.IETFInterfaces_InterfaceType_ieee8023adLag

	// First transaction: create the aggregate (without subinterfaces/IPs),
	// create the LACP entry and configure member ports.
	if deviations.AggregateAtomicUpdate(dut) {
		batch := &gnmi.SetBatch{}
		gnmi.BatchUpdate(batch, d.Interface(lagName).Config(), agg)
		gnmi.BatchUpdate(batch, d.Lacp().Interface(lagName).Config(), lacp)
		for _, p := range ports {
			i := &oc.Interface{Name: ygot.String(p.Name())}
			i.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd
			// i.Mtu = ygot.Uint16(a.MTU)
			if deviations.InterfaceEnabled(dut) {
				i.Enabled = ygot.Bool(true)
			}
			e := i.GetOrCreateEthernet()
			e.AggregateId = ygot.String(lagName)
			gnmi.BatchUpdate(batch, d.Interface(p.Name()).Config(), i)
		}
		batch.Set(t, dut)
	} else {
		gnmi.Update(t, dut, d.Interface(lagName).Config(), agg)
		gnmi.Update(t, dut, d.Lacp().Interface(lagName).Config(), lacp)
		for _, p := range ports {
			i := &oc.Interface{Name: ygot.String(p.Name())}
			i.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd
			// i.Mtu = ygot.Uint16(a.MTU)
			if deviations.InterfaceEnabled(dut) {
				i.Enabled = ygot.Bool(true)
			}
			e := i.GetOrCreateEthernet()
			e.AggregateId = ygot.String(lagName)
			gnmi.Update(t, dut, d.Interface(p.Name()).Config(), i)
		}
	}

	// Assign VRF before programming IP addresses. On EOS-like devices, moving an
	// interface into a VRF after IP assignment may clear/reject the address.
	// Use a.ID instead of hard-coded subinterface 0 so tagged ATE-facing
	// subinterfaces such as LagX.10 are assigned to the correct VRF.
	assignAggregateToVRF(t, dut, lagName, a.ID, vrfName)

	if deviations.AggregateAtomicUpdate(dut) {
		post := &gnmi.SetBatch{}
		full := &oc.Interface{Name: ygot.String(lagName)}
		full.GetOrCreateAggregation().LagType = agg.GetOrCreateAggregation().GetLagType()
		full.Type = agg.Type
		// Use helper to populate subinterface(s) and addresses.
		configDUTInterface(t, full, a, dut)
		gnmi.BatchUpdate(post, d.Interface(lagName).Config(), full)
		post.Set(t, dut)
	} else {
		full := &oc.Interface{Name: ygot.String(lagName)}
		full.GetOrCreateAggregation().LagType = agg.GetOrCreateAggregation().GetLagType()
		full.Type = agg.Type
		configDUTInterface(t, full, a, dut)
		gnmi.Update(t, dut, d.Interface(lagName).Config(), full)
	}
}

// createVRFs creates multiple VRFs with a single CLI push to reduce gNMI Set calls.
func createVRFs(t *testing.T, dut *ondatra.DUTDevice, vrfNames []string) {
	t.Helper()

	if len(vrfNames) == 0 {
		return
	}

	var b strings.Builder
	for _, vrfName := range vrfNames {
		if vrfName == "" {
			continue
		}
		b.WriteString(fmt.Sprintf(`vrf instance %s
!
ip routing vrf %s
!
ipv6 unicast-routing vrf %s
!
`, vrfName, vrfName, vrfName))
	}

	cli := b.String()
	if cli == "" {
		return
	}

	t.Logf("Applying CLI VRF creation/routing config for %d VRF(s): %v", len(vrfNames), vrfNames)
	helpers.GnmiCLIConfig(t, dut, cli)
}

// configureMACsec configures a MACsec security profile and applies it to the given interface
// via CLI. MACsec key management and profile binding have no standard OC equivalent.
func configureMACsec(t *testing.T, dut *ondatra.DUTDevice, intfName string) {
	t.Helper()
	macSecCLI := fmt.Sprintf(`mac security
   profile sampleProfile
      key 12345678123456781234567812345678 7 075E731F1A081B061343595F502B29272C6267714706140005070B0B07550C001C
      key 12345678123456781234567812345679 7 06575D72184F0B1A014640585805282820796166761205150750040A0C52560D06 fallback
      mka key-server priority 10
      mka session rekey-period 3600
      sci
   !
   interface %s
   mac security profile sampleProfile
!`, intfName)
	t.Logf("Applying CLI MACsec profile on interface %s", intfName)
	helpers.GnmiCLIConfig(t, dut, macSecCLI)
}

// IPSecTunnelCfg holds parameters for configuring an IPSec tunnel interface.
type IPSecTunnelCfg struct {
	TunnelName  string // e.g., "Tunnel1"
	Description string // tunnel interface description
	LocalFQDN   string // IKE local-id FQDN
	RemoteFQDN  string // IKE remote-id FQDN
	TunnelIPv4  string // CIDR, e.g., "10.0.1.1/30"
	TunnelIPv6  string // CIDR, e.g., "2001:db8:100:1::1/64"
	TunnelSrc   string // tunnel source address
	TunnelDst   string // tunnel destination address
	TunnelVRF   string // VRF the tunnel interface belongs to
}

// configureIPSecTunnel configures IPSec IKE/SA policies and a tunnel interface entirely
// via CLI. Arista does not accept OC configuration for tunnel interfaces (including IP
// address assignment), so all tunnel attributes are pushed through gNMI CLI.
func configureIPSecTunnel(t *testing.T, dut *ondatra.DUTDevice, cfg IPSecTunnelCfg) {
	t.Helper()

	// Build optional ip/ipv6 address lines for the tunnel interface.
	var addrLines string
	if cfg.TunnelIPv4 != "" {
		addrLines += fmt.Sprintf("   ip address %s\n", cfg.TunnelIPv4)
	}
	if cfg.TunnelIPv6 != "" {
		addrLines += fmt.Sprintf("   ipv6 address %s\n", cfg.TunnelIPv6)
	}

	tunnelCLI := fmt.Sprintf(`ip security
   ike policy IKE_POLICY_1
      dh-group 24
      local-id fqdn %s
      remote-id fqdn %s
   !
   sa policy SA_POLICY_1
      esp encryption aes256gcm128
      pfs dh-group 14
   !
   profile IPSEC_PROFILE_1
      ike-policy IKE_POLICY_1
      sa-policy SA_POLICY_1
      connection start
      shared-key 7 047F0E021A70
!
interface %s
   description %s
   mtu 9216
   vrf %s
%s   tunnel mode ipsec
   tunnel source %s
   tunnel destination %s
   tunnel path-mtu-discovery
   tunnel ipsec profile IPSEC_PROFILE_1
!`, cfg.LocalFQDN, cfg.RemoteFQDN, cfg.TunnelName, cfg.Description, cfg.TunnelVRF, addrLines, cfg.TunnelSrc, cfg.TunnelDst)
	t.Logf("Applying CLI IPSec tunnel config on %s in VRF %s (src=%s dst=%s)", cfg.TunnelName, cfg.TunnelVRF, cfg.TunnelSrc, cfg.TunnelDst)
	helpers.GnmiCLIConfig(t, dut, tunnelCLI)
}

// staticRoute represents a single static route entry.
type staticRoute struct {
	Prefix    string // destination prefix in CIDR notation
	NextHop   string // next-hop IP address
	VRF       string // source VRF (empty for the default VRF)
	EgressVRF string // egress VRF for cross-VRF leaking (empty if not used)
}

// configureStaticRoutes configures static routes using OpenConfig for named-VRF routes
// without egress-vrf, and CLI for routes with egress-vrf or in the default VRF.
// OC support for next-network-instance is limited on most devices.
// Default-VRF routes must use plain CLI (no vrf qualifier) on Arista.
func configureStaticRoutes(t *testing.T, dut *ondatra.DUTDevice, routes []staticRoute) {
	t.Helper()

	// Group named-VRF routes without egress-vrf for OC configuration.
	ocRoutesByVRF := make(map[string][]staticRoute)
	for _, r := range routes {
		if r.EgressVRF == "" && r.VRF != "" {
			ocRoutesByVRF[r.VRF] = append(ocRoutesByVRF[r.VRF], r)
		}
	}

	// Configure named-VRF plain next-hop routes via OpenConfig.
	for vrfName, vrfRoutes := range ocRoutesByVRF {
		proto := &oc.NetworkInstance_Protocol{
			Identifier: oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			Name:       ygot.String(deviations.StaticProtocolName(dut)),
		}
		for _, r := range vrfRoutes {
			sr := proto.GetOrCreateStatic(r.Prefix)
			sr.Prefix = ygot.String(r.Prefix)
			nh := sr.GetOrCreateNextHop("0")
			nh.Index = ygot.String("0")
			nh.NextHop = oc.UnionString(r.NextHop)
		}
		sp := gnmi.OC().NetworkInstance(vrfName).Protocol(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut))
		gnmi.Update(t, dut, sp.Config(), proto)
	}

	// Configure via CLI: routes with egress-vrf, or routes in the default VRF.
	var cliRoutes []string
	for _, r := range routes {
		if r.EgressVRF == "" && r.VRF != "" {
			continue // already handled via OC above
		}
		ipType := "ip"
		for _, ch := range r.Prefix {
			if ch == ':' {
				ipType = "ipv6"
				break
			}
		}
		var cli string
		switch {
		case r.EgressVRF != "" && r.VRF != "":
			cli = fmt.Sprintf("%s route vrf %s %s egress-vrf %s %s",
				ipType, r.VRF, r.Prefix, r.EgressVRF, r.NextHop)
		case r.EgressVRF == "" && r.VRF == "":
			// Default VRF, plain next-hop — no vrf qualifier.
			cli = fmt.Sprintf("%s route %s %s", ipType, r.Prefix, r.NextHop)
		default:
			// EgressVRF set but VRF is empty (edge case: egress from default VRF).
			cli = fmt.Sprintf("%s route %s egress-vrf %s %s",
				ipType, r.Prefix, r.EgressVRF, r.NextHop)
		}
		t.Logf("CLI static route: %s", cli)
		cliRoutes = append(cliRoutes, cli)
	}

	if len(cliRoutes) > 0 {
		cliSumm := strings.Join(cliRoutes, "\n")
		t.Logf("Applying %d CLI static route command(s) in one gNMI Set", len(cliRoutes))
		helpers.GnmiCLIConfig(t, dut, cliSumm)
	}
}

func configureDUT(t *testing.T, dut *ondatra.DUTDevice,
	portGroups [][]*ondatra.Port,
	portAttrs []attrs.Attributes,
	vrfName string) {

	t.Helper()

	if len(portGroups) != len(portAttrs) {
		t.Fatalf("mismatched portGroups and portAttrs lengths")
	}

	// VRF should already be created by createVRF() before calling this
	// Just configure the interfaces without VRF creation

	for i := range portGroups {
		// Generate a unique aggregate ID per DUT per LAG.
		lag := netutil.NextAggregateInterface(t, dut)
		configureLAGInterface(t, dut, lag, portGroups[i], &portAttrs[i], vrfName)
	}
}
func configureLoopback(t *testing.T, dut *ondatra.DUTDevice, lbName, ip string, prefixLen uint8, isIPv6 bool) {
	t.Helper()

	i := &oc.Interface{}
	i.Name = ygot.String(lbName)
	i.Type = oc.IETFInterfaces_InterfaceType_softwareLoopback

	if deviations.InterfaceEnabled(dut) {
		i.Enabled = ygot.Bool(true)
	}

	s0 := i.GetOrCreateSubinterface(0)

	if isIPv6 {
		ipv6 := s0.GetOrCreateIpv6()
		if deviations.InterfaceEnabled(dut) {
			ipv6.Enabled = ygot.Bool(true)
		}
		addr := ipv6.GetOrCreateAddress(ip)
		addr.PrefixLength = ygot.Uint8(prefixLen)
	} else {
		ipv4 := s0.GetOrCreateIpv4()
		if deviations.InterfaceEnabled(dut) {
			ipv4.Enabled = ygot.Bool(true)
		}
		addr := ipv4.GetOrCreateAddress(ip)
		addr.PrefixLength = ygot.Uint8(prefixLen)
	}

	gnmi.Replace(t, dut,
		gnmi.OC().
			Interface(lbName).
			Config(),
		i)
}

func configureATE(t *testing.T) gosnappi.Config {
	t.Helper()

	top := gosnappi.NewConfig()

	// Port mapping expected from testbed:
	// - ATE port1 <-> DUT1 port5 (with MACSec on DUT side)
	// - ATE port2 <-> DUT2 port5
	p1 := top.Ports().Add().SetName("port1")
	p2 := top.Ports().Add().SetName("port2")

	// add lags
	l1 := top.Lags().Add().SetName(ate1LagName)

	lagPort1 := l1.Ports().Add().SetPortName(p1.Name())
	lagPort1.Lacp().
		SetActorActivity("active").
		SetActorPortNumber(1)
	lagPort1.Ethernet().
		SetName("lag1Eth").
		SetMac(ate1LagPortMac).
		SetMtu(uint32(ate1LagConfig.MTU))
	l1.Protocol().Lacp().
		SetActorSystemId("00:00:00:00:00:01").
		SetActorSystemPriority(0).
		SetActorKey(1)

	// -- Macsec Config
	macsec1 := lagPort1.Macsec()
	secy1 := macsec1.SecureEntity().SetName(macsecPeerName)
	secy1Encapsulation := secy1.DataPlane().Encapsulation()
	secy1Encapsulation.CryptoEngine().EncryptDecrypt().HardwareAcceleration().InlineCrypto()
	// -- MKA Config
	mka := secy1.KeyGenerationProtocol().Mka().SetName("PeerA-Mka")
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
	secureChannel := mka.Tx().SecureChannels().Add()
	secureChannel.SetName("SecureChannel1").
		SetSystemId(lagPort1.Ethernet().Mac())

	// add devices
	d1 := top.Devices().Add().SetName(ate1DevName)
	// add protocol stacks for device d1
	d1Eth1 := d1.Ethernets().
		Add().
		SetName("d1Eth").
		SetMac(ate1LagConfig.MAC)
	d1Eth1.Connection().SetLagName(l1.Name())

	d1Eth1.Vlans().Add().SetName("d1EthVlan").SetId(vlanID)

	d1ipv4 := d1Eth1.Ipv4Addresses().
		Add().
		SetName("p1d1ipv4").
		SetAddress(ate1LagConfig.IPv4).
		SetGateway(dut1Lag3Config.IPv4).
		SetPrefix(uint32(ate1LagConfig.IPv4Len))

	d1ipv6 := d1Eth1.Ipv6Addresses().
		Add().
		SetName("p1d1ipv6").
		SetAddress(ate1LagConfig.IPv6).
		SetGateway(dut1Lag3Config.IPv6).
		SetPrefix(uint32(ate1LagConfig.IPv6Len))

	l2 := top.Lags().Add().SetName(ate2LagName)
	lagPort2 := l2.Ports().Add().SetPortName(p2.Name())
	lagPort2.Lacp().
		SetActorActivity("active").
		SetActorPortNumber(1)
	lagPort2.Ethernet().
		SetName("lag2Eth").
		SetMac(ate2LagPortMac).
		SetMtu(uint32(ate2LagConfig.MTU))
	l2.Protocol().Lacp().
		SetActorSystemId("00:00:00:00:00:02").
		SetActorSystemPriority(0).
		SetActorKey(1)

	d2 := top.Devices().Add().SetName(ate2DevName)
	d2Eth1 := d2.Ethernets().
		Add().
		SetName("d2Eth").
		SetMac(ate2LagConfig.MAC)
	d2Eth1.Connection().SetLagName(l2.Name())

	d2ipv4 := d2Eth1.Ipv4Addresses().
		Add().
		SetName("p2d2ipv4").
		SetAddress(ate2LagConfig.IPv4).
		SetGateway(dut2Lag3Config.IPv4).
		SetPrefix(uint32(ate2LagConfig.IPv4Len))


	d2ipv6 := d2Eth1.Ipv6Addresses().
		Add().
		SetName("p2d2ipv6").
		SetAddress(ate2LagConfig.IPv6).
		SetGateway(dut2Lag3Config.IPv6).
		SetPrefix(uint32(ate2LagConfig.IPv6Len))


	flowV4 := top.Flows().Add().SetName(flowIPv4)
	flowV4.TxRx().Device().SetTxNames([]string{d2ipv4.Name()}).SetRxNames([]string{d1ipv4.Name()})

	for _, sizeWeight := range sizeWeightProfile {
		flowV4.Size().WeightPairs().Custom().Add().SetSize(sizeWeight.Size).SetWeight(sizeWeight.Weight)
	}
	flowV4.Rate().SetPps(trafficPPS)
	flowV4.Duration().FixedPackets().SetPackets(trafficPkts)
	flowV4.Metrics().SetEnable(true)

	e2 := flowV4.Packet().Add().Ethernet()
	e2.Src().SetValue(ate2LagConfig.MAC)

	v4 := flowV4.Packet().Add().Ipv4()
	v4.Src().SetValue(ate2LagConfig.IPv4)
	v4.Dst().SetValue(ate1LagConfig.IPv4)

	// IPv6 Flow from port2 to port1.
	flowV6 := top.Flows().Add().SetName(flowIPv6)
	flowV6.TxRx().Device().SetTxNames([]string{d2ipv6.Name()}).SetRxNames([]string{d1ipv6.Name()})

	for _, sizeWeight := range sizeWeightProfile {
		flowV6.Size().WeightPairs().Custom().Add().SetSize(sizeWeight.Size).SetWeight(sizeWeight.Weight)
	}
	flowV6.Rate().SetPps(trafficPPS)
	flowV6.Duration().FixedPackets().SetPackets(trafficPkts)
	flowV6.Metrics().SetEnable(true)

	e4 := flowV6.Packet().Add().Ethernet()
	e4.Src().SetValue(ate2LagConfig.MAC)

	v6 := flowV6.Packet().Add().Ipv6()
	v6.Src().SetValue(ate2LagConfig.IPv6)
	v6.Dst().SetValue(ate1LagConfig.IPv6)

	return top
}

func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, flowName string, testResults bool) {
	t.Helper()

	recvMetric := gnmi.Get(t, ate.OTG(), gnmi.OTG().Flow(flowName).State())
	framesTx := recvMetric.GetCounters().GetOutPkts()
	framesRx := recvMetric.GetCounters().GetInPkts()

	if framesTx == 0 {
		t.Errorf("%s: no traffic transmitted, FramesTx: got %d, want > 0", flowName, framesTx)
		return
	}

	if testResults {
		// Expect frames to be received
		if framesRx != framesTx {
			t.Errorf("%s: frame loss detected: FramesTx: %d, FramesRx: %d, want FramesRx == FramesTx", flowName, framesTx, framesRx)
		}
	} else {
		// Expect no frames to be received
		if framesRx != 0 {
			t.Errorf("%s: unexpected frames received: FramesTx: %d, FramesRx: %d, want FramesRx == 0", flowName, framesTx, framesRx)
		}
	}

	t.Logf("%s: FramesTx: %d, FramesRx: %d", flowName, framesTx, framesRx)
}

func waitForOTGLAGUP(t *testing.T, ate *ondatra.ATEDevice, lagName string, wantMembersUp uint64, timeout time.Duration) {
	t.Helper()

	otg := ate.OTG()

	t.Logf("Waiting for OTG LAG %s to be UP with %d member(s)", lagName, wantMembersUp)

	watch := gnmi.Watch(
		t,
		otg,
		gnmi.OTG().Lag(lagName).State(),
		timeout,
		func(val *ygnmi.Value[*otgtelemetry.Lag]) bool {
			lag, ok := val.Val()
			if !ok || lag == nil {
				return false
			}

			oper := lag.GetOperStatus()
			membersUp := lag.GetCounters().GetMemberPortsUp()

			if oper == otgtelemetry.Lag_OperStatus_UP && membersUp == wantMembersUp {
				t.Logf("OTG LAG %s is UP with %d member(s) up", lagName, membersUp)
				return true
			}

			t.Logf("Waiting OTG LAG %s: oper-status=%v member-ports-up=%d (want oper-status=UP, member-ports-up=%d)",
				lagName, oper, membersUp, wantMembersUp)

			return false
		},
	)

	if _, ok := watch.Await(t); !ok {
		finalOper := gnmi.Get(t, otg, gnmi.OTG().Lag(lagName).OperStatus().State())
		finalMembers := gnmi.Get(t, otg, gnmi.OTG().Lag(lagName).Counters().MemberPortsUp().State())

		t.Fatalf("OTG LAG %s did not become ready within %v: final oper-status=%v member-ports-up=%d (want oper-status=UP, member-ports-up=%d)",
			lagName, timeout, finalOper, finalMembers, wantMembersUp)
	}
}

func waitForOTGMACSecUp(t *testing.T, ate *ondatra.ATEDevice, ifName string, timeout time.Duration) {
	t.Helper()

	otg := ate.OTG()

	t.Logf("Waiting for OTG MACsec session on %s to be UP", ifName)

	watch := gnmi.Watch(
		t,
		otg,
		gnmi.OTG().Macsec().Interface(ifName).SessionState().State(),
		timeout,
		func(val *ygnmi.Value[otgtelemetry.E_Interface_SessionState]) bool {
			state, ok := val.Val()
			if !ok {
				t.Logf("Waiting MACsec session on %s: current state=%v", ifName, state)
				return false
			}
			return true
		},
	)

	if _, ok := watch.Await(t); !ok {
		finalState := gnmi.Get(t, otg, gnmi.OTG().Macsec().Interface(ifName).SessionState().State())
		t.Fatalf("MACsec session on %s did not come UP within %v, final state=%v",
			ifName, timeout, finalState)
	}
}

// enableCapture enables packet capture on specified OTG ports by adding to topology
func enableCapture(t *testing.T, topo gosnappi.Config, otgPortNames []string) gosnappi.Config {
	t.Helper()
	cap := topo.Captures().Add().SetName("capture").SetPortNames(otgPortNames).SetFormat(gosnappi.CaptureFormat.PCAP)
	filter := cap.Filters().Add()
	filter.Ethernet().EtherType().SetValue("0x88E5") // Capture only MACsec-encrypted packets (EtherType 0x88E5)
	return topo
}

// startCapture starts packet capture on OTG ports using control state
func startCapture(t *testing.T, ate *ondatra.ATEDevice) {
	t.Helper()
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	otg.SetControlState(t, cs)
}

// stopCapture stops packet capture on OTG ports using control state
func stopCapture(t *testing.T, ate *ondatra.ATEDevice) {
	t.Helper()
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.STOP)
	otg.SetControlState(t, cs)
}

// verifyCapturedMACSecPackets validates captured packets contain MACsec encryption.
// MACsec-encrypted packets are identified by the MACsec EtherType (0x88E5).
// This function should be called after GetCapture() retrieves the packet bytes.
func verifyCapturedMACSecPackets(t *testing.T, packetBytes []byte, portName string) {
	t.Helper()

	t.Logf("=== MACsec PACKET CAPTURE VALIDATION START for port %s ===", portName)

	if len(packetBytes) == 0 {
		t.Errorf("MACsec packet capture on port %s: no packets captured, want at least 1 MACsec-encrypted packet", portName)
		return
	}

	// Write capture to temporary pcap file for analysis
	f, err := os.CreateTemp("", ".pcap")
	if err != nil {
		t.Fatalf("Could not create temporary pcap file: %v", err)
	}
	if _, err := f.Write(packetBytes); err != nil {
		f.Close()
		t.Fatalf("Could not write packetBytes to pcap file: %v", err)
	}
	f.Close()
	// defer os.Remove(f.Name())

	handle, err := pcap.OpenOffline(f.Name())
	if err != nil {
		t.Fatalf("Could not open pcap file: %v", err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	macsecPacketCount := 0
	totalPackets := 0
	const macsecEtherType = 0x88E5

	for packet := range packetSource.Packets() {
		totalPackets++

		// Get the Ethernet layer
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}

		eth := ethLayer.(*layers.Ethernet)
		if eth.EthernetType == layers.EthernetType(macsecEtherType) {
			macsecPacketCount++
			// t.Logf("Captured MACsec packet on port %s: packet length=%d bytes, EtherType=0x%04X",
			// 	portName, len(packet.Data()), uint16(eth.EthernetType))
		}
	}

	t.Logf("=== MACsec PACKET CAPTURE VALIDATION SUMMARY ===")
	t.Logf("Total packets captured: %d", totalPackets)
	t.Logf("MACsec-encrypted packets found: %d", macsecPacketCount)

	if totalPackets == 0 {
		t.Errorf("MACsec packet capture on port %s: no packets captured, want at least 1 MACsec-encrypted packet", portName)
	} else if macsecPacketCount == 0 {
		t.Errorf("MACsec packet capture on port %s: captured %d total packets but no MACsec-encrypted packets (EtherType 0x%04X) detected",
			portName, totalPackets, macsecEtherType)
	} else {
		t.Logf("MACsec packet capture verification on port %s: successfully captured %d MACsec-encrypted packets out of %d total packets",
			portName, macsecPacketCount, totalPackets)
	}
}

func TestIPSecWithMACSecOverAggregatedLinks(t *testing.T) {
	dut1 := ondatra.DUT(t, "dut1")
	dut2 := ondatra.DUT(t, "dut2")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	// Step: Configure DUT customer-facing interfaces, VLANs, VRFs, MACSec, and DUT-DUT transport aggregates.
	// Create two LAGs (each with 2 member ports) and apply to both DUTs.
	// Use per-DUT aggregate IDs from netutil to ensure device-valid agg names.
	// ATE still uses logical names ate1LagName/ate2LagName.

	// // Use Ondatra Port objects for each DUT.
	dut1p1 := dut1.Port(t, "port1")
	dut1p2 := dut1.Port(t, "port2")
	dut1p3 := dut1.Port(t, "port3")
	dut1p4 := dut1.Port(t, "port4")
	dut1p5 := dut1.Port(t, "port5") // port5 on each DUT connects to ATE and has MACSec

	dut2p1 := dut2.Port(t, "port1")
	dut2p2 := dut2.Port(t, "port2")
	dut2p3 := dut2.Port(t, "port3")
	dut2p4 := dut2.Port(t, "port4")
	dut2p5 := dut2.Port(t, "port5") // port5 on each DUT connects to ATE

	dut1Ports := [][]*ondatra.Port{
		{dut1p1, dut1p2},
		{dut1p3, dut1p4},
	}
	dut2Ports := [][]*ondatra.Port{
		{dut2p1, dut2p2},
		{dut2p3, dut2p4},
	}

	// DUT-specific attributes: LAGs on each DUT should use DUT attributes
	dut1PortAttrs := []attrs.Attributes{dut1Lag1Config, dut1Lag2Config}
	dut2PortAttrs := []attrs.Attributes{dut2Lag1Config, dut2Lag2Config}

	// Create all VRFs upfront before configuring interfaces.
	createVRFs(t, dut1, []string{ateVRF, tunnelVRF})
	createVRFs(t, dut2, []string{ateVRF, tunnelVRF})

	// Configure DUTs: generate one aggregate per port group inside configureDUT.
	// dut1Ports and dut2Ports are the LAGs in TUNNEL_VRF for DUT-to-DUT communication.
	configureDUT(t, dut1, dut1Ports, dut1PortAttrs, "")
	configureDUT(t, dut1, [][]*ondatra.Port{{dut1p5}}, []attrs.Attributes{dut1Lag3Config}, ateVRF)

	configureDUT(t, dut2, dut2Ports, dut2PortAttrs, "")
	configureDUT(t, dut2, [][]*ondatra.Port{{dut2p5}}, []attrs.Attributes{dut2Lag3Config}, ateVRF)

	// Configure loopback interfaces used as IPSec tunnel endpoints.
	configureLoopback(t, dut1, loopbackIfName, dut1LoopbackIPv6, loopbackPrefixLen, true)
	configureLoopback(t, dut2, loopbackIfName, dut2LoopbackIPv6, loopbackPrefixLen, true)

	configureMACsec(t, dut1, dut1p5.Name())

	configureIPSecTunnel(t, dut1, IPSecTunnelCfg{
		TunnelName:  tunnelIfName,
		Description: "IPsec Tunnel Pair 1 to DUT2",
		LocalFQDN:   dut1FQDN,
		RemoteFQDN:  dut2FQDN,
		TunnelIPv4:  dut1TunnelIPv4CIDR,
		TunnelIPv6:  dut1TunnelIPv6CIDR,
		TunnelSrc:   dut1LoopbackIPv6,
		TunnelDst:   dut2LoopbackIPv6,
		TunnelVRF:   tunnelVRF,
	})

	configureIPSecTunnel(t, dut2, IPSecTunnelCfg{
		TunnelName:  tunnelIfName,
		Description: "IPsec Tunnel Pair 1 to DUT1",
		LocalFQDN:   dut2FQDN,
		RemoteFQDN:  dut1FQDN,
		TunnelIPv4:  dut2TunnelIPv4CIDR,
		TunnelIPv6:  dut2TunnelIPv6CIDR,
		TunnelSrc:   dut2LoopbackIPv6,
		TunnelDst:   dut1LoopbackIPv6,
		TunnelVRF:   tunnelVRF,
	})

	configureStaticRoutes(t, dut1, []staticRoute{
		{Prefix: ate1IPv4Prefix, NextHop: ate1LagConfig.IPv4, VRF: tunnelVRF, EgressVRF: ateVRF},
		{Prefix: ate2IPv4Prefix, NextHop: dut2TunnelIPv4NH, VRF: ateVRF, EgressVRF: tunnelVRF},
		{Prefix: ate1IPv6Prefix, NextHop: ate1LagConfig.IPv6, VRF: tunnelVRF, EgressVRF: ateVRF},
		{Prefix: ate2IPv6Prefix, NextHop: dut2TunnelIPv6NH, VRF: ateVRF, EgressVRF: tunnelVRF},
		{Prefix: dut2LoopbackPfx, NextHop: dut2Lag2Config.IPv6},
		{Prefix: dut2LoopbackPfx, NextHop: dut2Lag1Config.IPv6},
	})

	configureStaticRoutes(t, dut2, []staticRoute{
		{Prefix: ate2IPv4Prefix, NextHop: ate2LagConfig.IPv4, VRF: tunnelVRF, EgressVRF: ateVRF},
		{Prefix: ate1IPv4Prefix, NextHop: dut1TunnelIPv4NH, VRF: ateVRF, EgressVRF: tunnelVRF},
		{Prefix: ate2IPv6Prefix, NextHop: ate2LagConfig.IPv6, VRF: tunnelVRF, EgressVRF: ateVRF},
		{Prefix: ate1IPv6Prefix, NextHop: dut1TunnelIPv6NH, VRF: ateVRF, EgressVRF: tunnelVRF},
		{Prefix: dut1LoopbackPfx, NextHop: dut1Lag2Config.IPv6},
		{Prefix: dut1LoopbackPfx, NextHop: dut1Lag1Config.IPv6},
	})

	// Step: Configure ATE topology and flows.
	top := configureATE(t)
	// Enable capture should be part of setconfig
	top = enableCapture(t, top, []string{"port1"})
	otg.PushConfig(t, top)
	otg.StartProtocols(t)

	waitForOTGMACSecUp(t, ate, macsecPeerName, lagUpTimeout)
	waitForOTGLAGUP(t, ate, ate1LagName, 1, lagUpTimeout)
	waitForOTGLAGUP(t, ate, ate2LagName, 1, lagUpTimeout)

	otgutils.WaitForARP(t, ate.OTG(), top, "IPv4")
	otgutils.WaitForARP(t, ate.OTG(), top, "IPv6")

	// StartCapture should be called before starting the traffic
	startCapture(t, ate)

	// Step: Verify base operational readiness before traffic.
	t.Run("BaselineTelemetry", func(t *testing.T) {
		otg.StartTraffic(t)

		// Wait for traffic to flow and stabilize.
		time.Sleep(trafficStartWaitTime)

		otg.StopTraffic(t)

		// StopCapture should be called after stopping the traffic.
		stopCapture(t, ate)

		// Wait for counters to stabilize after traffic stops.
		time.Sleep(counterSettleWaitTime)
		otgutils.LogFlowMetrics(t, otg, top)

		verifyTraffic(t, ate, flowIPv4, true)
		verifyTraffic(t, ate, flowIPv6, true)

		// GetCapture should be called after stopping the traffic and before validation
		captureReq := gosnappi.NewCaptureRequest()
		captureReq.SetPortName("port1")
		packetBytes := otg.GetCapture(t, captureReq)

		// Validate captured packets contain MACsec encryption
		verifyCapturedMACSecPackets(t, packetBytes, "port1")

	})
}