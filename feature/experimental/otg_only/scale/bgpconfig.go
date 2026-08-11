package scale

import (
	"net"
	"strconv"
	"testing"

	"github.com/open-traffic-generator/snappi/gosnappi"
)

// ---------------------------------------------------------------------------
// OTG config building
//
// One device and one flow at a time. How many of each, and with what addresses,
// is the test's decision; these functions only turn one filled-in spec into
// gosnappi calls. AddBGPv4Device and AddBGPv6Device are deliberately separate
// rather than abstracted behind an address-family interface: gosnappi gives
// BgpV4Peer and BgpV6Peer no common type, and two explicit functions read
// better at the call site than one generic one.
// ---------------------------------------------------------------------------

// DeviceSpec is one BGP device: an ethernet port connection, its VLAN tags, one
// IP address, one BGP peer and the route range that peer advertises.
type DeviceSpec struct {
	// PortName is the OTG port to attach to, e.g. "port1"; SidePrefix names the
	// side for generated object names, e.g. "p1" -> p1dev3, p1peer3.
	PortName, SidePrefix string
	// Index is the 1-based session index.
	Index uint32

	MAC    string
	EthMTU uint32

	// DevIP is this device's address, GwIP its gateway, which is also its BGP
	// peer address. IPPrefix is the interface prefix length.
	DevIP, GwIP net.IP
	IPPrefix    uint32

	// RouterID is the BGP router ID. Empty means "use DevIP", which is what the
	// v4 test does; the v6 test must supply one because OTG validates router_id
	// as an IPv4 address.
	RouterID string

	// AS is the peer's AS number. Every peer is iBGP in one AS.
	AS uint32

	// Routes is how many prefixes this peer advertises, starting at RouteStart
	// with prefix length RoutePrefix. 0 advertises nothing.
	Routes         uint32
	RouteStart     string
	RoutePrefix    uint32
	RouteRangeName string

	// VLAN adds a per-session dot1q tag; QinQ adds an outer tag on top of it.
	VLAN, QinQ bool

	// ListenPort and NeighborPort are the non-default BGP TCP ports as given for
	// the port1 side; they are mirrored automatically for the other side. Both
	// zero leaves the default 179.
	ListenPort, NeighborPort uint32
}

// AddBGPv4Device adds one device (ethernet + vlans + ipv4 + BGPv4 peer + route
// range) to the config and returns the BGP peer name.
func AddBGPv4Device(t *testing.T, config gosnappi.Config, s DeviceSpec) string {
	t.Helper()
	devName := s.SidePrefix + "dev" + strconv.Itoa(int(s.Index))
	ipName := devName + ".ipv4"
	peerName := s.SidePrefix + "peer" + strconv.Itoa(int(s.Index))

	dev, eth := addDeviceEthernet(config, devName, s)

	eth.Ipv4Addresses().Add().SetName(ipName).
		SetAddress(s.DevIP.String()).
		SetGateway(s.GwIP.String()).
		SetPrefix(s.IPPrefix)

	bgp := dev.Bgp().SetRouterId(s.routerID())
	bgpIf := bgp.Ipv4Interfaces().Add().SetIpv4Name(ipName)
	peer := bgpIf.Peers().Add().
		SetAsNumber(s.AS).
		SetAsType(gosnappi.BgpV4PeerAsType.IBGP).
		SetPeerAddress(s.GwIP.String()).
		SetName(peerName)
	peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

	if lp, np, ok := s.tcpPorts(); ok {
		adv := peer.Advanced()
		adv.SetListenPort(lp)
		adv.SetNeighborPort(np)
	}

	if s.Routes > 0 {
		rr := peer.V4Routes().Add().
			SetName(s.RouteRangeName).
			SetNextHopIpv4Address(s.DevIP.String()).
			SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
			SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
		rr.Addresses().Add().
			SetAddress(s.RouteStart).
			SetPrefix(s.RoutePrefix).
			SetCount(s.Routes).
			SetStep(1)
	}
	return peerName
}

// AddBGPv6Device adds one device (ethernet + vlans + ipv6 + BGPv6 peer + route
// range) to the config and returns the BGP peer name.
func AddBGPv6Device(t *testing.T, config gosnappi.Config, s DeviceSpec) string {
	t.Helper()
	devName := s.SidePrefix + "dev" + strconv.Itoa(int(s.Index))
	ipName := devName + ".ipv6"
	peerName := s.SidePrefix + "peer" + strconv.Itoa(int(s.Index))

	dev, eth := addDeviceEthernet(config, devName, s)

	eth.Ipv6Addresses().Add().SetName(ipName).
		SetAddress(s.DevIP.String()).
		SetGateway(s.GwIP.String()).
		SetPrefix(s.IPPrefix)

	bgp := dev.Bgp().SetRouterId(s.routerID())
	bgpIf := bgp.Ipv6Interfaces().Add().SetIpv6Name(ipName)
	peer := bgpIf.Peers().Add().
		SetAsNumber(s.AS).
		SetAsType(gosnappi.BgpV6PeerAsType.IBGP).
		SetPeerAddress(s.GwIP.String()).
		SetName(peerName)
	peer.LearnedInformationFilter().SetUnicastIpv6Prefix(true)

	if lp, np, ok := s.tcpPorts(); ok {
		adv := peer.Advanced()
		adv.SetListenPort(lp)
		adv.SetNeighborPort(np)
	}

	if s.Routes > 0 {
		rr := peer.V6Routes().Add().
			SetName(s.RouteRangeName).
			SetNextHopIpv6Address(s.DevIP.String()).
			SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6).
			SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL)
		rr.Addresses().Add().
			SetAddress(s.RouteStart).
			SetPrefix(s.RoutePrefix).
			SetCount(s.Routes).
			SetStep(1)
	}
	return peerName
}

// addDeviceEthernet adds the address-family-independent part of a device: the
// device itself, its ethernet, and its VLAN tags. The tag pair depends only on
// the session index, so the paired port1 and port2 devices land in the same
// broadcast domain. The outer (QinQ) tag is added first, the inner dot1q second.
func addDeviceEthernet(config gosnappi.Config, devName string, s DeviceSpec) (gosnappi.Device, gosnappi.DeviceEthernet) {
	dev := config.Devices().Add().SetName(devName)
	eth := dev.Ethernets().Add().SetName(devName + ".eth").SetMac(s.MAC).SetMtu(s.EthMTU)
	eth.Connection().SetPortName(s.PortName)

	if s.VLAN {
		inner, outer := VLANIDs(s.Index)
		if s.QinQ {
			eth.Vlans().Add().SetName(devName + ".qinq").SetId(outer)
		}
		eth.Vlans().Add().SetName(devName + ".vlan").SetId(inner)
	}
	return dev, eth
}

// routerID is DevIP unless the spec names one explicitly.
func (s DeviceSpec) routerID() string {
	if s.RouterID != "" {
		return s.RouterID
	}
	return s.DevIP.String()
}

// tcpPorts returns the listen/neighbor port pair for this side, mirrored so
// that what port1 listens on is what port2 connects to. ok is false when the
// default 179 should be left alone.
func (s DeviceSpec) tcpPorts() (listen, neighbor uint32, ok bool) {
	if s.ListenPort == 0 || s.NeighborPort == 0 {
		return 0, 0, false
	}
	if s.SidePrefix != "p1" {
		return s.NeighborPort, s.ListenPort, true
	}
	return s.ListenPort, s.NeighborPort, true
}

// FlowSpec is one data-plane flow between a pair of advertised route ranges.
type FlowSpec struct {
	Name string
	// TxNames and RxNames are the route range names the flow runs between.
	TxNames, RxNames []string
	// Index is the session index, which selects the VLAN tag pair.
	Index uint32

	SrcMAC, DstMAC string
	// SrcStart and DstStart are the first addresses of the two route blocks, and
	// Count is how many addresses each one steps through.
	SrcStart, DstStart string
	Count              uint32

	Packets, Pps, Size uint32
	VLAN, QinQ         bool
}

// AddIPv4Flow adds a fixed-packet IPv4 flow over a pair of route ranges.
func AddIPv4Flow(config gosnappi.Config, s FlowSpec) {
	flow := addFlowHeaders(config, s)
	v4 := flow.Packet().Add().Ipv4()
	v4.Src().Increment().SetStart(s.SrcStart).SetCount(s.Count)
	v4.Dst().Increment().SetStart(s.DstStart).SetCount(s.Count)
}

// AddIPv6Flow adds a fixed-packet IPv6 flow over a pair of route ranges.
func AddIPv6Flow(config gosnappi.Config, s FlowSpec) {
	flow := addFlowHeaders(config, s)
	v6 := flow.Packet().Add().Ipv6()
	v6.Src().Increment().SetStart(s.SrcStart).SetCount(s.Count)
	v6.Dst().Increment().SetStart(s.DstStart).SetCount(s.Count)
}

// addFlowHeaders adds everything below the IP header: the flow itself, its
// endpoints, rate and size, the ethernet header and the VLAN tags. Tagged
// devices need the same tags on the transmitted frames, outer tag first.
func addFlowHeaders(config gosnappi.Config, s FlowSpec) gosnappi.Flow {
	flow := config.Flows().Add().SetName(s.Name)
	flow.Metrics().SetEnable(true)
	flow.TxRx().Device().SetTxNames(s.TxNames).SetRxNames(s.RxNames)
	flow.Duration().FixedPackets().SetPackets(s.Packets)
	flow.Rate().SetPps(uint64(s.Pps))
	flow.Size().SetFixed(s.Size)

	// Dst MAC is set explicitly to the paired device's MAC.
	eth := flow.Packet().Add().Ethernet()
	eth.Src().SetValue(s.SrcMAC)
	eth.Dst().SetValue(s.DstMAC)

	if s.VLAN {
		inner, outer := VLANIDs(s.Index)
		if s.QinQ {
			flow.Packet().Add().Vlan().Id().SetValue(outer)
		}
		flow.Packet().Add().Vlan().Id().SetValue(inner)
	}
	return flow
}
