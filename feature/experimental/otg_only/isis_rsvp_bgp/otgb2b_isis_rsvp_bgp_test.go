package otg_isis_rsvp_bgp

import (
	"os"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
)

const (
	trafficDuration = 10 * time.Second
	tolerance       = 50
	tolerancePct    = 2
	isisRoute       = "2.2.2.2"
	bgpFirstPrefix  = "200.0.0.1"
	bgpRoutesCount  = 20
)

var (
	atePort1 = attrs.Attributes{
		Name:    "atePort1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv6:    "2001:db8::192:0:2:2",
		IPv4Len: 24,
		IPv6Len: 126,
	}

	atePort2 = attrs.Attributes{
		Name:    "atePort2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.1",
		IPv6:    "2001:db8::192:0:2:1",
		IPv4Len: 24,
		IPv6Len: 126,
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}
func configureOTG(t *testing.T) gosnappi.Config {

	t.Helper()
	ate := ondatra.ATE(t, "ate")
	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	config := gosnappi.NewConfig()
	// add ports
	p1 := config.Ports().Add().SetName(ap1.ID())
	p2 := config.Ports().Add().SetName(ap2.ID())
	// add devices
	d1 := config.Devices().Add().SetName("p1.d1")
	d2 := config.Devices().Add().SetName("p2.d1")

	// capture on p2
	config.Captures().Add().
		SetName("p2_cap").
		SetPortNames([]string{p2.Name()}).
		SetFormat(gosnappi.CaptureFormat.PCAP).SetOverwrite(true)

	// Configuration on port1. Only IPv4 is enabled here and used as traffic src
	d1Eth1 := d1.Ethernets().
		Add().
		SetName(d1.Name() + ".eth").
		SetMac(atePort1.MAC).
		SetMtu(1500)
	d1Eth1.
		Connection().
		SetPortName(p1.Name())
	d1ipv41 := d1Eth1.
		Ipv4Addresses().
		Add().
		SetName(d1Eth1.Name() + ".ipv4").
		SetAddress(atePort1.IPv4).
		SetGateway(atePort2.IPv4).
		SetPrefix(24)

	// P1 isis router
	d1isis := d1.Isis().SetName(d1.Name() + ".isis").SetSystemId("640000000001")
	d1isis.Basic().SetIpv4TeRouterId(d1ipv41.Address()).SetHostname(atePort1.Name)
	d1isis.Advanced().SetAreaAddresses([]string{"49"})
	d1isisint := d1isis.Interfaces().
		Add().
		SetName(d1.Isis().Name() + ".intf").
		SetEthName(d1Eth1.Name()).
		SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
		SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_2).
		SetMetric(10)
	d1isisint.TrafficEngineering().Add().PriorityBandwidths()
	d1isisint.Advanced().SetAutoAdjustMtu(true).SetAutoAdjustArea(true).SetAutoAdjustSupportedProtocols(true)

	// Port 1 BGP config
	d1Bgp := d1.Bgp().SetRouterId(atePort1.IPv4)
	d1Bgpv4 := d1Bgp.Ipv4Interfaces().Add().SetIpv4Name(d1ipv41.Name())
	d1Bgpv4Peer := d1Bgpv4.Peers().Add().SetAsNumber(64000).SetAsType(gosnappi.BgpV4PeerAsType.EBGP).
		SetPeerAddress(atePort2.IPv4).SetName(d1.Name() + ".bgp")
	d1Bgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

	d2Eth1 := d2.Ethernets().
		Add().
		SetName(d2.Name() + ".eth1").
		SetMac(atePort2.MAC).
		SetMtu(1500)
	d2Eth1.
		Connection().
		SetPortName(p2.Name())
	d2ipv41 := d2Eth1.Ipv4Addresses().
		Add().
		SetName(d2.Name() + ".ipv4").
		SetAddress(atePort2.IPv4).
		SetGateway(atePort1.IPv4).
		SetPrefix(24)

	// P2 isis router
	d2isis := d2.Isis().SetName(d2.Name() + ".isis").SetSystemId("650000000001")
	d2isis.Basic().SetIpv4TeRouterId(d2ipv41.Address()).SetHostname(atePort2.Name)
	d2isis.Advanced().SetAreaAddresses([]string{"49"})
	d2isisint := d2isis.Interfaces().
		Add().
		SetName(d2.Isis().Name() + ".intf").
		SetEthName(d2Eth1.Name()).
		SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
		SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_2).
		SetMetric(10)
	d2isisint.TrafficEngineering().Add().PriorityBandwidths()
	d2isisint.Advanced().SetAutoAdjustMtu(true).SetAutoAdjustArea(true).SetAutoAdjustSupportedProtocols(true)
	d2IsisRoute1 := d2isis.V4Routes().Add().SetName(d2.Isis().Name() + ".rr")
	d2IsisRoute1.Addresses().
		Add().
		SetAddress(isisRoute).
		SetPrefix(32)

	// P2 RSVP
	d2rsvp := d2.Rsvp().SetName(d2.Name() + ".rsvp")
	d2rsvp.Ipv4Interfaces().
		Add().SetIpv4Name(d2ipv41.Name()).
		SetNeighborIp(d2ipv41.Gateway()).
		SetEnableRefreshReduction(true).
		SetSendBundle(true).SetEnableHello(true)
	d2RsvpConnLspIntf := d2rsvp.LspIpv4Interfaces().
		Add().
		SetIpv4Name(d2ipv41.Name())
	d2RsvpConnEgress := d2RsvpConnLspIntf.P2PEgressIpv4Lsps()
	d2RsvpConnEgress.SetName(d2rsvp.Name() + ".egress").
		SetEnableFixedLabel(false).
		SetRefreshInterval(30).
		SetReservationStyle("shared_explicit").
		SetTimeoutMultiplier(3)

	// Port 2 BGP config
	d2Bgp := d2.Bgp().SetRouterId(atePort2.IPv4)
	d2Bgpv4 := d2Bgp.Ipv4Interfaces().Add().SetIpv4Name(d2ipv41.Name())
	d2Bgpv4Peer := d2Bgpv4.Peers().Add().SetAsNumber(65000).SetAsType(gosnappi.BgpV4PeerAsType.EBGP).
		SetPeerAddress(atePort1.IPv4).SetName(d2.Name() + ".bgp")
	d2Bgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)
	d2Bgpv4PeerRrV4 := d2Bgpv4Peer.V4Routes().Add().SetNextHopIpv4Address(atePort1.IPv4).
		SetName(d2Bgpv4Peer.Name() + ".rrv4").
		SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
		SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
	d2Bgpv4PeerRrV4.Addresses().Add().SetAddress(bgpFirstPrefix).SetPrefix(32).SetCount(bgpRoutesCount).SetStep(1)

	flow1 := config.Flows().Add()
	flow1.Metrics().SetEnable(true)
	flow1.Duration().FixedPackets().SetPackets(100)
	flow1.Rate().SetPps(20)
	flow1.SetName(d1ipv41.Address() + "-> " + isisRoute).
		TxRx().Device().
		SetTxNames([]string{d1ipv41.Name()}).
		SetRxNames([]string{d2IsisRoute1.Name()})
	flowEth := flow1.Packet().Add().Ethernet()
	flowEth.Src().SetValue(d1Eth1.Mac())
	flowEth.Dst().Auto()
	flowIP := flow1.Packet().Add().Ipv4()
	flowIP.Src().SetValue(d1ipv41.Address())
	flowIP.Dst().SetValue(isisRoute)

	flow2 := config.Flows().Add()
	flow2.Metrics().SetEnable(true)
	flow2.Duration().FixedPackets().SetPackets(100)
	flow2.Rate().SetPps(20)
	flow2.SetName(d1ipv41.Address() + "-> bgp routes").
		TxRx().Device().
		SetTxNames([]string{d1ipv41.Name()}).
		SetRxNames([]string{d2Bgpv4PeerRrV4.Name()})
	flowEth = flow2.Packet().Add().Ethernet()
	flowEth.Src().SetValue(d1Eth1.Mac())
	flowEth.Dst().Auto()
	flowIP = flow2.Packet().Add().Ipv4()
	flowIP.Priority().Tos().Precedence().Increment().SetStart(0).SetCount(7)
	flowIP.Src().SetValue(d1ipv41.Address())
	flowIP.Dst().Increment().SetStart(bgpFirstPrefix).SetCount(bgpRoutesCount)

	ate.OTG().PushConfig(t, config)
	time.Sleep(time.Second * 5)

	// start capture
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	ate.OTG().SetControlState(t, cs)

	ate.OTG().StartProtocols(t)
	time.Sleep(time.Second * 5)

	return config
}

// verifyTraffic confirms that every traffic flow has the expected amount of loss (0% or 100%
// depending on wantLoss, +- 2%).
func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, c gosnappi.Config, wantLoss bool) {
	otg := ate.OTG()
	otgutils.LogFlowMetrics(t, otg, c)

	bytes := otg.GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(ate.Port(t, "port2").ID()))
	f, err := os.CreateTemp(".", "pcap")
	if err != nil {
		t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(bytes); err != nil {
		t.Fatalf("ERROR: Could not write bytes to pcap file: %v\n", err)
	}
	f.Close()

	for _, f := range c.Flows().Items() {
		t.Logf("Verifying flow metrics for flow %s\n", f.Name())
		recvMetric := gnmi.Get(t, otg, gnmi.OTG().Flow(f.Name()).State())
		txPackets := float32(recvMetric.GetCounters().GetOutPkts())
		rxPackets := float32(recvMetric.GetCounters().GetInPkts())
		lostPackets := txPackets - rxPackets
		lossPct := lostPackets * 100 / txPackets
		if !wantLoss {
			if lostPackets > tolerance {
				t.Logf("Packets received not matching packets sent. Sent: %v, Received: %v", txPackets, rxPackets)
			}
			if lossPct > tolerancePct && txPackets > 0 {
				t.Errorf("Traffic Loss Pct for Flow: %s\n got %v, want max %v pct failure", f.Name(), lossPct, tolerancePct)
			} else {
				t.Logf("Traffic Test Passed! for flow %s", f.Name())
			}
		} else {
			if lossPct < 100-tolerancePct && txPackets > 0 {
				t.Errorf("Traffic is expected to fail %s\n got %v, want max %v pct failure", f.Name(), lossPct, 100-tolerancePct)
			} else {
				t.Logf("Traffic Loss Test Passed! for flow %s", f.Name())
			}
		}

	}
}

// verifyIsis checks the status of the ISIS routers
func verifyIsis(t *testing.T, otg *otg.OTG, c gosnappi.Config) {

	for _, d := range c.Devices().Items() {
		isisName := d.Isis().Name()
		for {
			level2State := gnmi.Get(t, otg, gnmi.OTG().IsisRouter(isisName).Counters().Level2().State())
			t.Logf("L2 sessions flap for isis router %s are %d", isisName, level2State.GetSessionsFlap())
			t.Logf("L2 sessions up for isis router %s are %d", isisName, level2State.GetSessionsUp())
			if level2State.GetSessionsUp() == 1 {
				break
			}
			time.Sleep(5 * time.Second)
		}
		_, ok := gnmi.Watch(t, otg, gnmi.OTG().IsisRouter(isisName).Counters().Level2().SessionsUp().State(), 5*time.Minute, func(v *ygnmi.Value[uint64]) bool {
			time.Sleep(5 * time.Second)
			val, present := v.Val()
			t.Logf("v is %v", v)
			t.Logf("present is %v and val is %d", present, val)
			return present && val == 1
		}).Await(t)
		if !ok {
			t.Errorf("No ISIS session up for router %s or timeout occured while waiting", isisName)
		}

	}
}

func verifyBgp(t *testing.T, otg *otg.OTG, c gosnappi.Config, state string) {
	for _, d := range c.Devices().Items() {
		for _, ip := range d.Bgp().Ipv4Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
					currState, ok := val.Val()
					t.Logf("BGP state for peer %v is %s", configPeer.Name(), currState.String())
					return ok && currState.String() == state
				}).Await(t)
				if !ok {
					fptest.LogQuery(t, "BGP reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
					t.Errorf("No BGP neighbor formed for peer %s", configPeer.Name())
				}
			}
		}
	}
}

// verifyIsisRoutes checks the metric of one route
// func verifyIsisRoutes(t *testing.T, otg *otg.OTG, isisName, route string) {
// 	metrics := gnmi.GetAll(t, otg, gnmi.OTG().IsisRouter(isisName).LinkStateDatabase().LspsAny().Tlvs().ExtendedIpv4Reachability().PrefixAny().Metric().State())
// 	t.Logf("Metric for route %s is %d", route, metrics[0])
// 	_, ok := gnmi.WatchAll(t, otg, gnmi.OTG().IsisRouter(isisName).LinkStateDatabase().LspsAny().Tlvs().ExtendedIpv4Reachability().PrefixAny().Metric().State(), time.Minute, func(v *ygnmi.Value[uint32]) bool {
// 		metric, present := v.Val()
// 		if present {
// 			if metric == 10 {
// 				return true
// 			}
// 		}
// 		return false
// 	}).Await(t)

// }

func sendTraffic(t *testing.T, otg *otg.OTG) {
	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)
}

func TestOTGB2bIsisRsvpBgp(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	otgConfig := configureOTG(t)
	verifyIsis(t, otg, otgConfig)
	verifyBgp(t, otg, otgConfig, "ESTABLISHED")

	sendTraffic(t, otg)
	verifyTraffic(t, ate, otgConfig, false)

}
