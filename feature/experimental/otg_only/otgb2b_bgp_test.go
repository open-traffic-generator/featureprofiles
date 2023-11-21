package otg_b2b_bgp

import (
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
func configureOTG(t *testing.T, otg *otg.OTG) gosnappi.Config {

	config := gosnappi.NewConfig()
	srcPort := config.Ports().Add().SetName("port1")
	dstPort := config.Ports().Add().SetName("port2")

	srcDev := config.Devices().Add().SetName(atePort1.Name)
	srcEth := srcDev.Ethernets().Add().SetName(atePort1.Name + ".Eth").SetMac(atePort1.MAC)
	srcEth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(srcPort.Name())
	srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4")
	srcIpv4.SetAddress(atePort1.IPv4).SetGateway(atePort2.IPv4).SetPrefix(uint32(atePort1.IPv4Len))

	txBgp := srcDev.Bgp().
		SetRouterId(atePort1.IPv4)

	txBgpv4 := txBgp.
		Ipv4Interfaces().Add().
		SetIpv4Name(srcIpv4.Name())

	txBgpv4Peer := txBgpv4.
		Peers().
		Add().
		SetAsNumber(65000).
		SetAsType(gosnappi.BgpV4PeerAsType.IBGP).
		SetPeerAddress(atePort2.IPv4).
		SetName("txBgpv4Peer")

	txBgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

	txBgpv4PeerRrV4 := txBgpv4Peer.
		V4Routes().
		Add().
		SetNextHopIpv4Address(atePort2.IPv4).
		SetName("txBgpv4PeerRrV4").
		SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
		SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)

	txBgpv4PeerRrV4.Addresses().Add().
		SetAddress("100.1.1.1").
		SetPrefix(32).
		SetCount(1).
		SetStep(1)

	txBgpv4PeerRrV4.Advanced().
		SetMultiExitDiscriminator(50).
		SetOrigin(gosnappi.BgpRouteAdvancedOrigin.EGP).
		SetLocalPreference(200)

	txBgpv4PeerRrV4.Communities().Add().
		SetAsNumber(1).
		SetAsCustom(2).
		SetType(gosnappi.BgpCommunityType.MANUAL_AS_NUMBER)

	txBgpv4PeerRrV4AsPath := txBgpv4PeerRrV4.AsPath().
		SetAsSetMode(gosnappi.BgpAsPathAsSetMode.INCLUDE_AS_SET)

	txBgpv4PeerRrV4AsPath.Segments().Add().
		SetAsNumbers([]uint32{1112, 1113}).
		SetType(gosnappi.BgpAsPathSegmentType.AS_SEQ)

	txBgpv4PeerRrV4AsPath.Segments().Add().
		SetAsNumbers([]uint32{2222, 2223}).
		SetType(gosnappi.BgpAsPathSegmentType.AS_SET)

	dstDev := config.Devices().Add().SetName(atePort2.Name)
	dstEth := dstDev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	dstEth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(dstPort.Name())
	dstIpv4 := dstEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	dstIpv4.SetAddress(atePort2.IPv4).SetGateway(atePort1.IPv4).SetPrefix(uint32(atePort2.IPv4Len))

	rxBgp := dstDev.Bgp().
		SetRouterId(atePort2.IPv4)

	rxBgpv4 := rxBgp.
		Ipv4Interfaces().Add().
		SetIpv4Name(dstIpv4.Name())

	rxBgpv4Peer := rxBgpv4.
		Peers().
		Add().
		SetAsNumber(65000).
		SetAsType(gosnappi.BgpV4PeerAsType.IBGP).
		SetPeerAddress(atePort1.IPv4).
		SetName("rxBgpv4Peer")

	rxBgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

	rxBgpv4PeerRrV4 := rxBgpv4Peer.
		V4Routes().
		Add().
		SetNextHopIpv4Address(atePort1.IPv4).
		SetName("rxBgpv4PeerRrV4").
		SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
		SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)

	rxBgpv4PeerRrV4.Addresses().Add().
		SetAddress("200.1.1.1").
		SetPrefix(32).
		SetCount(1).
		SetStep(1)
	// ATE Traffic Configuration.
	t.Logf("TestBGP:start ate Traffic config")
	flowipv4 := config.Flows().Add().SetName("bgpv4RoutesFlow")
	flowipv4.Metrics().SetEnable(true)
	flowipv4.TxRx().Device().
		SetTxNames([]string{txBgpv4PeerRrV4.Name()}).
		SetRxNames([]string{rxBgpv4PeerRrV4.Name()})
	flowipv4.Size().SetFixed(512)
	flowipv4.Duration().SetChoice("continuous")
	e1 := flowipv4.Packet().Add().Ethernet()
	e1.Src().SetValue(srcEth.Mac())
	v4 := flowipv4.Packet().Add().Ipv4()
	v4.Src().SetValue("100.1.1.1")
	v4.Dst().SetValue("200.1.1.1")

	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	// time.Sleep(40 * time.Second)
	otg.StartProtocols(t)
	// time.Sleep(40 * time.Second)

	return config
}

// verifyTraffic confirms that every traffic flow has the expected amount of loss (0% or 100%
// depending on wantLoss, +- 2%).
func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, c gosnappi.Config, wantLoss bool) {
	otg := ate.OTG()
	otgutils.LogFlowMetrics(t, otg, c)
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

func sendTraffic(t *testing.T, otg *otg.OTG, c gosnappi.Config) {
	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)
}

func verifyOTGBGPTelemetry(t *testing.T, otg *otg.OTG, c gosnappi.Config, state string) {
	for _, d := range c.Devices().Items() {
		for _, ip := range d.Bgp().Ipv4Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
					currState, ok := val.Val()
					return ok && currState.String() == state
				}).Await(t)
				if !ok {
					fptest.LogQuery(t, "BGP reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
					t.Errorf("No BGP neighbor formed for peer %s", configPeer.Name())
				}
			}
		}
		for _, ip := range d.Bgp().Ipv6Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
					currState, ok := val.Val()
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

func TestOTGb2bBgp(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	otgConfig := configureOTG(t, otg)
	// Verify the OTG BGP state.
	t.Logf("Verify OTG BGP sessions up")
	verifyOTGBGPTelemetry(t, otg, otgConfig, "ESTABLISHED")
	// Starting ATE Traffic and verify Traffic Flows and packet loss.
	sendTraffic(t, otg, otgConfig)
	verifyTraffic(t, ate, otgConfig, false)
}

