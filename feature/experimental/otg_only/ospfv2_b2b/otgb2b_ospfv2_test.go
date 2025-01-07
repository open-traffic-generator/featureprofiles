package otg_ospfv2_b2b

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
	trafficDuration   = 5 * time.Second
	tolerance         = 50
	tolerancePct      = 2
	routesCount       = 40
	txStartRange      = "100.1.1.1"
	rxStartRange      = "200.1.1.1"
	totalPeersPerPort = 20
)

type trafficEndpoints struct {
	name, values []string
}

var (
	atePort1 = attrs.Attributes{
		Name:    "atePort1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.1",
		IPv4Len: 16,
		RouteCount: 1,
	}

	atePort2 = attrs.Attributes{
		Name:    "atePort2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.3.1",
		IPv4Len: 16,
		RouteCount: 1,
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func configureOtgOspfv2(t *testing.T, otg *otg.OTG) gosnappi.Config {
	config := gosnappi.NewConfig()
	p1 := config.Ports().Add().SetName("port1")
	p2 := config.Ports().Add().SetName("port2")

	// Start Ospfv2 config
	// add devices
	d1 := config.Devices().Add().SetName("d1")
	d2 := config.Devices().Add().SetName("d2")


	// add protocol stacks for device d1
	d1Eth1 := d1.Ethernets().
		Add().
		SetName("d1Eth").
		SetMac(atePort1.MAC)
	d1Eth1.Connection().SetPortName(p1.Name())

	d1Eth1.Ipv4Addresses().
		Add().
		SetName("p1d1ipv4").
		SetAddress("1.1.1.1").
		SetGateway("1.1.1.2").
		SetPrefix(24)

	d1ospfv2 := d1.Ospfv2().
		SetName("d1Ospfv2").
		SetStoreLsa(true) // To get LS stats

	d1ospfv2.RouterId().SetCustom("1.1.1.1") // Test router-id

	d1ospfv2.Interfaces().Add().
		SetName("p1d1int").
		SetIpv4Name("p1d1ipv4").
		NetworkType().PointToPoint() // non-default Network-type

	d1ospfv2v4route := d1ospfv2.
		V4Routes().
		Add().
		SetName("p1d1rr1_v4routes")

	d1ospfv2v4route.
		Addresses().
		Add().
		SetAddress("10.10.10.1").
		SetPrefix(24).
		SetCount(atePort1.RouteCount).
		SetStep(1)

	// add protocol stacks for device d2
	d2Eth1 := d2.Ethernets().
		Add().
		SetName("d2Eth").
		SetMac(atePort2.MAC)
	d2Eth1.Connection().SetPortName(p2.Name())

	d2Eth1.Ipv4Addresses().
		Add().
		SetName("p2d2ipv4").
		SetAddress("1.1.1.2").
		SetGateway("1.1.1.1").
		SetPrefix(24)

	d2ospfv2 := d2.Ospfv2().
		SetName("d2Ospfv2").
		SetStoreLsa(true)
	d2ospfv2.RouterId().SetCustom("1.1.1.2")

	d2ospfv2.Interfaces().Add().
		SetName("p2d1int").
		SetIpv4Name("p2d2ipv4").
		NetworkType().PointToPoint()

	d2ospfv2v4route := d2ospfv2.
		V4Routes().
		Add().
		SetName("p2d2rr1_v4routes")

	d2ospfv2v4route.
		Addresses().
		Add().
		SetAddress("20.20.20.1").
		SetPrefix(24).
		SetCount(atePort2.RouteCount).
		SetStep(1)

	// Set non-default route-origin
	d2ospfv2v4route.
		RouteOrigin().NssaExternal().
		SetPropagation(true).
		Flags().SetAFlag(true).SetNFlag(true)

	// Flow port1->port2
	flow1 := config.Flows().Add()
	flow1.SetName("IPv4 " + p1.Name() + "-> " + p2.Name()).
		TxRx().
		Device().
		SetTxNames([]string{d1ospfv2v4route.Name()}).
		SetRxNames([]string{d2ospfv2v4route.Name()})

	flow1.Metrics().SetEnable(true)
	flow1.Duration().FixedPackets().SetPackets(1000)
	flow1.Rate().SetPps(200)
	//ethernet
	flow1Eth := flow1.Packet().Add().Ethernet()
	flow1Eth.Src().SetValue(d1Eth1.Mac())
	flow1Eth.Dst().Auto()
	//IP packet
	flow1Ip := flow1.Packet().Add().Ipv4()
	flow1Ip.Src().Increment().SetStart(d1ospfv2v4route.Addresses().Items()[0].Address())
	flow1Ip.Src().Increment().SetStep("0.0.0.1")
	flow1Ip.Src().Increment().SetCount(5)
	flow1Ip.Dst().Increment().SetStart(d2ospfv2v4route.Addresses().Items()[0].Address())
	flow1Ip.Dst().Increment().SetStep("0.0.0.1")
	flow1Ip.Dst().Increment().SetCount(5)

	// Flow port2->port1
	flow2 := config.Flows().Add()
	flow2.SetName("IPv4 " + p2.Name() + "-> " + p1.Name()).
		TxRx().
		Device().
		SetTxNames([]string{d2ospfv2v4route.Name()}).
		SetRxNames([]string{d1ospfv2v4route.Name()})

	flow2.Metrics().SetEnable(true)
	flow2.Duration().FixedPackets().SetPackets(1000)
	flow2.Rate().SetPps(200)
	//ethernet
	flow2Eth := flow2.Packet().Add().Ethernet()
	flow2Eth.Src().SetValue(d1Eth1.Mac())
	flow2Eth.Dst().Auto()
	//IP packet
	flow2Ip := flow2.Packet().Add().Ipv4()
	flow2Ip.Src().Increment().SetStart(d2ospfv2v4route.Addresses().Items()[0].Address())
	flow2Ip.Src().Increment().SetStep("0.0.0.1")
	flow2Ip.Src().Increment().SetCount(5)
	flow2Ip.Dst().Increment().SetStart(d1ospfv2v4route.Addresses().Items()[0].Address())
	flow2Ip.Dst().Increment().SetStep("0.0.0.1")
	flow2Ip.Dst().Increment().SetCount(5)

	// End Ospfv2 config

	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	otg.StartProtocols(t)

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

func sendTraffic(t *testing.T, otg *otg.OTG) {
	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)
}

func verifyOtgOspfv2Telemetry(t *testing.T, otg *otg.OTG, c gosnappi.Config, state string) {
	for _, d := range c.Devices().Items() {
		for _, ip := range d.Bgp().Ipv4Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
					currState, ok := val.Val()
					return ok && currState.String() == state
				}).Await(t)
				if !ok {
					fptest.LogQuery(t, "OSPFv2 reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
					t.Errorf("No OSPFv2 neighbor formed for peer %s", configPeer.Name())
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
					fptest.LogQuery(t, "OSPFv2 reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
					t.Errorf("No OSPFv2 neighbor formed for peer %s", configPeer.Name())
				}
			}
		}

	}
}

func TestOtgb2bOspfv2(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	// Configure OSPFv2
	otgConfig := configureOtgOspfv2(t, otg)

	// Verify the OTG OSPFv2 state.
	t.Logf("Verify OTG OSPFv2 sessions up")
	verifyOtgOspfv2Telemetry(t, otg, otgConfig, "ESTABLISHED")

	// Starting ATE Traffic and verify Traffic Flows and packet loss.
	sendTraffic(t, otg)
	verifyTraffic(t, ate, otgConfig, false)
}
