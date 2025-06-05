package otg_ospfv2_b2b

import (
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	//"github.com/openconfig/featureprofiles/internal/attrs"
	"fmt"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otg "github.com/openconfig/ondatra/otg"
	"strings"
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

/*
type trafficEndpoints struct {
	name, values []string
}

var (

	atePort1 = attrs.Attributes{
		Name:       "atePort1",
		MAC:        "02:00:01:01:01:01",
		IPv4:       "192.0.2.1",
		IPv4Len:    16,
		RouteCount: 1,
	}

	atePort2 = attrs.Attributes{
		Name:       "atePort2",
		MAC:        "02:00:02:01:01:01",
		IPv4:       "192.0.3.1",
		IPv4Len:    16,
		RouteCount: 1,
	}

)
*/

type ospfStats struct {
	Name       string
	NumSession uint64
	FlapCount  uint64
}

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func Ospfv3BroadcastAandP2PDutPort(t *testing.T, otg *otg.OTG) gosnappi.Config {
	config := gosnappi.NewConfig()

	routecount := uint32(1)

	// add ports
	p1 := config.Ports().Add().SetName("port1")
	p2 := config.Ports().Add().SetName("port2")

	// add devices
	d1 := config.Devices().Add().SetName("d1")
	d2 := config.Devices().Add().SetName("d2")

	// add protocol stacks for device d1
	d1Eth1 := d1.Ethernets().
		Add().
		SetName("d1Eth").
		SetMac("00:00:01:01:01:01")

	d1Eth1.Connection().SetPortName(p1.Name())

	p1d1v1 := d1Eth1.Vlans().Add().SetName("p1d1v1").SetId(1)

	d1Eth1.Ipv6Addresses().
		Add().
		SetName("p1d1ipv6").
		SetAddress("11::2").
		SetGateway("11::1").
		SetPrefix(64)

	d1ospfv3 := d1.Ospfv3()
	d1ospfv3.RouterId().SetCustom("1.1.1.1")

	d1Instanceospfv3 := d1ospfv3.Instances().Add().
		SetName("d1Ospfv3")

	d1Instanceospfv3.SetStoreLsa(true)

	d1intf := d1Instanceospfv3.Interfaces().Add()

	d1intf.SetName("p1d1int").
		SetIpv6Name("p1d1ipv6").
		NetworkType().PointToPoint()

	d1intf.Options()

	d1ospfv3v6route := d1Instanceospfv3.
		V6Routes().
		Add().
		SetName("p1d1rr1_v6routes")

	d1ospfv3v6route.
		Addresses().
		Add().
		SetAddress("4:4:4::1").
		SetPrefix(64).
		SetCount(routecount).
		SetStep(1)

	// add protocol stacks for device d2
	d2Eth1 := d2.Ethernets().
		Add().
		SetName("d2Eth").
		SetMac("00:00:02:02:02:02")

	d2Eth1.Connection().SetPortName(p2.Name())

	p2d1v1 := d2Eth1.Vlans().Add().SetName("p2d1v1").SetId(2)

	d2Eth1.Ipv6Addresses().
		Add().
		SetName("p2d1ipv6").
		SetAddress("12::2").
		SetGateway("12::1").
		SetPrefix(64)

	d2ospfv3 := d2.Ospfv3()
	d2ospfv3.RouterId().SetCustom("2.2.2.2")

	d2Instanceospfv3 := d2ospfv3.Instances().Add().
		SetName("d2Ospfv3")

	d2Instanceospfv3.SetStoreLsa(true)

	d2intf := d2Instanceospfv3.Interfaces().Add()

	d2intf.SetName("p2d1int").
		SetIpv6Name("p2d1ipv6").
		NetworkType().Broadcast().SetPriority(1)

	d2intf.Options()

	d2ospfv3v6route := d2Instanceospfv3.
		V6Routes().
		Add().
		SetName("p2d2rr1_v6routes")

	d2ospfv3v6route.
		Addresses().
		Add().
		SetAddress("6:6:6::1").
		SetPrefix(64).
		SetCount(routecount).
		SetStep(1)

	// Set non-default route-origin
	//d2ospfv3v6route.
	//      RouteOrigin().NssaExternal().Capabilities().
	//      SetPropagation(true).
	//      ForwardingAddress()

	// Flow port1->port2
	flow1 := config.Flows().Add()
	flow1.SetName("IPv6 " + p1.Name() + "-> " + p2.Name()).
		TxRx().
		Device().
		SetTxNames([]string{d1ospfv3v6route.Name()}).
		SetRxNames([]string{d2ospfv3v6route.Name()})

	flow1.Metrics().SetEnable(true)
	flow1.Duration().FixedPackets().SetPackets(1000)
	flow1.Rate().SetPps(200)

	//ethernet + VLAN
	flow1Eth := flow1.Packet().Add().Ethernet()
	flow1.Packet().Add().Vlan().Id().SetValue(p1d1v1.Id())
	flow1Eth.Src().SetValue(d1Eth1.Mac())
	flow1Eth.Dst().Auto()

	//IP packet
	flow1Ip := flow1.Packet().Add().Ipv6()
	flow1Ip.Src().Increment().SetStart(d1ospfv3v6route.Addresses().Items()[0].Address())
	flow1Ip.Src().Increment().SetCount(5)
	flow1Ip.Dst().Increment().SetStart(d2ospfv3v6route.Addresses().Items()[0].Address())
	flow1Ip.Dst().Increment().SetCount(5)

	// Flow port2->port1
	flow2 := config.Flows().Add()
	flow2.SetName("IPv4 " + p2.Name() + "-> " + p1.Name()).
		TxRx().
		Device().
		SetTxNames([]string{d2ospfv3v6route.Name()}).
		SetRxNames([]string{d1ospfv3v6route.Name()})

	flow2.Metrics().SetEnable(true)
	flow2.Duration().FixedPackets().SetPackets(1000)
	flow2.Rate().SetPps(200)

	//ethernet + VLAN
	flow2Eth := flow2.Packet().Add().Ethernet()
	flow2.Packet().Add().Vlan().Id().SetValue(p2d1v1.Id())

	flow2Eth.Src().SetValue(d2Eth1.Mac())
	flow2Eth.Dst().Auto()

	//IP packet
	flow2Ip := flow2.Packet().Add().Ipv6()
	flow2Ip.Src().Increment().SetStart(d2ospfv3v6route.Addresses().Items()[0].Address())
	flow2Ip.Src().Increment().SetCount(5)
	flow2Ip.Dst().Increment().SetStart(d1ospfv3v6route.Addresses().Items()[0].Address())
	flow2Ip.Dst().Increment().SetCount(5)

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

func verifyOtgOspfv3TelemetryCheckAllSessionsUp(
	t *testing.T, otg *otg.OTG,
	c gosnappi.Config,
	expectedMatric ospfStats) {
	//timeout := 60
	out := fmt.Sprintf("%s\n", strings.Repeat("-", 40))
	out += fmt.Sprintf("%15s %15s\n", "RouterName", "upCount")
	out += fmt.Sprintf("%s\n", strings.Repeat("-", 40))
	for _, d := range c.Devices().Items() {
		ospfv3Instance := d.Ospfv3()
		for _, i := range ospfv3Instance.Instances().Items() {
			ospfv3 := i
			fmt.Println(i)
			state := gnmi.Get(t, otg, gnmi.OTG().Ospfv3Router(ospfv3.Name()).Counters().SessionsUp().State())
			out += fmt.Sprintf("%15s %15d\n", ospfv3.Name(), state)
			if state == 1 {
			}
		}
	}
	out += fmt.Sprintf("%s\n", strings.Repeat("-", 40))
	fmt.Println(out)
}

func verifyOtgOspfv3TelemetryCheckSessionsUpInRtr(
	t *testing.T, otg *otg.OTG,
	rtrName string,
	expectedMatric ospfStats) {
	out := fmt.Sprintf("%s\n", strings.Repeat("-", 40))
	out += fmt.Sprintf("%15s %15s\n", "RouterName", "upCount")
	out += fmt.Sprintf("%s\n", strings.Repeat("-", 40))
	state := gnmi.Get(t, otg, gnmi.OTG().Ospfv3Router(rtrName).Counters().SessionsUp().State())
	out += fmt.Sprintf("%15s %15d\n", rtrName, state)
	if state == 1 {
	}
	out += fmt.Sprintf("%s\n", strings.Repeat("-", 40))
	fmt.Println(out)
}

func TestOtgb2bOspfv3(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	// Configure OSPFv2
	otgConfig := Ospfv3BroadcastAandP2PDutPort(t, otg)
	time.Sleep(20 * time.Second)

	// Verify the OTG OSPFv2 state.
	t.Logf("Verify OTG OSPFv2 sessions up")
	var expectedMetric ospfStats
	expectedMetric.NumSession = 1
	expectedMetric.FlapCount = 0

	expectedMetric.Name = "d1Ospfv3"
	verifyOtgOspfv3TelemetryCheckSessionsUpInRtr(t, otg, expectedMetric.Name, expectedMetric)

	expectedMetric.Name = "d2Ospfv3"
	verifyOtgOspfv3TelemetryCheckAllSessionsUp(t, otg, otgConfig, expectedMetric)

	// Starting ATE Traffic and verify Traffic Flows and packet loss.
	sendTraffic(t, otg)
	verifyTraffic(t, ate, otgConfig, false)
}
