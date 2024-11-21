package otg_isis

import (
	"log"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
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

	// add devices
	srcDev := config.Devices().Add().SetName(atePort1.Name)
	srcEth := srcDev.Ethernets().Add().SetName(atePort1.Name + ".Eth").SetMac(atePort1.MAC)
	srcEth.Connection().SetPortName(srcPort.Name())
	srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4")
	srcIpv4.SetAddress(atePort1.IPv4).SetGateway(atePort2.IPv4).SetPrefix(uint32(atePort1.IPv4Len))

	dstDev := config.Devices().Add().SetName(atePort2.Name)
	dstEth := dstDev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	dstEth.Connection().SetPortName(dstPort.Name())
	dstIpv4 := dstEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	dstIpv4.SetAddress(atePort2.IPv4).SetGateway(atePort1.IPv4).SetPrefix(uint32(atePort2.IPv4Len))

	dtxIsis := srcDev.Isis().
		SetSystemId("640000000001").
		SetName("dtxIsis")

	dtxIsis.Basic().
		SetIpv4TeRouterId(atePort1.IPv4).
		SetHostname(dtxIsis.Name()).
		SetLearnedLspFilter(true).
		SetEnableWideMetric(true)

	dtxIsis.Advanced().
		SetAreaAddresses([]string{"490001"}).
		SetLspRefreshRate(900).
		SetEnableAttachedBit(false)

	txIsisint := dtxIsis.Interfaces().
		Add().
		SetEthName(srcEth.Name()).
		SetName("dtxIsisInt").
		SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
		SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_1_2).
		SetMetric(10)
	txIsisint.TrafficEngineering().Add().PriorityBandwidths()
	txIsisint.Advanced().
		SetAutoAdjustMtu(true).SetAutoAdjustArea(true).SetAutoAdjustSupportedProtocols(true)

	dtxIsisRrV4 := dtxIsis.
		V4Routes().
		Add().SetName("dtxIsisRr4").SetLinkMetric(10)

	dtxIsisRrV4.Addresses().Add().
		SetAddress("100.1.1.1").
		SetPrefix(32).
		SetCount(5).
		SetStep(1)

	// adding Simulated topology
	gridSt := otgutils.NewGridisisSt(config)
	gridSt.SetRow(3).SetCol(3).
		SetSystemIdFirstOctet("66").
		SetLinkIp4FirstOctet("20")

	grigRouteV4 := gridSt.V4RouteInfo()
	grigRouteV4.SetAddressFirstOctet("30").
		SetPrefix(32).
		SetCount(1)

	gridTopo := gridSt.GenerateTopology()
	gridTopo.Connect(srcDev, 0, 1)

	drxIsis := dstDev.Isis().
		SetSystemId("650000000001").
		SetName("drxIsis")

	drxIsis.Basic().
		SetIpv4TeRouterId(atePort2.IPv4).
		SetHostname(drxIsis.Name()).
		SetLearnedLspFilter(true).
		SetEnableWideMetric(true)

	drxIsis.Advanced().
		SetAreaAddresses([]string{"490001"}).
		SetLspRefreshRate(900).
		SetEnableAttachedBit(false)

	rxIsisint := drxIsis.Interfaces().
		Add().
		SetEthName(dstEth.Name()).
		SetName("drxIsisInt").
		SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
		SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_1_2).
		SetMetric(10)

	rxIsisint.TrafficEngineering().Add().PriorityBandwidths()
	rxIsisint.Advanced().
		SetAutoAdjustMtu(true).SetAutoAdjustArea(true).SetAutoAdjustSupportedProtocols(true)

	drxIsisRrV4 := drxIsis.
		V4Routes().
		Add().SetName("drxIsisRr4").SetLinkMetric(10)

	drxIsisRrV4.Addresses().Add().
		SetAddress("200.1.1.1").
		SetPrefix(32).
		SetCount(5).
		SetStep(1)

	ringSt := otgutils.NewRingIsisSt(config)
	ringSt.SetNoOfNodes(3).
		SetSystemIdFirstOctet("67").
		SetLinkIp4FirstOctet("30")

	ringRouteV4 := ringSt.V4RouteInfo()
	ringRouteV4.SetAddressFirstOctet("40").
		SetPrefix(32).
		SetCount(1)

	ringTopo := ringSt.GenerateTopology()
	ringTopo.Connect(dstDev, 1)

	//B. Create flows from endpoints in simulated rtrs i.e. ISIS routes
	//B. Create flows from endpoints in simulated rtrs i.e. ISIS routes
	fromSimRtr := gridTopo.GetDevice(2, 2)
	toSimRtr := ringTopo.GetDevice(2)
	flow := config.Flows().Add()
	fromRoute := fromSimRtr.Isis().V4Routes().Items()[0]
	toRoute := toSimRtr.Isis().V4Routes().Items()[0]
	flow.SetName("IPv4 " + fromSimRtr.Name() + "-> " + toSimRtr.Name()).
		TxRx().
		Device().
		SetTxNames([]string{fromRoute.Name()}).
		SetRxNames([]string{toRoute.Name()})
	flow.Metrics().SetEnable(true)
	flow.Duration().FixedPackets().SetPackets(1000)
	flow.Rate().SetPps(200)
	//ethernet
	flowEth := flow.Packet().Add().Ethernet()
	flowEth.Src().SetValue(srcEth.Mac())
	flowEth.Dst().Auto()
	//IP packet
	flowIp := flow.Packet().Add().Ipv4()
	flowIp.Src().SetValue(fromRoute.Addresses().Items()[0].Address())
	flowIp.Dst().SetValue(toRoute.Addresses().Items()[0].Address())

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

// verifyIsis checks the status of the ISIS routers
func verifyIsis(t *testing.T, otg *otg.OTG, c gosnappi.Config) {

	routerNames := []string{}
	for _, d := range c.Devices().Items() {
		for _, e := range d.Ethernets().Items() {
			if !e.Connection().HasSimulatedLink() {
				isis := d.Isis()
				routerNames = append(routerNames, isis.Name())
				log.Println("routerNames", routerNames)
			}
		}
	}
	for _, isisName := range routerNames {
		// isisName := d.Isis().Name()
		for {
			level2State := gnmi.Get(t, otg, gnmi.OTG().IsisRouter(isisName).Counters().Level2().State())
			t.Logf("L2 sessions flap for isis router %s are %d", isisName, level2State.GetSessionsFlap())
			t.Logf("L2 sessions up for isis router %s are %d", isisName, level2State.GetSessionsUp())
			level1State := gnmi.Get(t, otg, gnmi.OTG().IsisRouter(isisName).Counters().Level1().State())
			t.Logf("L1 sessions flap for isis router %s are %d", isisName, level1State.GetSessionsFlap())
			t.Logf("L1 sessions up for isis router %s are %d", isisName, level1State.GetSessionsUp())
			if level2State.GetSessionsUp() == 1 && level1State.GetSessionsUp() == 1 {
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

// verifyIsis checks the status of the ISIS routers
func verifyIsisLsp(t *testing.T, otg *otg.OTG, c gosnappi.Config) {

	routerNames := []string{}
	for _, d := range c.Devices().Items() {
		for _, e := range d.Ethernets().Items() {
			if !e.Connection().HasSimulatedLink() {
				isis := d.Isis()
				routerNames = append(routerNames, isis.Name())
			}
		}
	}
	for _, isisName := range routerNames {

		_, ok1 := gnmi.WatchAll(t, otg, gnmi.OTG().IsisRouter(isisName).LinkStateDatabase().LspsAny().LspId().State(), time.Minute, func(v *ygnmi.Value[string]) bool {
			lspId, present := v.Val()
			if present {
				if lspId == "660000000005-0-0" || lspId == "670000000001-0-0" {
					t.Logf("Match lspId == %v", lspId)
					return true
				}
			}
			return false
		}).Await(t)

		if !ok1 {
			t.Fatalf("ISIS LSP ID is not matching")
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

func TestOTGB2bIsisSt(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	// Configure Isis and Push config and Start protocols
	otgConfig := configureOTG(t, otg)
	// Starting ATE Traffic and verify Traffic Flows and packet loss.
	verifyIsis(t, otg, otgConfig)
	verifyIsisLsp(t, otg, otgConfig)
	sendTraffic(t, otg)
	verifyTraffic(t, ate, otgConfig, false)
}
