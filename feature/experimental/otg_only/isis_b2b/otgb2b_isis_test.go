package otg_isis

import (
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otg "github.com/openconfig/ondatra/otg"
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

	dstDev := config.Devices().Add().SetName(atePort2.Name)
	dstEth := dstDev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	dstEth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(dstPort.Name())
	dstIpv4 := dstEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	dstIpv4.SetAddress(atePort2.IPv4).SetGateway(atePort1.IPv4).SetPrefix(uint32(atePort2.IPv4Len))

	dtxIsis := srcDev.Isis().
		SetSystemId("640000000001").
		SetName("dtxIsis")

	dtxIsis.Basic().
		SetIpv4TeRouterId(atePort1.IPv4).
		SetHostname(dtxIsis.Name()).
		SetLearnedLspFilter(true).
		SetEnableWideMetric(false)

	dtxIsis.Advanced().
		SetAreaAddresses([]string{"490001"}).
		SetLspRefreshRate(900).
		SetEnableAttachedBit(false)

	txIsisint := dtxIsis.Interfaces().
		Add().
		SetEthName(srcEth.Name()).
		SetName("dtxIsisInt").
		SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
		SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_2)

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

	drxIsis := dstDev.Isis().
		SetSystemId("650000000001").
		SetName("drxIsis")

	drxIsis.Basic().
		SetIpv4TeRouterId(atePort2.IPv4).
		SetHostname(drxIsis.Name()).
		SetLearnedLspFilter(true).
		SetEnableWideMetric(false)

	drxIsis.Advanced().
		SetAreaAddresses([]string{"490001"}).
		SetLspRefreshRate(900).
		SetEnableAttachedBit(false)

	rxIsisint := drxIsis.Interfaces().
		Add().
		SetEthName(dstEth.Name()).
		SetName("drxIsisInt").
		SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
		SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_2)

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

	t.Logf("TestISIS :start ate Traffic config")
	v4Flow := config.Flows().Add().SetName("ISISv4Flow")
	v4Flow.Metrics().SetEnable(true)
	v4Flow.TxRx().Device().
		SetTxNames([]string{dtxIsisRrV4.Name()}).
		SetRxNames([]string{drxIsisRrV4.Name()})
	v4Flow.Size().SetFixed(512)
	v4Flow.Rate().SetPps(1000)
	v4Flow.Duration().SetChoice("continuous")
	e1 := v4Flow.Packet().Add().Ethernet()
	e1.Src().SetValue(srcEth.Mac())
	e1.Dst().SetValue(dstEth.Mac())
	v4 := v4Flow.Packet().Add().Ipv4()
	v4.Src().SetValue("100.1.1.1")
	v4.Dst().SetValue("200.1.1.1")
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

func sendTraffic(t *testing.T, otg *otg.OTG, c gosnappi.Config) {
	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)
}

func TestOTGB2bIsis(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	// Configure Isis and Push config and Start protocols
	otgConfig := configureOTG(t, otg)
	// Starting ATE Traffic and verify Traffic Flows and packet loss.
	sendTraffic(t, otg, otgConfig)
	verifyTraffic(t, ate, otgConfig, false)

}

