package otg_b2b

import (
	//"os"

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
	// config.Captures().Add().
	// 	SetName("otg_cap").
	// 	SetPortNames([]string{dstPort.Name()}).
	// 	SetFormat(gosnappi.CaptureFormat.PCAP).SetOverwrite(true)

	srcDev := config.Devices().Add().SetName(atePort1.Name)
	srcEth := srcDev.Ethernets().Add().SetName(atePort1.Name + ".Eth").SetMac(atePort1.MAC)
	srcEth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(srcPort.Name())
	srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4")
	srcIpv4.SetAddress(atePort1.IPv4).SetGateway(atePort2.IPv4).SetPrefix(uint32(atePort1.IPv4Len))
	srcIpv6 := srcEth.Ipv6Addresses().Add().SetName(atePort1.Name + ".IPv6")
	srcIpv6.SetAddress(atePort1.IPv6).SetGateway(atePort2.IPv6).SetPrefix(uint32(atePort1.IPv6Len))

	dstDev := config.Devices().Add().SetName(atePort2.Name)
	dstEth := dstDev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	dstEth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(dstPort.Name())
	dstIpv4 := dstEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	dstIpv4.SetAddress(atePort2.IPv4).SetGateway(atePort1.IPv4).SetPrefix(uint32(atePort2.IPv4Len))
	dstIpv6 := dstEth.Ipv6Addresses().Add().SetName(atePort2.Name + ".IPv6")
	dstIpv6.SetAddress(atePort2.IPv6).SetGateway(atePort1.IPv6).SetPrefix(uint32(atePort2.IPv6Len))

	// ATE Traffic Configuration
	flowipv4 := config.Flows().Add().SetName("Flow-IPv4")
	flowipv4.Metrics().SetEnable(true)
	flowipv4.TxRx().Device().
		SetTxNames([]string{srcIpv4.Name()}).SetRxNames([]string{dstIpv4.Name()})
	flowipv4.Size().SetFixed(512)
	flowipv4.Rate().SetPercentage(1)
	flowipv4.Duration().SetChoice("fixed_packets")
	flowipv4.Duration().FixedPackets().SetPackets(1000)
	e1 := flowipv4.Packet().Add().Ethernet()
	e1.Src().SetValue(srcEth.Mac())
	e1.Dst().SetValue(dstEth.Mac())
	v4 := flowipv4.Packet().Add().Ipv4()
	v4.Src().SetValue(srcIpv4.Address())
	v4.Dst().SetValue(dstIpv4.Address())

	flowipv6 := config.Flows().Add().SetName("Flow-IPv6")
	flowipv6.Metrics().SetEnable(true)
	flowipv6.TxRx().Device().
		SetTxNames([]string{srcIpv6.Name()}).SetRxNames([]string{dstIpv6.Name()})
	flowipv6.Size().SetFixed(512)
	flowipv6.Rate().SetPercentage(1)
	flowipv6.Duration().SetChoice("fixed_packets")
	flowipv6.Duration().FixedPackets().SetPackets(1000)
	e2 := flowipv6.Packet().Add().Ethernet()
	e2.Src().SetValue(srcEth.Mac())
	e2.Dst().SetValue(dstEth.Mac())
	v6 := flowipv6.Packet().Add().Ipv6()
	v6.Src().SetValue(srcIpv6.Address())
	v6.Dst().SetValue(dstIpv6.Address())

	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	otg.StartProtocols(t)
	return config
}

func testTraffic(t *testing.T, ate *ondatra.ATEDevice, c gosnappi.Config) {
	time.Sleep(2 * time.Second)
	trafficDuration := 10 * time.Second
	otg := ate.OTG()
	// capture
	// cs := gosnappi.NewControlState()
	// cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	// otg.SetControlState(t, cs)

	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)
	time.Sleep(5 * time.Second)
	otgutils.LogPortMetrics(t, otg, c)
	otgutils.LogFlowMetrics(t, otg, c)
	// bytes := otg.GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(c.Ports().Items()[1].Name()))
	// f, err := os.CreateTemp(".", "pcap")
	// if err != nil {
	// 	t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	// }
	// defer os.Remove(f.Name())

	// if _, err := f.Write(bytes); err != nil {
	// 	t.Fatalf("ERROR: Could not write bytes to pcap file: %v\n", err)
	// }
	// f.Close()

	for _, flow := range c.Flows().Items() {
		t.Logf("Verifying flow metrics for flow %s\n", flow.Name())
		txPackets := float32(gnmi.Get(t, otg, gnmi.OTG().Flow(flow.Name()).Counters().OutPkts().State()))
		rxPackets := float32(gnmi.Get(t, otg, gnmi.OTG().Flow(flow.Name()).Counters().InPkts().State()))
		lossPct := (txPackets - rxPackets) * 100 / txPackets
		if lossPct > 0 {
			t.Errorf("Traffic Loss Pct for Flow: %s\n got %v, want 0", flow.Name(), lossPct)
		} else {
			if txPackets > 0 {
				t.Logf("Traffic for flow %s Passed!", flow.Name())
			} else {
				t.Errorf("Tx Packets for Flow: %s\n got %v, want >0", flow.Name(), txPackets)
			}
		}
	}
}

func TestOTGb2b(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	otgConfig := configureOTG(t, otg)

	t.Logf("Verify traffic")
	testTraffic(t, ate, otgConfig)

}
