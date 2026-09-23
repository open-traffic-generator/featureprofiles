package lagb2b

import (
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otgapi "github.com/openconfig/ondatra/otg"
)

var (
	ateLag1 = attrs.Attributes{
		Name:    "ateLag1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: 24,
	}
	ateLag2 = attrs.Attributes{
		Name:    "ateLag2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.1",
		IPv4Len: 24,
	}
	lag1Members = []string{"port1"}
	lag2Members = []string{"port2"}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func configureOTG(t *testing.T, otg *otgapi.OTG, ate *ondatra.ATEDevice) gosnappi.Config {
	t.Helper()
	config := gosnappi.NewConfig()

	addLag := func(name, mac string, members []string) gosnappi.Lag {
		lag := config.Lags().Add().SetName(name)
		lag.Protocol().Lacp().SetActorKey(1).SetActorSystemPriority(1).SetActorSystemId(mac)
		for index, member := range members {
			port := ate.Port(t, member)
			config.Ports().Add().SetName(port.ID())
			lagPort := lag.Ports().Add().SetPortName(port.ID())
			lagPort.Ethernet().SetMac(mac).SetName(name + "-" + port.ID())
			lagPort.Lacp().SetActorActivity("active").SetActorPortNumber(uint32(index) + 1).SetActorPortPriority(1).SetLacpduTimeout(0)
		}
		return lag
	}

	srcLag := addLag(ateLag1.Name, ateLag1.MAC, lag1Members)
	dstLag := addLag(ateLag2.Name, ateLag2.MAC, lag2Members)
	config.Captures().Add().SetName("otg_cap").SetPortNames([]string{ate.Port(t, lag2Members[0]).ID()}).SetFormat(gosnappi.CaptureFormat.PCAP).SetOverwrite(true)

	addDevice := func(attributes attrs.Attributes, lag gosnappi.Lag, gateway string) (string, string) {
		device := config.Devices().Add().SetName(attributes.Name + "dev")
		ethernet := device.Ethernets().Add().SetName(attributes.Name + ".Eth").SetMac(attributes.MAC)
		ethernet.Connection().SetLagName(lag.Name())
		ipv4 := ethernet.Ipv4Addresses().Add().SetName(attributes.Name + ".IPv4")
		ipv4.SetAddress(attributes.IPv4).SetGateway(gateway).SetPrefix(uint32(attributes.IPv4Len))
		return ipv4.Name(), ipv4.Address()
	}

	srcIPv4Name, srcIPv4Address := addDevice(ateLag1, srcLag, ateLag2.IPv4)
	dstIPv4Name, dstIPv4Address := addDevice(ateLag2, dstLag, ateLag1.IPv4)

	flow := config.Flows().Add().SetName("Flow-IPv4")
	flow.Metrics().SetEnable(true)
	flow.TxRx().Device().SetTxNames([]string{srcIPv4Name}).SetRxNames([]string{dstIPv4Name})
	flow.Size().SetFixed(512)
	flow.Rate().SetPercentage(1)
	flow.Duration().FixedPackets().SetPackets(1000)
	ethernet := flow.Packet().Add().Ethernet()
	ethernet.Src().SetValue(ateLag1.MAC)
	ethernet.Dst().SetValue(ateLag2.MAC)
	ipv4 := flow.Packet().Add().Ipv4()
	ipv4.Src().SetValue(srcIPv4Address)
	ipv4.Dst().SetValue(dstIPv4Address)

	t.Logf("Pushing LAG config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	otg.StartProtocols(t)
	return config
}

func testTraffic(t *testing.T, ate *ondatra.ATEDevice, config gosnappi.Config) {
	t.Helper()
	otg := ate.OTG()
	controlState := gosnappi.NewControlState()
	controlState.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	otg.SetControlState(t, controlState)

	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(10 * time.Second)
	otg.StopTraffic(t)
	time.Sleep(time.Second)
	otgutils.LogPortMetrics(t, otg, config)
	otgutils.LogFlowMetrics(t, otg, config)

	// bytes := otg.GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(config.Ports().Items()[2].Name()))
	// file, err := os.CreateTemp(".", "pcap")
	// if err != nil {
	// 	t.Fatalf("Could not create temporary pcap file: %v", err)
	// }
	// defer os.Remove(file.Name())
	// if _, err := file.Write(bytes); err != nil {
	// 	t.Fatalf("Could not write pcap file: %v", err)
	// }
	// file.Close()

	for _, flow := range config.Flows().Items() {
		txPackets := float32(gnmi.Get(t, otg, gnmi.OTG().Flow(flow.Name()).Counters().OutPkts().State()))
		rxPackets := float32(gnmi.Get(t, otg, gnmi.OTG().Flow(flow.Name()).Counters().InPkts().State()))
		if txPackets == 0 {
			t.Errorf("Tx Packets for Flow %s: got 0, want >0", flow.Name())
			continue
		}
		if lossPct := (txPackets - rxPackets) * 100 / txPackets; lossPct > 0 {
			t.Errorf("Traffic Loss Pct for Flow %s: got %v, want 0", flow.Name(), lossPct)
		}
	}
}

func TestOTGb2bLAG(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	config := configureOTG(t, otg, ate)

	t.Logf("Verify traffic across two LAGs")
	testTraffic(t, ate, config)

}
