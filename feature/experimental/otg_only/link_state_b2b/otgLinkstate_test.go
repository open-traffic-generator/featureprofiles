package linkstate_b2b

import (
	//"os"

	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
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
	atePort3 = attrs.Attributes{
		Name:    "atePort3",
		MAC:     "02:00:01:01:01:02",
		IPv4:    "192.0.2.2",
		IPv6:    "2001:db8::192:0:2:2",
		IPv4Len: 24,
		IPv6Len: 126,
	}

	atePort4 = attrs.Attributes{
		Name:    "atePort4",
		MAC:     "02:00:02:01:01:02",
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
	srcPort1 := config.Ports().Add().SetName("port3")
	dstPort1 := config.Ports().Add().SetName("port4")
	// config.Captures().Add().
	// 	SetName("otg_cap").
	// 	SetPortNames([]string{dstPort.Name()}).
	// 	SetFormat(gosnappi.CaptureFormat.PCAP).SetOverwrite(true)

	srcDev := config.Devices().Add().SetName(atePort1.Name)
	srcEth := srcDev.Ethernets().Add().SetName(atePort1.Name + ".Eth").SetMac(atePort1.MAC)
	srcEth.Connection().SetPortName(srcPort.Name())
	srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4")
	srcIpv4.SetAddress(atePort1.IPv4).SetGateway(atePort2.IPv4).SetPrefix(uint32(atePort1.IPv4Len))
	srcIpv6 := srcEth.Ipv6Addresses().Add().SetName(atePort1.Name + ".IPv6")
	srcIpv6.SetAddress(atePort1.IPv6).SetGateway(atePort2.IPv6).SetPrefix(uint32(atePort1.IPv6Len))

	dstDev := config.Devices().Add().SetName(atePort2.Name)
	dstEth := dstDev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	dstEth.Connection().SetPortName(dstPort.Name())
	dstIpv4 := dstEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	dstIpv4.SetAddress(atePort2.IPv4).SetGateway(atePort1.IPv4).SetPrefix(uint32(atePort2.IPv4Len))
	dstIpv6 := dstEth.Ipv6Addresses().Add().SetName(atePort2.Name + ".IPv6")
	dstIpv6.SetAddress(atePort2.IPv6).SetGateway(atePort1.IPv6).SetPrefix(uint32(atePort2.IPv6Len))

	srcDev1 := config.Devices().Add().SetName(atePort3.Name)
	srcEth1 := srcDev1.Ethernets().Add().SetName(atePort3.Name + ".Eth").SetMac(atePort3.MAC)
	srcEth1.Connection().SetPortName(srcPort1.Name())
	srcIpv41 := srcEth.Ipv4Addresses().Add().SetName(atePort3.Name + ".IPv4")
	srcIpv41.SetAddress(atePort3.IPv4).SetGateway(atePort4.IPv4).SetPrefix(uint32(atePort3.IPv4Len))
	srcIpv61 := srcEth1.Ipv6Addresses().Add().SetName(atePort3.Name + ".IPv6")
	srcIpv61.SetAddress(atePort3.IPv6).SetGateway(atePort4.IPv6).SetPrefix(uint32(atePort3.IPv6Len))

	dstDev1 := config.Devices().Add().SetName(atePort4.Name)
	dstEth1 := dstDev1.Ethernets().Add().SetName(atePort4.Name + ".Eth").SetMac(atePort4.MAC)
	dstEth1.Connection().SetPortName(dstPort1.Name())
	dstIpv41 := dstEth1.Ipv4Addresses().Add().SetName(atePort4.Name + ".IPv4")
	dstIpv41.SetAddress(atePort4.IPv4).SetGateway(atePort3.IPv4).SetPrefix(uint32(atePort4.IPv4Len))
	dstIpv61 := dstEth1.Ipv6Addresses().Add().SetName(atePort4.Name + ".IPv6")
	dstIpv61.SetAddress(atePort4.IPv6).SetGateway(atePort3.IPv6).SetPrefix(uint32(atePort4.IPv6Len))

	// ATE Traffic Configuration
	flowipv4 := config.Flows().Add().SetName("Flow-IPv4")
	flowipv4.Metrics().SetEnable(true)
	flowipv4.TxRx().Device().
		SetTxNames([]string{srcIpv4.Name()}).SetRxNames([]string{dstIpv4.Name()})
	flowipv4.Size().SetFixed(512)
	flowipv4.Rate().SetPercentage(1)
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

func TestOTGLink(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	otgConfig := configureOTG(t, otg)
	// configureOTG(t, otg)

	portStateAction := gosnappi.NewControlState()
	portStateAction.Port().Link().SetPortNames([]string{"port1"}).SetState(gosnappi.StatePortLinkState.DOWN)
	ate.OTG().SetControlState(t, portStateAction)

	portStateAction2 := gosnappi.NewControlState()
	portStateAction2.Port().Link().SetPortNames([]string{"port3"}).SetState(gosnappi.StatePortLinkState.DOWN)
	ate.OTG().SetControlState(t, portStateAction2)

	startTime := time.Now()
	gnmi.Get(t, otg, gnmi.OTG().Port("port1").State())

	gnmi.Watch(t, otg, gnmi.OTG().Port("port2").Link().State(), 30*time.Second, func(val *ygnmi.Value[otgtelemetry.E_Port_Link]) bool {
		linkState, present := val.Val()
		t.Logf("link state on port 2 is %s", linkState.String())
		return present && linkState == otgtelemetry.Port_Link_DOWN
	}).Await(t)
	gnmi.Watch(t, otg, gnmi.OTG().Port("port4").Link().State(), 30*time.Second, func(val *ygnmi.Value[otgtelemetry.E_Port_Link]) bool {
		linkState, present := val.Val()
		t.Logf("link state on port 4 is %s", linkState.String())
		return present && linkState == otgtelemetry.Port_Link_DOWN
	}).Await(t)

	newTime := time.Since(startTime)

	t.Logf("time took for the link to go down %s", newTime)

	otgConfig.Flows().Clear()
	otg.PushConfig(t, otgConfig)
	otg.StartProtocols(t)

	gnmi.Watch(t, otg, gnmi.OTG().Port("port1").Link().State(), 30*time.Second, func(val *ygnmi.Value[otgtelemetry.E_Port_Link]) bool {
		linkState, present := val.Val()
		t.Logf("link state on port 1 is %s", linkState.String())
		return present && linkState == otgtelemetry.Port_Link_UP
	}).Await(t)
	gnmi.Watch(t, otg, gnmi.OTG().Port("port2").Link().State(), 30*time.Second, func(val *ygnmi.Value[otgtelemetry.E_Port_Link]) bool {
		linkState, present := val.Val()
		t.Logf("link state on port 2 is %s", linkState.String())
		return present && linkState == otgtelemetry.Port_Link_UP
	}).Await(t)
	gnmi.Watch(t, otg, gnmi.OTG().Port("port3").Link().State(), 30*time.Second, func(val *ygnmi.Value[otgtelemetry.E_Port_Link]) bool {
		linkState, present := val.Val()
		t.Logf("link state on port 3 is %s", linkState.String())
		return present && linkState == otgtelemetry.Port_Link_UP
	}).Await(t)
	gnmi.Watch(t, otg, gnmi.OTG().Port("port4").Link().State(), 30*time.Second, func(val *ygnmi.Value[otgtelemetry.E_Port_Link]) bool {
		linkState, present := val.Val()
		t.Logf("link state on port 4 is %s", linkState.String())
		return present && linkState == otgtelemetry.Port_Link_UP
	}).Await(t)

	portStateAction.Port().Link().SetPortNames([]string{"port1"}).SetState(gosnappi.StatePortLinkState.UP)
	defer ate.OTG().SetControlState(t, portStateAction)
	portStateAction2.Port().Link().SetPortNames([]string{"port3"}).SetState(gosnappi.StatePortLinkState.UP)
	defer ate.OTG().SetControlState(t, portStateAction2)

}
