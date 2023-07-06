package ate_b2b

import (
	"testing"
	"time"

	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
)

var (
	atePort1 = attrs.Attributes{
		Name:    "atePort1",
		IPv4:    "192.0.2.2",
		IPv6:    "2001:db8::192:0:2:2",
		IPv4Len: 24,
		IPv6Len: 126,
	}

	atePort2 = attrs.Attributes{
		Name:    "atePort2",
		IPv4:    "192.0.2.1",
		IPv6:    "2001:db8::192:0:2:1",
		IPv4Len: 24,
		IPv6Len: 126,
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func configureATE(t *testing.T, ate *ondatra.ATEDevice) []*ondatra.Flow {
	top := ate.Topology().New()

	p1 := ate.Port(t, "port1")
	i1 := top.AddInterface(atePort1.Name).WithPort(p1)
	i1.IPv4().WithAddress(atePort1.IPv4CIDR()).WithDefaultGateway(atePort2.IPv4)
	i1.IPv6().WithAddress(atePort1.IPv6CIDR()).WithDefaultGateway(atePort2.IPv6)

	p2 := ate.Port(t, "port2")
	i2 := top.AddInterface(atePort2.Name).WithPort(p2)
	i2.IPv4().WithAddress(atePort2.IPv4CIDR()).WithDefaultGateway(atePort1.IPv4)
	i2.IPv6().WithAddress(atePort2.IPv6CIDR()).WithDefaultGateway(atePort1.IPv6)

	top.Push(t)
	time.Sleep(10 * time.Second)
	top.StartProtocols(t)

	ethHeader := ondatra.NewEthernetHeader()
	ipv4Header := ondatra.NewIPv4Header()
	ipv6Header := ondatra.NewIPv6Header()

	flowipv4 := ate.Traffic().NewFlow("Flow-IPv4").WithSrcEndpoints(i1).WithDstEndpoints(i2).WithHeaders(ethHeader, ipv4Header)
	flowipv4.WithFrameRatePct(1).WithFrameSize(512)
	flowipv6 := ate.Traffic().NewFlow("Flow-IPv6").WithSrcEndpoints(i1).WithDstEndpoints(i2).WithHeaders(ethHeader, ipv6Header)
	flowipv6.WithFrameRatePct(1).WithFrameSize(512)

	return []*ondatra.Flow{flowipv4, flowipv6}

}

func testTraffic(t *testing.T, ate *ondatra.ATEDevice, allFlows []*ondatra.Flow) {

	trafficDuration := 10 * time.Second
	t.Logf("Running traffic for %v seconds", trafficDuration)
	ate.Traffic().Start(t, allFlows...)
	time.Sleep(trafficDuration)
	ate.Traffic().Stop(t)

	for _, flow := range allFlows {
		t.Logf("%v tx packets %v", flow.Name(), gnmi.Get(t, ate, gnmi.OC().Flow(flow.Name()).Counters().OutPkts().State()))
		t.Logf("%v rx packets %v", flow.Name(), gnmi.Get(t, ate, gnmi.OC().Flow(flow.Name()).Counters().InPkts().State()))
		lossPct := gnmi.Get(t, ate, gnmi.OC().Flow(flow.Name()).LossPct().State())
		if lossPct > 0 {
			t.Errorf("Traffic Loss Pct for Flow: %s\n got %v, want 0", flow.Name(), lossPct)
		} else {
			t.Logf("Traffic for flow %s Passed!", flow.Name())
		}
	}

}

func TestATEb2b(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	allFlows := configureATE(t, ate)
	t.Logf("Verify traffic")
	testTraffic(t, ate, allFlows)
}
