package ate_b2b

import (
	"testing"
	"time"

	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
)

var (
	atePort1 = attrs.Attributes{
		Name:    "atePort1",
		IPv4:    "192.0.2.2",
		IPv4Len: 24,
	}

	atePort2 = attrs.Attributes{
		Name:    "atePort2",
		IPv4:    "192.0.2.6",
		IPv4Len: 24,
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func configureATE(t *testing.T, ate *ondatra.ATEDevice) *ondatra.ATETopology {
	top := ate.Topology().New()

	p1 := ate.Port(t, "port1")
	i1 := top.AddInterface(atePort1.Name).WithPort(p1)
	i1.IPv4().
		WithAddress(atePort1.IPv4CIDR()).
		WithDefaultGateway(atePort2.IPv4)

	p2 := ate.Port(t, "port2")
	i2 := top.AddInterface(atePort2.Name).WithPort(p2)
	i2.IPv4().
		WithAddress(atePort2.IPv4CIDR()).
		WithDefaultGateway(atePort1.IPv4)

	return top
}

func testTraffic(t *testing.T, ate *ondatra.ATEDevice, top *ondatra.ATETopology, srcEndPoint *ondatra.Interface, dstEndPoint *ondatra.Interface) float32 {
	ethHeader := ondatra.NewEthernetHeader()
	ipv4Header := ondatra.NewIPv4Header()
	ipv4Header.WithSrcAddress(atePort1.IPv4).WithDstAddress(atePort2.IPv4)

	flow := ate.Traffic().NewFlow("Flow").
		WithSrcEndpoints(srcEndPoint).
		WithDstEndpoints(dstEndPoint).
		WithHeaders(ethHeader, ipv4Header)

	ate.Traffic().Start(t, flow)
	time.Sleep(15 * time.Second)
	ate.Traffic().Stop(t)

	time.Sleep(20 * time.Second)

	flowPath := ate.Telemetry().Flow(flow.Name())
	return flowPath.LossPct().Get(t)
}

func TestATEb2b(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	top := configureATE(t, ate)

	t.Logf("Setting config")
	top.Push(t).StartProtocols(t)

	t.Logf("Verify traffic")
	srcEndPoint := top.Interfaces()[atePort1.Name]
	dstEndPoint := top.Interfaces()[atePort2.Name]

	// Verify that there should be no traffic loss
	loss := testTraffic(t, ate, top, srcEndPoint, dstEndPoint)
	if loss > 0.5 {
		t.Errorf("Loss: got %g, want < 0.5", loss)
	}

}
