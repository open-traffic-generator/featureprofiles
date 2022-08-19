package one_arm_test

import (
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	otg "github.com/openconfig/ondatra/otg"
	otgtelemetry "github.com/openconfig/ondatra/telemetry/otg"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}
func configureOTGOneArm(t *testing.T, otg *otg.OTG) gosnappi.Config {
	config := otg.NewConfig(t)
	port1 := config.Ports().Add().SetName("port1")
	flow := config.Flows().Add().SetName("f1")
	flow.Metrics().SetEnable(true)
	flow.TxRx().SetChoice("port").Port().SetTxName(port1.Name())
	flow.Duration().FixedPackets().SetPackets(100)
	flow.Rate().SetPps(50)
	eth := flow.Packet().Add().Ethernet()
	eth.Dst().SetValue("00:AB:BC:AB:BC:AB")
	eth.Src().SetValue("00:CD:DC:CD:DC:CD")

	otg.PushConfig(t, config)
	return config
}

func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, c gosnappi.Config, expectedPacket uint64) {
	otg := ate.OTG()
	for _, p := range c.Ports().Items() {
		_, ok := otg.Telemetry().Port(p.Name()).Counters().OutFrames().Watch(t, time.Minute, func(val *otgtelemetry.QualifiedUint64) bool {
			return val.IsPresent() && val.Val(t) == expectedPacket
		}).Await(t)
		if !ok {
			t.Logf("Expected Tx Packets :%v, Actual: %v", expectedPacket, otg.Telemetry().Port(p.Name()).Counters().OutFrames().Get(t))
			t.Fatal("Expected Packet Mismatch!!!")
		}
	}
	for _, f := range c.Flows().Items() {
		_, ok := otg.Telemetry().Flow(f.Name()).Counters().OutPkts().Watch(t, time.Minute, func(val *otgtelemetry.QualifiedUint64) bool {
			return val.IsPresent() && val.Val(t) == expectedPacket
		}).Await(t)
		if !ok {
			t.Logf("Expected Tx Packets :%v, Actual: %v", expectedPacket, otg.Telemetry().Flow(f.Name()).Counters().OutPkts().Get(t))
			t.Fatal("Expected Packet Mismatch!!!")
		}
	}
	t.Logf("Port and Flow Metrics is Ok!!!")
}

func TestOTGOneArm(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	otgConfig := configureOTGOneArm(t, otg)

	t.Logf("Setting config")
	otg.PushConfig(t, otgConfig)

	t.Logf("Starting traffic")
	otg.StartTraffic(t)

	t.Logf("Verify traffic")
	verifyTraffic(t, ate, otgConfig, 100)

	t.Logf("Stop traffic")
	otg.StopTraffic(t)
}
