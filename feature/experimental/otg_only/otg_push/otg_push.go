package otg_push

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	otg "github.com/openconfig/ondatra/otg"
)

const (
	configFile      = "bgp.yaml"
	trafficDuration = 10 * time.Second
	tolerance       = 50
	tolerancePct    = 2
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}
func configureOTG(t *testing.T, otg *otg.OTG) gosnappi.Config {

	bytes, err := os.ReadFile(configFile)
	if err != nil {
		t.Errorf("could not read configuration file: %v", err)
		return nil
	}
	config := gosnappi.NewConfig()
	if strings.HasSuffix(configFile, "json") {
		t.Log("Feeding JSON string to gosnappi config ...")
		if err := config.Unmarshal().FromJson(string(bytes)); err != nil {
			t.Errorf("could not feed JSON to gosnappi config: %v", err)
			return nil
		}
	} else if strings.HasSuffix(configFile, "yaml") {
		t.Log("Feeding YAML string to gosnappi config ...")
		if err := config.Unmarshal().FromYaml(string(bytes)); err != nil {
			t.Errorf("could not feed YAML to gosnappi config: %v", err)
			return nil
		}

	}
	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	// time.Sleep(40 * time.Second)
	otg.StartProtocols(t)
	// time.Sleep(40 * time.Second)

	return config
}

// verifyTraffic confirms that every traffic flow has the expected amount of loss (0% or 100%
// depending on wantLoss, +- 2%).
// func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, c gosnappi.Config, wantLoss bool) {
// 	otg := ate.OTG()
// 	otgutils.LogFlowMetrics(t, otg, c)
// 	for _, f := range c.Flows().Items() {
// 		t.Logf("Verifying flow metrics for flow %s\n", f.Name())
// 		recvMetric := gnmi.Get(t, otg, gnmi.OTG().Flow(f.Name()).State())
// 		txPackets := float32(recvMetric.GetCounters().GetOutPkts())
// 		rxPackets := float32(recvMetric.GetCounters().GetInPkts())
// 		lostPackets := txPackets - rxPackets
// 		lossPct := lostPackets * 100 / txPackets
// 		if !wantLoss {
// 			if lostPackets > tolerance {
// 				t.Logf("Packets received not matching packets sent. Sent: %v, Received: %v", txPackets, rxPackets)
// 			}
// 			if lossPct > tolerancePct && txPackets > 0 {
// 				t.Errorf("Traffic Loss Pct for Flow: %s\n got %v, want max %v pct failure", f.Name(), lossPct, tolerancePct)
// 			} else {
// 				t.Logf("Traffic Test Passed! for flow %s", f.Name())
// 			}
// 		} else {
// 			if lossPct < 100-tolerancePct && txPackets > 0 {
// 				t.Errorf("Traffic is expected to fail %s\n got %v, want max %v pct failure", f.Name(), lossPct, 100-tolerancePct)
// 			} else {
// 				t.Logf("Traffic Loss Test Passed! for flow %s", f.Name())
// 			}
// 		}

// 	}
// }

// func sendTraffic(t *testing.T, otg *otg.OTG) {
// 	t.Logf("Starting traffic")
// 	otg.StartTraffic(t)
// 	time.Sleep(trafficDuration)
// 	t.Logf("Stop traffic")
// 	otg.StopTraffic(t)
// }

// func verifyOTGBGPTelemetry(t *testing.T, otg *otg.OTG, c gosnappi.Config, state string) {
// 	for _, d := range c.Devices().Items() {
// 		for _, ip := range d.Bgp().Ipv4Interfaces().Items() {
// 			for _, configPeer := range ip.Peers().Items() {
// 				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
// 				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
// 					currState, ok := val.Val()
// 					return ok && currState.String() == state
// 				}).Await(t)
// 				if !ok {
// 					fptest.LogQuery(t, "BGP reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
// 					t.Errorf("No BGP neighbor formed for peer %s", configPeer.Name())
// 				}
// 			}
// 		}
// 		for _, ip := range d.Bgp().Ipv6Interfaces().Items() {
// 			for _, configPeer := range ip.Peers().Items() {
// 				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
// 				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
// 					currState, ok := val.Val()
// 					return ok && currState.String() == state
// 				}).Await(t)
// 				if !ok {
// 					fptest.LogQuery(t, "BGP reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
// 					t.Errorf("No BGP neighbor formed for peer %s", configPeer.Name())
// 				}
// 			}
// 		}

// 	}
// }

func TestPush(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	configureOTG(t, otg)
	// Verify the OTG BGP state.
	// t.Logf("Verify OTG BGP sessions up")
	// verifyOTGBGPTelemetry(t, otg, otgConfig, "ESTABLISHED")
	// // Starting ATE Traffic and verify Traffic Flows and packet loss.
	// sendTraffic(t, otg)
	// verifyTraffic(t, ate, otgConfig, false)
}
