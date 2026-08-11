package scale

import (
	"testing"
	"time"

	"github.com/openconfig/ondatra/gnmi"
	otg "github.com/openconfig/ondatra/otg"
)

// ---------------------------------------------------------------------------
// Data-plane flow telemetry
//
// Fetching only. The tolerances, and what counts as a passing flow, stay with
// the test.
// ---------------------------------------------------------------------------

// AwaitFlowsStopped polls until every flow has stopped and sent its full packet
// count. Flows are queried by name and dropped from the set once done, so the
// per-poll cost falls as flows finish. It reports an error rather than failing
// fatally on timeout, leaving the test to decide what to do next.
func AwaitFlowsStopped(t *testing.T, otgDev *otg.OTG, flowNames []string, wantPkts uint64, timeout time.Duration) {
	t.Helper()
	pending := make(map[string]bool, len(flowNames))
	for _, n := range flowNames {
		pending[n] = true
	}
	total := len(flowNames)
	deadline := time.Now().Add(timeout)
	start := time.Now()

	for len(pending) > 0 {
		var txSoFar uint64
		stillRunning, shortTx := 0, 0
		polled := len(pending)
		fetchStart := time.Now()
		for name := range pending {
			m, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().Flow(name).State()).Val()
			if !ok {
				continue
			}
			tx := m.GetCounters().GetOutPkts()
			txSoFar += tx
			transmitting := m.GetTransmit()
			if transmitting {
				stillRunning++
			}
			if tx < wantPkts {
				shortTx++
			}
			if !transmitting && tx >= wantPkts {
				delete(pending, name)
			}
		}
		fetchTook := APITime.Track(APIGetFlowMetrics, fetchStart)
		t.Logf("[t+%-6v] flows finished transmitting: %d/%d (still transmitting: %d, below %d packets: %d, tx on pending flows: %d) | GetMetrics: %d flows in %v",
			time.Since(start).Truncate(time.Second), total-len(pending), total, stillRunning, wantPkts, shortTx, txSoFar,
			polled, fetchTook.Round(time.Millisecond))
		if len(pending) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("timed out after %v waiting for flows to finish transmitting: %d/%d still not done",
				timeout, len(pending), total)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// FlowStat is one flow's transmitted and received packet counts.
type FlowStat struct {
	Name   string
	Tx, Rx uint64
}

// FlowCounters reads the final counters of every named flow, in the order given.
func FlowCounters(t *testing.T, otgDev *otg.OTG, flowNames []string) []FlowStat {
	t.Helper()
	stats := make([]FlowStat, 0, len(flowNames))
	for _, name := range flowNames {
		m := gnmi.Get(t, otgDev, gnmi.OTG().Flow(name).State())
		stats = append(stats, FlowStat{
			Name: name,
			Tx:   m.GetCounters().GetOutPkts(),
			Rx:   m.GetCounters().GetInPkts(),
		})
	}
	return stats
}
