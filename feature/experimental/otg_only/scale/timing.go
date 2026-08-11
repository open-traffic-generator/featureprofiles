package scale

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// API call timing
//
// Every API call is timed, so a run shows where its wall clock went. One-shot
// calls get a ">>> OTG API" line as they happen; the fetches inside the poll
// loops are aggregated (count / total / avg / min / max) into the per-iteration
// table. Calls made before the loop are cleared by the per-iteration Reset and
// appear only in their own log lines.
// ---------------------------------------------------------------------------

// Labels for the timed calls; where the ondatra name differs from the OTG API
// it drives, both are given.
const (
	APISetConfig      = "PushConfig [SetConfig]"
	APIPortReboot     = "SetControlAction [port reboot]"
	APIStartProtocols = "StartProtocols"
	APIStopProtocols  = "StopProtocols"
	APIStartTraffic   = "StartTraffic [SetTransmitState:start]"
	APIStopTraffic    = "StopTraffic [SetTransmitState:stop]"
	APIGetBGPStates   = "GetMetrics: BGP session state"
	APIGetBGPCounters = "GetMetrics: BGP peer counters"
	APIGetFlowMetrics = "GetMetrics: flow metrics"
	APIGetPortState   = "GetMetrics: port / neighbor state"
	APIGetPortLink    = "GetMetrics: port link (reboot wait)"

	// Chassis-side calls, timed alongside the OTG ones.
	APIChassisDiscover = "chassis SSH+REST: port discovery"
	APIChassisPortInfo = "chassis REST: port memory / PCPU"
	APIChassisPerf     = "chassis REST: chassis CPU / memory"
)

// callStat aggregates every duration recorded under one label.
type callStat struct {
	calls    int
	total    time.Duration
	min, max time.Duration
}

func (s callStat) avg() time.Duration {
	if s.calls == 0 {
		return 0
	}
	return s.total / time.Duration(s.calls)
}

// APITimings records OTG API call durations for one iteration, in the order the
// labels were first seen.
type APITimings struct {
	order []string
	stat  map[string]*callStat
}

// APITime is the timer shared by this package and the tests using it, so one
// table covers both the OTG calls a test makes and the chassis calls made here.
var APITime = NewAPITimings()

func NewAPITimings() *APITimings {
	return &APITimings{stat: map[string]*callStat{}}
}

// Reset drops everything recorded so far, so each iteration reports its own
// timings rather than the run's running total.
func (a *APITimings) Reset() {
	a.order = nil
	a.stat = map[string]*callStat{}
}

// record files one duration under label and returns it unchanged.
func (a *APITimings) record(label string, d time.Duration) time.Duration {
	s, ok := a.stat[label]
	if !ok {
		s = &callStat{min: d, max: d}
		a.stat[label] = s
		a.order = append(a.order, label)
	}
	s.calls++
	s.total += d
	if d < s.min {
		s.min = d
	}
	if d > s.max {
		s.max = d
	}
	return d
}

// call runs a one-shot OTG API call, records how long it took and highlights it
// in the log. Use track for calls made once per poll, which would flood the log
// at scale.
func (a *APITimings) Call(t *testing.T, label string, fn func()) time.Duration {
	t.Helper()
	start := time.Now()
	fn()
	d := a.record(label, time.Since(start))
	t.Logf(">>> OTG API | %-38s %14v", label, d.Round(time.Millisecond))
	return d
}

// track records a duration the caller measured itself, without logging it, and
// returns it so the caller can fold it into its own log line.
func (a *APITimings) Track(label string, start time.Time) time.Duration {
	return a.record(label, time.Since(start))
}

// String renders the recorded timings as a log block. when labels the scope the
// numbers cover, e.g. "iteration 1/3, 1000 sessions/port".
func (a *APITimings) String(when string) string {
	border := strings.Repeat("-", 100)
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tAPI call timings (%s)\n%s\n", when, border)
	fmt.Fprintf(&b, "\t\t%-38s %6s %14s %14s %14s %14s\n",
		"API call", "calls", "total", "avg", "min", "max")
	if len(a.order) == 0 {
		fmt.Fprintf(&b, "\t\tno API calls recorded\n%s\n", border)
		return b.String()
	}
	var grand time.Duration
	for _, label := range a.order {
		s := a.stat[label]
		grand += s.total
		fmt.Fprintf(&b, "\t\t%-38s %6d %14v %14v %14v %14v\n", label, s.calls,
			s.total.Round(time.Millisecond), s.avg().Round(time.Millisecond),
			s.min.Round(time.Millisecond), s.max.Round(time.Millisecond))
	}
	fmt.Fprintf(&b, "%s\n", border)
	fmt.Fprintf(&b, "\t\t%-38s %6s %14v\n", "total time in OTG API calls", "", grand.Round(time.Millisecond))
	fmt.Fprintf(&b, "%s\n", border)
	return b.String()
}
