// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otgutils

import (
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ygnmi/ygnmi"
)

const (
	timeout = 1 * time.Minute
)

// TrafficTestParams encapsulates the parameters required for traffic tests, including the OTG configuration and the ATE device.
type TrafficTestParams struct {
	Config gosnappi.Config
	Ate    *ondatra.ATEDevice
}

// WaitForTxPacketsReceived waits for the transmitted and received packet counts for each flow match, indicating that traffic has converged.
func WaitForTxPacketsReceived(t *testing.T, params TrafficTestParams) {
	t.Helper()
	otg := params.Ate.OTG()
	t.Log("Waiting for the TxPackets to arrive at Rx")

	for _, f := range params.Config.Flows().Items() {
		flowName := f.Name()

		inPktsPath := gnmi.OTG().Flow(flowName).Counters().InPkts().State()

		gnmi.Watch(t, otg, inPktsPath, timeout, func(v *ygnmi.Value[uint64]) bool {
			rxPkts, present := v.Val()
			if !present {
				return false
			}

			flowMetrics := gnmi.Get(t, otg, gnmi.OTG().Flow(flowName).State())
			txPkts := flowMetrics.GetCounters().GetOutPkts()

			return txPkts > 0 && rxPkts == txPkts
		}).Await(t)
	}
}