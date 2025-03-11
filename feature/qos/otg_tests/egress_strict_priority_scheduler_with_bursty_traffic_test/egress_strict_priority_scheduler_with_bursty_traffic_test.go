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

package egress_strict_priority_scheduler_with_bursty_traffic_test

import (
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/featureprofiles/internal/qoscfg"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/netutil"
	"github.com/openconfig/ygot/ygot"
)

var (
	dutIngressPort1AteP1 = attrs.Attributes{IPv4: "198.51.100.1", IPv4Len: 30, IPv6: "2001::1", IPv6Len: 126}
	dutIngressPort2AteP2 = attrs.Attributes{IPv4: "198.51.100.5", IPv4Len: 30, IPv6: "2001::5", IPv6Len: 126}
	dutEgressPort3AteP3  = attrs.Attributes{IPv4: "198.51.100.9", IPv4Len: 30, IPv6: "2001::9", IPv6Len: 126}

	ateTxP1 = attrs.Attributes{Name: "ate1", MAC: "0f:99:f6:9c:81:01", IPv4: "198.51.100.2", IPv4Len: 30, IPv6: "2001::2", IPv6Len: 126}
	ateTxP2 = attrs.Attributes{Name: "ate2", MAC: "0f:99:f6:9c:81:02", IPv4: "198.51.100.6", IPv4Len: 30, IPv6: "2001::6", IPv6Len: 126}
	ateRxP3 = attrs.Attributes{Name: "ate3", MAC: "0f:99:f6:9c:81:03", IPv4: "198.51.100.10", IPv4Len: 30, IPv6: "2001::10", IPv6Len: 126}
)

type trafficData struct {
	trafficRate           float64
	expectedThroughputPct float32
	frameSize             uint32
	dscp                  uint8
	queue                 string
	inputIntf             attrs.Attributes
	burstPackets          uint32
	burstMinGap           uint32
	burstGap              uint32
}

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func TestEgressStrictPrioritySchedulerBurstTrafficIPv4(t *testing.T) {

	dut := ondatra.DUT(t, "dut")
	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")

	// Configure DUT interfaces and QoS.
	ConfigureDUTIntfIPv4(t, dut)
	switch dut.Vendor() {
	case ondatra.CISCO:
		ConfigureCiscoQoSIPv4(t, dut)
	default:
		ConfigureDUTQoSIPv4(t, dut)
	}

	// Configure ATE interfaces.
	ate := ondatra.ATE(t, "ate")
	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	ap3 := ate.Port(t, "port3")
	top := gosnappi.NewConfig()

	ateTxP1.AddToOTG(top, ap1, &dutIngressPort1AteP1)
	ateTxP2.AddToOTG(top, ap2, &dutIngressPort2AteP2)
	ateRxP3.AddToOTG(top, ap3, &dutEgressPort3AteP3)
	ate.OTG().PushConfig(t, top)

	createTrafficFlows(t, ate, top, dut)
	t.Run("Running test", func(t *testing.T) {

		ate.OTG().StartProtocols(t)
		otgutils.WaitForARP(t, ate.OTG(), top, "IPv4")

		t.Logf("Running traffic 1 on DUT interfaces: %s => %s \n", dp1.Name(), dp3.Name())
		t.Logf("Running traffic 2 on DUT interfaces: %s => %s \n", dp2.Name(), dp3.Name())
		t.Logf("Sending traffic flows:\n")
		time.Sleep(10 * time.Second)
		ate.OTG().StartTraffic(t)
		time.Sleep(30 * time.Second)
		ate.OTG().StopTraffic(t)
		time.Sleep(10 * time.Second)

		otgutils.LogFlowMetrics(t, ate.OTG(), top)
		otgutils.LogPortMetrics(t, ate.OTG(), top)

		queues := netutil.CommonTrafficQueues(t, dut)
		nc1drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.NC1).DroppedPkts().State())
		af4drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF4).DroppedPkts().State())
		af3drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF3).DroppedPkts().State())
		af2drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF2).DroppedPkts().State())
		af1drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF1).DroppedPkts().State())
		be1drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.BE1).DroppedPkts().State())

		t.Logf("Dropped pkts on NC1: %d ", nc1drops)
		t.Logf("Dropped pkts on AF4: %d ", af4drops)
		t.Logf("Dropped pkts on AF3: %d ", af3drops)
		t.Logf("Dropped pkts on AF2: %d ", af2drops)
		t.Logf("Dropped pkts on AF1: %d ", af1drops)
		t.Logf("Dropped pkts on BE1: %d ", be1drops)

	})

}

func TestEgressStrictPrioritySchedulerBurstTrafficIPv6(t *testing.T) {

	dut := ondatra.DUT(t, "dut")
	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")

	// Configure DUT interfaces and QoS.
	ConfigureDUTIntfIPv4(t, dut)
	switch dut.Vendor() {
	case ondatra.CISCO:
		ConfigureCiscoQoSIPv6(t, dut)
	default:
		ConfigureDUTQoSIPv6(t, dut)
	}

	// Configure ATE interfaces.
	ate := ondatra.ATE(t, "ate")
	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	ap3 := ate.Port(t, "port3")
	top := gosnappi.NewConfig()

	ateTxP1.AddToOTG(top, ap1, &dutIngressPort1AteP1)
	ateTxP2.AddToOTG(top, ap2, &dutIngressPort2AteP2)
	ateRxP3.AddToOTG(top, ap3, &dutEgressPort3AteP3)
	ate.OTG().PushConfig(t, top)

	createTrafficFlows(t, ate, top, dut)
	t.Run("Running test", func(t *testing.T) {

		ate.OTG().StartProtocols(t)
		otgutils.WaitForARP(t, ate.OTG(), top, "IPv6")

		t.Logf("Running traffic 1 on DUT interfaces: %s => %s \n", dp1.Name(), dp3.Name())
		t.Logf("Running traffic 2 on DUT interfaces: %s => %s \n", dp2.Name(), dp3.Name())
		t.Logf("Sending traffic flows:\n")
		time.Sleep(10 * time.Second)
		ate.OTG().StartTraffic(t)
		time.Sleep(30 * time.Second)
		ate.OTG().StopTraffic(t)
		time.Sleep(10 * time.Second)

		otgutils.LogFlowMetrics(t, ate.OTG(), top)
		otgutils.LogPortMetrics(t, ate.OTG(), top)

		queues := netutil.CommonTrafficQueues(t, dut)
		nc1drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.NC1).DroppedPkts().State())
		af4drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF4).DroppedPkts().State())
		af3drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF3).DroppedPkts().State())
		af2drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF2).DroppedPkts().State())
		af1drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.AF1).DroppedPkts().State())
		be1drops := gnmi.Get(t, dut, gnmi.OC().Qos().Interface(dp3.Name()).Output().Queue(queues.BE1).DroppedPkts().State())

		t.Logf("Dropped pkts on NC1: %d ", nc1drops)
		t.Logf("Dropped pkts on AF4: %d ", af4drops)
		t.Logf("Dropped pkts on AF3: %d ", af3drops)
		t.Logf("Dropped pkts on AF2: %d ", af2drops)
		t.Logf("Dropped pkts on AF1: %d ", af1drops)
		t.Logf("Dropped pkts on BE1: %d ", be1drops)

	})

}

func createTrafficFlows(t *testing.T, ate *ondatra.ATEDevice, top gosnappi.Config, dut *ondatra.DUTDevice) {
	t.Helper()
	// configuration of regular and burst flows on the ATE
	/*
		Non-burst flows on ateTxP1:

		Forwarding Group	Traffic linerate (%)	Frame size	Expected Loss %
		be1					12						512			100
		af1					12						512			100
		af2					15						512			50
		af3					12						512			0
		af4					30						512			0
		nc1					1						512			0

		Burst flows on ateTxP2:

		Fwd Grp    | Traffic linerate (%)   | FS         | Burst         | IPG           | IBG             | Expected loss (%)
		be1        | 20                     | 256        | 50000         | 12            | 100             | 100
		af1        | 13                     | 256        | 50000         | 12            | 100             | 100
		af2        | 17                     | 256        | 50000         | 12            | 100             | 50
		af3        | 10                     | 256        | 50000         | 12            | 100             | 0
		af4        | 20                     | 256        | 50000         | 12            | 100             | 0
		nc1        | 10                     | 256        | 50000         | 12            | 100             | 0
	*/

	queues := netutil.CommonTrafficQueues(t, dut)
	trafficFlows := map[string]*trafficData{
		"ateTxP1-regular-nc1": {
			frameSize:             512,
			trafficRate:           1,
			expectedThroughputPct: 100.0,
			dscp:                  6,
			queue:                 queues.NC1,
			inputIntf:             ateTxP1,
		},
		"ateTxP2-burst-nc1": {
			frameSize:             256,
			trafficRate:           10,
			dscp:                  7,
			expectedThroughputPct: 100.0,
			queue:                 queues.NC1,
			inputIntf:             ateTxP2,
			burstPackets:          50000,
			burstMinGap:           12,
			burstGap:              100,
		},
		"ateTxP1-regular-af4": {
			frameSize:             512,
			trafficRate:           30,
			expectedThroughputPct: 100.0,
			dscp:                  4,
			queue:                 queues.AF4,
			inputIntf:             ateTxP1,
		},
		"ateTxP2-burst-af4": {
			frameSize:             256,
			trafficRate:           20,
			dscp:                  5,
			expectedThroughputPct: 100.0,
			queue:                 queues.AF4,
			inputIntf:             ateTxP2,
			burstPackets:          50000,
			burstMinGap:           12,
			burstGap:              100,
		},
		"ateTxP1-regular-af3": {
			frameSize:             512,
			trafficRate:           12,
			expectedThroughputPct: 100.0,
			dscp:                  3,
			queue:                 queues.AF3,
			inputIntf:             ateTxP1,
		},
		"ateTxP2-burst-af3": {
			frameSize:             256,
			trafficRate:           10,
			dscp:                  3,
			expectedThroughputPct: 100.0,
			queue:                 queues.AF3,
			inputIntf:             ateTxP2,
			burstPackets:          50000,
			burstMinGap:           12,
			burstGap:              100,
		},
		"ateTxP1-regular-af2": {
			frameSize:             512,
			trafficRate:           15,
			expectedThroughputPct: 50.0,
			dscp:                  2,
			queue:                 queues.AF2,
			inputIntf:             ateTxP1,
		},
		"ateTxP2-burst-af2": {
			frameSize:             256,
			trafficRate:           17,
			dscp:                  2,
			expectedThroughputPct: 50.0,
			queue:                 queues.AF2,
			inputIntf:             ateTxP2,
			burstPackets:          50000,
			burstMinGap:           12,
			burstGap:              100,
		},
		"ateTxP1-regular-af1": {
			frameSize:             512,
			trafficRate:           12,
			expectedThroughputPct: 0.0,
			dscp:                  1,
			queue:                 queues.AF1,
			inputIntf:             ateTxP1,
		},
		"ateTxP2-burst-af1": {
			frameSize:             256,
			trafficRate:           13,
			dscp:                  1,
			expectedThroughputPct: 0.0,
			queue:                 queues.AF1,
			inputIntf:             ateTxP2,
			burstPackets:          50000,
			burstMinGap:           12,
			burstGap:              100,
		},
		"ateTxP1-regular-be1": {
			frameSize:             512,
			trafficRate:           12,
			expectedThroughputPct: 0.0,
			dscp:                  0,
			queue:                 queues.BE1,
			inputIntf:             ateTxP1,
		},
		"ateTxP2-burst-be1": {
			frameSize:             512,
			trafficRate:           20,
			expectedThroughputPct: 0.0,
			dscp:                  0,
			queue:                 queues.BE1,
			inputIntf:             ateTxP2,
			burstPackets:          50000,
			burstMinGap:           12,
			burstGap:              100,
		},
	}
	top.Flows().Clear()

	for trafficID, data := range trafficFlows {
		t.Logf("Configuring flow %s", trafficID)
		flow := top.Flows().Add().SetName(trafficID)
		flow.Metrics().SetEnable(true)
		flow.TxRx().Device().SetTxNames([]string{data.inputIntf.Name + ".IPv4"}).SetRxNames([]string{ateRxP3.Name + ".IPv4"})
		ethHeader := flow.Packet().Add().Ethernet()
		ethHeader.Src().SetValue(data.inputIntf.MAC)

		ipHeader := flow.Packet().Add().Ipv4()
		ipHeader.Src().SetValue(data.inputIntf.IPv4)
		ipHeader.Dst().SetValue(ateRxP3.IPv4)
		ipHeader.Priority().Dscp().Phb().SetValue(uint32(data.dscp))

		flow.Size().SetFixed(uint32(data.frameSize))
		flow.Rate().SetPercentage(float32(data.trafficRate))
		if data.burstMinGap > 0 {
			flow.Duration().Burst().SetPackets(uint32(data.burstPackets)).SetGap(uint32(data.burstMinGap))
		}
		if data.burstGap > 0 {
			flow.Duration().Burst().InterBurstGap().SetBytes(float64(data.burstGap))
		}

	}
	ate.OTG().PushConfig(t, top)
}

func ConfigureCiscoQoSIPv4(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
}

func ConfigureCiscoQoSIPv6(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
}

func ConfigureDUTIntfIPv4(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")

	dutIntfs := []struct {
		desc      string
		intfName  string
		ipAddr    string
		prefixLen uint8
	}{{
		desc:      "DUT input intf port1",
		intfName:  dp1.Name(),
		ipAddr:    dutIngressPort1AteP1.IPv4,
		prefixLen: dutIngressPort1AteP1.IPv4Len,
	}, {
		desc:      "DUT input intf port2",
		intfName:  dp2.Name(),
		ipAddr:    dutIngressPort2AteP2.IPv4,
		prefixLen: dutIngressPort1AteP1.IPv4Len,
	}, {
		desc:      "DUT output intf port3",
		intfName:  dp3.Name(),
		ipAddr:    dutEgressPort3AteP3.IPv4,
		prefixLen: dutIngressPort1AteP1.IPv4Len,
	}}

	// Configure the interfaces.
	for _, intf := range dutIntfs {
		t.Logf("Configure DUT interface %s with attributes %v", intf.intfName, intf)
		i := &oc.Interface{
			Name:        ygot.String(intf.intfName),
			Description: ygot.String(intf.desc),
			Type:        oc.IETFInterfaces_InterfaceType_ethernetCsmacd,
			Enabled:     ygot.Bool(true),
		}
		i.GetOrCreateEthernet()
		s := i.GetOrCreateSubinterface(0).GetOrCreateIpv4()
		if deviations.InterfaceEnabled(dut) && !deviations.IPv4MissingEnabled(dut) {
			s.Enabled = ygot.Bool(true)
			t.Logf("DUT %s %s %s requires interface enable deviation ", dut.Vendor(), dut.Model(), dut.Version())
		}
		a := s.GetOrCreateAddress(intf.ipAddr)
		a.PrefixLength = ygot.Uint8(intf.prefixLen)
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf.intfName).Config(), i)
		if deviations.ExplicitInterfaceInDefaultVRF(dut) {
			fptest.AssignToNetworkInstance(t, dut, intf.intfName, deviations.DefaultNetworkInstance(dut), 0)
			t.Logf("DUT %s %s %s requires explicit interface in default VRF deviation ", dut.Vendor(), dut.Model(), dut.Version())
		}
	}
	if deviations.ExplicitPortSpeed(dut) {
		fptest.SetPortSpeed(t, dp1)
		fptest.SetPortSpeed(t, dp2)
		fptest.SetPortSpeed(t, dp3)
		t.Logf("DUT %s %s %s requires explicit port speed set deviation ", dut.Vendor(), dut.Model(), dut.Version())
	}
}

func ConfigureDUTIntfIPv6(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")

	dutIntfs := []struct {
		desc      string
		intfName  string
		ipAddr    string
		prefixLen uint8
	}{{
		desc:      "DUT input intf port1",
		intfName:  dp1.Name(),
		ipAddr:    dutIngressPort1AteP1.IPv6,
		prefixLen: dutIngressPort1AteP1.IPv6Len,
	}, {
		desc:      "DUT input intf port2",
		intfName:  dp2.Name(),
		ipAddr:    dutIngressPort2AteP2.IPv6,
		prefixLen: dutIngressPort1AteP1.IPv6Len,
	}, {
		desc:      "DUT output intf port3",
		intfName:  dp3.Name(),
		ipAddr:    dutEgressPort3AteP3.IPv6,
		prefixLen: dutIngressPort1AteP1.IPv6Len,
	}}

	// Configure the interfaces.
	for _, intf := range dutIntfs {
		t.Logf("Configure DUT interface %s with attributes %v", intf.intfName, intf)
		i := &oc.Interface{
			Name:        ygot.String(intf.intfName),
			Description: ygot.String(intf.desc),
			Type:        oc.IETFInterfaces_InterfaceType_ethernetCsmacd,
			Enabled:     ygot.Bool(true),
		}
		i.GetOrCreateEthernet()
		s := i.GetOrCreateSubinterface(0).GetOrCreateIpv6()
		a := s.GetOrCreateAddress(intf.ipAddr)
		a.PrefixLength = ygot.Uint8(intf.prefixLen)
		gnmi.Replace(t, dut, gnmi.OC().Interface(intf.intfName).Config(), i)
		if deviations.ExplicitInterfaceInDefaultVRF(dut) {
			fptest.AssignToNetworkInstance(t, dut, intf.intfName, deviations.DefaultNetworkInstance(dut), 0)
			t.Logf("DUT %s %s %s requires explicit interface in default VRF deviation ", dut.Vendor(), dut.Model(), dut.Version())
		}
	}
	if deviations.ExplicitPortSpeed(dut) {
		fptest.SetPortSpeed(t, dp1)
		fptest.SetPortSpeed(t, dp2)
		fptest.SetPortSpeed(t, dp3)
		t.Logf("DUT %s %s %s requires explicit port speed set deviation ", dut.Vendor(), dut.Model(), dut.Version())
	}
}

func ConfigureDUTQoSIPv4(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")
	d := &oc.Root{}
	q := d.GetOrCreateQos()
	queues := netutil.CommonTrafficQueues(t, dut)

	if deviations.QOSQueueRequiresID(dut) {
		queueNames := []string{queues.NC1, queues.AF4, queues.AF3, queues.AF2, queues.AF1, queues.BE1}
		for i, queue := range queueNames {
			q1 := q.GetOrCreateQueue(queue)
			q1.Name = ygot.String(queue)
			queueid := len(queueNames) - i
			q1.QueueId = ygot.Uint8(uint8(queueid))
		}
		t.Logf("DUT %s %s %s requires QoS queue requires ID deviation ", dut.Vendor(), dut.Model(), dut.Version())
	}

	t.Logf("Create QoS forwarding groups and queue names configuration")
	forwardingGroups := []struct {
		desc        string
		queueName   string
		targetGroup string
	}{{
		desc:        "forwarding-group-BE1",
		queueName:   queues.BE1,
		targetGroup: "target-group-BE1",
	}, {
		desc:        "forwarding-group-AF1",
		queueName:   queues.AF1,
		targetGroup: "target-group-AF1",
	}, {
		desc:        "forwarding-group-AF2",
		queueName:   queues.AF2,
		targetGroup: "target-group-AF2",
	}, {
		desc:        "forwarding-group-AF3",
		queueName:   queues.AF3,
		targetGroup: "target-group-AF3",
	}, {
		desc:        "forwarding-group-AF4",
		queueName:   queues.AF4,
		targetGroup: "target-group-AF4",
	}, {
		desc:        "forwarding-group-NC1",
		queueName:   queues.NC1,
		targetGroup: "target-group-NC1",
	}}

	t.Logf("QoS forwarding groups config: %v", forwardingGroups)
	for _, tc := range forwardingGroups {
		qoscfg.SetForwardingGroup(t, dut, q, tc.targetGroup, tc.queueName)
	}

	t.Logf("Create QoS Classifiers config")
	classifiers := []struct {
		desc        string
		name        string
		classType   oc.E_Qos_Classifier_Type
		termID      string
		targetGroup string
		dscpSet     []uint8
	}{{
		desc:        "classifier_ipv4_be1",
		name:        "dscp_based_classifier_ipv4",
		classType:   oc.Qos_Classifier_Type_IPV4,
		termID:      "DSCP_BE1",
		targetGroup: "target-group-BE1",
		dscpSet:     []uint8{0},
	}, {
		desc:        "classifier_ipv4_af1",
		name:        "dscp_based_classifier_ipv4",
		classType:   oc.Qos_Classifier_Type_IPV4,
		termID:      "DSCP_AF1",
		targetGroup: "target-group-AF1",
		dscpSet:     []uint8{1},
	}, {
		desc:        "classifier_ipv4_af2",
		name:        "dscp_based_classifier_ipv4",
		classType:   oc.Qos_Classifier_Type_IPV4,
		termID:      "DSCP_AF2",
		targetGroup: "target-group-AF2",
		dscpSet:     []uint8{2},
	}, {
		desc:        "classifier_ipv4_af3",
		name:        "dscp_based_classifier_ipv4",
		classType:   oc.Qos_Classifier_Type_IPV4,
		termID:      "DSCP_AF3",
		targetGroup: "target-group-AF3",
		dscpSet:     []uint8{3},
	}, {
		desc:        "classifier_ipv4_af4",
		name:        "dscp_based_classifier_ipv4",
		classType:   oc.Qos_Classifier_Type_IPV4,
		termID:      "DSCP_AF4",
		targetGroup: "target-group-AF4",
		dscpSet:     []uint8{4, 5},
	}, {
		desc:        "classifier_ipv4_nc1",
		name:        "dscp_based_classifier_ipv4",
		classType:   oc.Qos_Classifier_Type_IPV4,
		termID:      "DSCP_NC1",
		targetGroup: "target-group-NC1",
		dscpSet:     []uint8{6, 7},
	}}

	t.Logf("QoS classifiers config: %v", classifiers)
	for _, tc := range classifiers {
		classifier := q.GetOrCreateClassifier(tc.name)
		classifier.SetName(tc.name)
		classifier.SetType(tc.classType)
		term, err := classifier.NewTerm(tc.termID)
		if err != nil {
			t.Fatalf("Failed to create classifier.NewTerm(): %v", err)
		}

		term.SetId(tc.termID)
		action := term.GetOrCreateActions()
		action.SetTargetGroup(tc.targetGroup)
		condition := term.GetOrCreateConditions()
		condition.GetOrCreateIpv4().SetDscpSet(tc.dscpSet)
		gnmi.Replace(t, dut, gnmi.OC().Qos().Config(), q)
	}

	t.Logf("Create QoS input classifier config")
	classifierIntfs := []struct {
		desc                string
		intf                string
		inputClassifierType oc.E_Input_Classifier_Type
		classifier          string
	}{{
		desc:                "Input Classifier Type IPV4",
		intf:                dp1.Name(),
		inputClassifierType: oc.Input_Classifier_Type_IPV4,
		classifier:          "dscp_based_classifier_ipv4",
	}, {
		desc:                "Input Classifier Type IPV4",
		intf:                dp2.Name(),
		inputClassifierType: oc.Input_Classifier_Type_IPV4,
		classifier:          "dscp_based_classifier_ipv4",
	}}

	t.Logf("QoS input classifier config: %v", classifierIntfs)
	for _, tc := range classifierIntfs {
		qoscfg.SetInputClassifier(t, dut, q, tc.intf, tc.inputClassifierType, tc.classifier)
	}

	t.Logf("Create QoS scheduler policies config")
	schedulerPolicies := []struct {
		desc        string
		sequence    uint32
		setPriority bool
		priority    oc.E_Scheduler_Priority
		inputID     string
		inputType   oc.E_Input_InputType
		setWeight   bool
		queueName   string
		targetGroup string
	}{{
		desc:        "scheduler-policy-BE1",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "BE1",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.BE1,
		targetGroup: "target-group-BE1",
	}, {
		desc:        "scheduler-policy-AF1",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF1",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF1,
		targetGroup: "target-group-AF1",
	}, {
		desc:        "scheduler-policy-AF2",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF2",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF2,
		targetGroup: "target-group-AF2",
	}, {
		desc:        "scheduler-policy-AF3",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF3",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF3,
		targetGroup: "target-group-AF3",
	}, {
		desc:        "scheduler-policy-AF4",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF4",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF4,
		targetGroup: "target-group-AF4",
	}, {
		desc:        "scheduler-policy-NC1",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "NC1",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.NC1,
		targetGroup: "target-group-NC1",
	}}

	schedulerPolicy := q.GetOrCreateSchedulerPolicy("scheduler")
	schedulerPolicy.SetName("scheduler")
	t.Logf("QoS scheduler policies config: %v", schedulerPolicies)
	for _, tc := range schedulerPolicies {
		s := schedulerPolicy.GetOrCreateScheduler(tc.sequence)
		s.SetSequence(tc.sequence)
		if tc.setPriority {
			s.SetPriority(tc.priority)
		}
		input := s.GetOrCreateInput(tc.inputID)
		input.SetId(tc.inputID)
		input.SetInputType(tc.inputType)
		input.SetQueue(tc.queueName)
		gnmi.Replace(t, dut, gnmi.OC().Qos().Config(), q)
	}

	t.Logf("Create QoS output interface config")
	schedulerIntfs := []struct {
		desc      string
		queueName string
		scheduler string
	}{{
		desc:      "output-interface-BE1",
		queueName: queues.BE1,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF1",
		queueName: queues.AF1,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF2",
		queueName: queues.AF2,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF3",
		queueName: queues.AF3,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF4",
		queueName: queues.AF4,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-NC1",
		queueName: queues.NC1,
		scheduler: "scheduler",
	}}

	t.Logf("QoS output interface config: %v", schedulerIntfs)
	for _, tc := range schedulerIntfs {
		i := q.GetOrCreateInterface(dp3.Name())
		i.SetInterfaceId(dp3.Name())
		i.GetOrCreateInterfaceRef().Interface = ygot.String(dp3.Name())
		if deviations.InterfaceRefConfigUnsupported(dut) {
			i.InterfaceRef = nil
		}
		output := i.GetOrCreateOutput()
		schedulerPolicy := output.GetOrCreateSchedulerPolicy()
		schedulerPolicy.SetName(tc.scheduler)
		queue := output.GetOrCreateQueue(tc.queueName)
		queue.SetName(tc.queueName)
		gnmi.Replace(t, dut, gnmi.OC().Qos().Config(), q)
	}
}

func ConfigureDUTQoSIPv6(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")
	d := &oc.Root{}
	q := d.GetOrCreateQos()
	queues := netutil.CommonTrafficQueues(t, dut)

	if deviations.QOSQueueRequiresID(dut) {
		queueNames := []string{queues.NC1, queues.AF4, queues.AF3, queues.AF2, queues.AF1, queues.BE1}
		for i, queue := range queueNames {
			q1 := q.GetOrCreateQueue(queue)
			q1.Name = ygot.String(queue)
			queueid := len(queueNames) - i
			q1.QueueId = ygot.Uint8(uint8(queueid))
		}
		t.Logf("DUT %s %s %s requires QoS queue requires ID deviation ", dut.Vendor(), dut.Model(), dut.Version())
	}

	t.Logf("Create QoS forwarding groups and queue names configuration")
	forwardingGroups := []struct {
		desc        string
		queueName   string
		targetGroup string
	}{{
		desc:        "forwarding-group-BE1",
		queueName:   queues.BE1,
		targetGroup: "target-group-BE1",
	}, {
		desc:        "forwarding-group-AF1",
		queueName:   queues.AF1,
		targetGroup: "target-group-AF1",
	}, {
		desc:        "forwarding-group-AF2",
		queueName:   queues.AF2,
		targetGroup: "target-group-AF2",
	}, {
		desc:        "forwarding-group-AF3",
		queueName:   queues.AF3,
		targetGroup: "target-group-AF3",
	}, {
		desc:        "forwarding-group-AF4",
		queueName:   queues.AF4,
		targetGroup: "target-group-AF4",
	}, {
		desc:        "forwarding-group-NC1",
		queueName:   queues.NC1,
		targetGroup: "target-group-NC1",
	}}

	t.Logf("QoS forwarding groups config: %v", forwardingGroups)
	for _, tc := range forwardingGroups {
		qoscfg.SetForwardingGroup(t, dut, q, tc.targetGroup, tc.queueName)
	}

	t.Logf("Create QoS Classifiers config")
	classifiers := []struct {
		desc        string
		name        string
		classType   oc.E_Qos_Classifier_Type
		termID      string
		targetGroup string
		dscpSet     []uint8
	}{{
		desc:        "classifier_ipv6_be1",
		name:        "dscp_based_classifier_ipv6",
		classType:   oc.Qos_Classifier_Type_IPV6,
		termID:      "DSCP_BE1",
		targetGroup: "target-group-BE1",
		dscpSet:     []uint8{0, 1, 2, 3, 4, 5, 6, 7},
	}, {
		desc:        "classifier_ipv6_af1",
		name:        "dscp_based_classifier_ipv6",
		classType:   oc.Qos_Classifier_Type_IPV6,
		termID:      "DSCP_AF1",
		targetGroup: "target-group-AF1",
		dscpSet:     []uint8{8, 9, 10, 11, 12, 13, 14, 15},
	}, {
		desc:        "classifier_ipv6_af2",
		name:        "dscp_based_classifier_ipv6",
		classType:   oc.Qos_Classifier_Type_IPV6,
		termID:      "DSCP_AF2",
		targetGroup: "target-group-AF2",
		dscpSet:     []uint8{16, 17, 18, 19, 20, 21, 22, 23},
	}, {
		desc:        "classifier_ipv6_af3",
		name:        "dscp_based_classifier_ipv6",
		classType:   oc.Qos_Classifier_Type_IPV6,
		termID:      "DSCP_AF3",
		targetGroup: "target-group-AF3",
		dscpSet:     []uint8{24, 25, 26, 27, 28, 29, 30, 31},
	}, {
		desc:        "classifier_ipv6_af4",
		name:        "dscp_based_classifier_ipv6",
		classType:   oc.Qos_Classifier_Type_IPV6,
		termID:      "DSCP_AF4",
		targetGroup: "target-group-AF4",
		dscpSet:     []uint8{32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47},
	}, {
		desc:        "classifier_ipv6_nc1",
		name:        "dscp_based_classifier_ipv6",
		classType:   oc.Qos_Classifier_Type_IPV6,
		termID:      "DSCP_NC1",
		targetGroup: "target-group-NC1",
		dscpSet:     []uint8{48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63},
	}}

	t.Logf("QoS classifiers config: %v", classifiers)
	for _, tc := range classifiers {
		classifier := q.GetOrCreateClassifier(tc.name)
		classifier.SetName(tc.name)
		classifier.SetType(tc.classType)
		term, err := classifier.NewTerm(tc.termID)
		if err != nil {
			t.Fatalf("Failed to create classifier.NewTerm(): %v", err)
		}

		term.SetId(tc.termID)
		action := term.GetOrCreateActions()
		action.SetTargetGroup(tc.targetGroup)
		condition := term.GetOrCreateConditions()
		condition.GetOrCreateIpv6().SetDscpSet(tc.dscpSet)
		gnmi.Replace(t, dut, gnmi.OC().Qos().Config(), q)
	}

	t.Logf("Create QoS input classifier config")
	classifierIntfs := []struct {
		desc                string
		intf                string
		inputClassifierType oc.E_Input_Classifier_Type
		classifier          string
	}{{
		desc:                "Input Classifier Type IPV6",
		intf:                dp1.Name(),
		inputClassifierType: oc.Input_Classifier_Type_IPV6,
		classifier:          "dscp_based_classifier_ipv6",
	}, {
		desc:                "Input Classifier Type IPV6",
		intf:                dp2.Name(),
		inputClassifierType: oc.Input_Classifier_Type_IPV6,
		classifier:          "dscp_based_classifier_ipv6",
	}}

	t.Logf("QoS input classifier config: %v", classifierIntfs)
	for _, tc := range classifierIntfs {
		qoscfg.SetInputClassifier(t, dut, q, tc.intf, tc.inputClassifierType, tc.classifier)
	}

	t.Logf("Create QoS scheduler policies config")
	schedulerPolicies := []struct {
		desc        string
		sequence    uint32
		setPriority bool
		priority    oc.E_Scheduler_Priority
		inputID     string
		inputType   oc.E_Input_InputType
		setWeight   bool
		queueName   string
		targetGroup string
	}{{
		desc:        "scheduler-policy-BE1",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "BE1",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.BE1,
		targetGroup: "target-group-BE1",
	}, {
		desc:        "scheduler-policy-AF1",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF1",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF1,
		targetGroup: "target-group-AF1",
	}, {
		desc:        "scheduler-policy-AF2",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF2",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF2,
		targetGroup: "target-group-AF2",
	}, {
		desc:        "scheduler-policy-AF3",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF3",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF3,
		targetGroup: "target-group-AF3",
	}, {
		desc:        "scheduler-policy-AF4",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "AF4",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.AF4,
		targetGroup: "target-group-AF4",
	}, {
		desc:        "scheduler-policy-NC1",
		sequence:    uint32(0),
		setPriority: true,
		setWeight:   false,
		priority:    oc.Scheduler_Priority_STRICT,
		inputID:     "NC1",
		inputType:   oc.Input_InputType_QUEUE,
		queueName:   queues.NC1,
		targetGroup: "target-group-NC1",
	}}

	schedulerPolicy := q.GetOrCreateSchedulerPolicy("scheduler")
	schedulerPolicy.SetName("scheduler")
	t.Logf("QoS scheduler policies config: %v", schedulerPolicies)
	for _, tc := range schedulerPolicies {
		s := schedulerPolicy.GetOrCreateScheduler(tc.sequence)
		s.SetSequence(tc.sequence)
		if tc.setPriority {
			s.SetPriority(tc.priority)
		}
		input := s.GetOrCreateInput(tc.inputID)
		input.SetId(tc.inputID)
		input.SetInputType(tc.inputType)
		input.SetQueue(tc.queueName)
		//if tc.setWeight {
		//	input.SetWeight(tc.weight)
		//}
		gnmi.Replace(t, dut, gnmi.OC().Qos().Config(), q)
	}

	t.Logf("Create qos output interface config")
	schedulerIntfs := []struct {
		desc       string
		queueName  string
		scheduler  string
		ecnProfile string
	}{{
		desc:      "output-interface-BE1",
		queueName: queues.BE1,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF1",
		queueName: queues.AF1,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF2",
		queueName: queues.AF2,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF3",
		queueName: queues.AF3,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-AF4",
		queueName: queues.AF4,
		scheduler: "scheduler",
	}, {
		desc:      "output-interface-NC1",
		queueName: queues.NC1,
		scheduler: "scheduler",
	}}

	maxBurstSize := uint32(268435456)
	t.Logf("qos output interface config: %v", schedulerIntfs)
	for _, tc := range schedulerIntfs {
		i := q.GetOrCreateInterface(dp3.Name())
		i.SetInterfaceId(dp3.Name())
		i.GetOrCreateInterfaceRef().Interface = ygot.String(dp3.Name())
		if deviations.InterfaceRefConfigUnsupported(dut) {
			i.InterfaceRef = nil
		}
		output := i.GetOrCreateOutput()
		schedulerPolicy := output.GetOrCreateSchedulerPolicy()
		schedulerPolicy.SetName(tc.scheduler)
		queue := output.GetOrCreateQueue(tc.queueName)
		queue.SetName(tc.queueName)
		queue.SetQueueManagementProfile(tc.ecnProfile)
		if dut.Vendor() == ondatra.NOKIA {
			bufferAllocation := q.GetOrCreateBufferAllocationProfile("ballocprofile")
			bq := bufferAllocation.GetOrCreateQueue(tc.queueName)
			bq.SetStaticSharedBufferLimit(maxBurstSize)
			output.SetBufferAllocationProfile("ballocprofile")
		}
		gnmi.Replace(t, dut, gnmi.OC().Qos().Config(), q)
	}
}

type CustomNetworkInstanceType struct {
	Prefix string
	Type   oc.E_NetworkInstanceTypes_NETWORK_INSTANCE_TYPE
}

func (c CustomNetworkInstanceType) String() string {
	return c.Prefix + c.Type.String()
}

func configureStaticLSP(t *testing.T, dut *ondatra.DUTDevice, lspName string, incomingLabel uint32, nextHopIP string) {
	root := &oc.Root{}
	dni := deviations.DefaultNetworkInstance(dut)
	defPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	mplsType := CustomNetworkInstanceType{
		Prefix: "oc-ni-types:",
		Type:   oc.NetworkInstanceTypes_NETWORK_INSTANCE_TYPE_DEFAULT_INSTANCE,
	}
	mplsName := "default"
	// ygot.String(deviations.DefaultNetworkInstance(dut))
	gnmi.Update(t, dut, defPath.Config(), &oc.NetworkInstance{
		Name: &mplsName,
		Type: mplsType.Type,
	})
	mplsCfg := root.GetOrCreateNetworkInstance(dni).GetOrCreateMpls()
	staticMplsCfg := mplsCfg.GetOrCreateLsps().GetOrCreateStaticLsp(lspName)
	staticMplsCfg.GetOrCreateEgress().SetIncomingLabel(oc.UnionUint32(incomingLabel))
	staticMplsCfg.GetOrCreateEgress().SetNextHop(nextHopIP)
	staticMplsCfg.GetOrCreateEgress().SetPushLabel(oc.Egress_PushLabel_IMPLICIT_NULL)
	gnmi.Update(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Mpls().Config(), mplsCfg)
}
