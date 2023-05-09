// Copyright 2022 Google LLC
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

// Package setup is scoped only to be used for scripts in path
// feature/experimental/system/gnmi/benchmarking/ate_tests/
// Do not use elsewhere.
package setup

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
)

const (
	// ISISInstance is ISIS instance name.
	ISISInstance = "DEFAULT"
	// PeerGrpName is BGP peer group name.
	PeerGrpName = "BGP-PEER-GROUP"
	// PeerGrpEgressName is Egress port BGP peer group name.
	PeerGrpEgressName = "BGP-PEER-GROUP-EGRESS"
	// DUTAs is DUT AS.
	DUTAs = 64500
	// ATEAs is ATE AS.
	ATEAs = 64501
	// ATEAs2 is ATE source port AS
	ATEAs2 = 64502
	// ISISMetric is Metric for ISIS
	ISISMetric = 100
	// RouteCount for both BGP and ISIS
	RouteCount = 200

	dutAreaAddress        = "49.0001"
	dutSysID              = "1920.0000.2001"
	dutStartIPAddr        = "192.0.2.1"
	ateStartIPAddr        = "192.0.2.2"
	plenIPv4              = 30
	authPassword          = "ISISAuthPassword"
	advertiseBGPRoutesv4  = "203.0.113.1"
	advertiseISISRoutesv4 = "198.18.0.0"
	setALLOWPolicy        = "ALLOW"
)

// DUTIPList, ATEIPList are lists of DUT and ATE interface ip addresses.
var (
	DUTIPList = make(map[string]net.IP)
	ATEIPList = make(map[string]net.IP)
)

// buildPortIPs generates ip addresses for the ports in binding file.
// (Both DUT and ATE ports).
func buildPortIPs(dut *ondatra.DUTDevice) {
	var dutIPIndex, ipSubnet, ateIPIndex int = 1, 2, 2
	var endSubnetIndex = 253
	for _, dp := range dut.Ports() {
		dutNextIP := nextIP(net.ParseIP(dutStartIPAddr), dutIPIndex, ipSubnet)
		ateNextIP := nextIP(net.ParseIP(ateStartIPAddr), ateIPIndex, ipSubnet)
		DUTIPList[dp.ID()] = dutNextIP
		ATEIPList[dp.ID()] = ateNextIP

		// Increment DUT and ATE host ip index by 4.
		dutIPIndex = dutIPIndex + 4
		ateIPIndex = ateIPIndex + 4

		// Reset DUT and ATE ip indexes when it is greater than endSubnetIndex.
		if dutIPIndex > int(endSubnetIndex) {
			ipSubnet = ipSubnet + 1
			dutIPIndex = 1
			ateIPIndex = 2
		}
	}
}

// nextIP returns ip address based on hostIndex and subnetIndex provided.
func nextIP(ip net.IP, hostIndex int, subnetIndex int) net.IP {
	s := ip.String()
	sa := strings.Split(s, ".")
	sa[2] = strconv.Itoa(subnetIndex)
	sa[3] = strconv.Itoa(hostIndex)
	s = strings.Join(sa, ".")
	return net.ParseIP(s)
}

// BuildBenchmarkingConfig builds required configuration for DUT interfaces, ISIS and BGP.
func BuildBenchmarkingConfig(t *testing.T) *oc.Root {
	dut := ondatra.DUT(t, "dut")
	d := &oc.Root{}

	// Generate ip addresses to configure DUT and ATE ports.
	buildPortIPs(dut)

	// Network instance and BGP configs.
	netInstance := d.GetOrCreateNetworkInstance(*deviations.DefaultNetworkInstance)

	bgp := netInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").GetOrCreateBgp()
	global := bgp.GetOrCreateGlobal()
	global.As = ygot.Uint32(DUTAs)
	global.RouterId = ygot.String(dutStartIPAddr)

	afi := global.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	afi.Enabled = ygot.Bool(true)

	pg := bgp.GetOrCreatePeerGroup(PeerGrpName)
	pg.PeerAs = ygot.Uint32(ATEAs)
	pg.PeerGroupName = ygot.String(PeerGrpName)
	afipg := pg.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	afipg.Enabled = ygot.Bool(true)
	rp := d.GetOrCreateRoutingPolicy()
	pdef := rp.GetOrCreatePolicyDefinition(setALLOWPolicy)
	pdef.GetOrCreateStatement("id-1").GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
	rpl := pg.GetOrCreateApplyPolicy()
	rpl.SetExportPolicy([]string{setALLOWPolicy})
	rpl.SetImportPolicy([]string{setALLOWPolicy})

	if *deviations.RoutePolicyUnderPeerGroup {
		pg1 := bgp.GetOrCreatePeerGroup(PeerGrpEgressName)
		pg1.PeerAs = ygot.Uint32(ATEAs)
		pg1.PeerGroupName = ygot.String(PeerGrpEgressName)
		afipg1 := pg1.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
		afipg1.Enabled = ygot.Bool(true)
	}

	// ISIS configs.
	isis := netInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_ISIS, ISISInstance).GetOrCreateIsis()

	globalISIS := isis.GetOrCreateGlobal()
	globalISIS.LevelCapability = oc.Isis_LevelType_LEVEL_2
	globalISIS.AuthenticationCheck = ygot.Bool(true)
	globalISIS.Net = []string{fmt.Sprintf("%v.%v.00", dutAreaAddress, dutSysID)}
	lspBit := globalISIS.GetOrCreateLspBit().GetOrCreateOverloadBit()
	lspBit.SetBit = ygot.Bool(false)
	isisTimers := globalISIS.GetOrCreateTimers()
	isisTimers.LspLifetimeInterval = ygot.Uint16(600)
	spfTimers := isisTimers.GetOrCreateSpf()
	spfTimers.SpfHoldInterval = ygot.Uint64(5000)
	spfTimers.SpfFirstInterval = ygot.Uint64(600)

	isisLevel2 := isis.GetOrCreateLevel(2)
	isisLevel2.MetricStyle = oc.Isis_MetricStyle_WIDE_METRIC

	isisLevel2Auth := isisLevel2.GetOrCreateAuthentication()
	isisLevel2Auth.Enabled = ygot.Bool(true)
	isisLevel2Auth.AuthPassword = ygot.String(authPassword)
	isisLevel2Auth.AuthMode = oc.IsisTypes_AUTH_MODE_MD5
	isisLevel2Auth.AuthType = oc.KeychainTypes_AUTH_TYPE_SIMPLE_KEY

	for _, dp := range dut.Ports() {
		// Interfaces config.
		i := d.GetOrCreateInterface(dp.Name())
		i.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd
		if *deviations.InterfaceEnabled {
			i.Enabled = ygot.Bool(true)
		}
		i.Description = ygot.String("from oc")
		i.Name = ygot.String(dp.Name())

		s := i.GetOrCreateSubinterface(0)
		s4 := s.GetOrCreateIpv4()
		if *deviations.InterfaceEnabled {
			s4.Enabled = ygot.Bool(true)
		}
		a4 := s4.GetOrCreateAddress(DUTIPList[dp.ID()].String())
		a4.PrefixLength = ygot.Uint8(plenIPv4)

		// BGP neighbor configs.
		nv4 := bgp.GetOrCreateNeighbor(ATEIPList[dp.ID()].String())
		nv4.PeerGroup = ygot.String(PeerGrpName)
		if dp.ID() == "port1" {
			nv4.PeerAs = ygot.Uint32(ATEAs2)
		} else {
			if *deviations.RoutePolicyUnderPeerGroup {
				nv4.PeerGroup = ygot.String(PeerGrpEgressName)
			}
			nv4.PeerAs = ygot.Uint32(ATEAs)
		}
		nv4.Enabled = ygot.Bool(true)

		// ISIS configs.
		isisIntf := isis.GetOrCreateInterface(dp.Name())
		isisIntf.Enabled = ygot.Bool(true)
		isisIntf.HelloPadding = oc.Isis_HelloPaddingType_ADAPTIVE
		isisIntf.CircuitType = oc.Isis_CircuitType_POINT_TO_POINT

		isisIntfAuth := isisIntf.GetOrCreateAuthentication()
		isisIntfAuth.Enabled = ygot.Bool(true)
		isisIntfAuth.AuthPassword = ygot.String(authPassword)
		isisIntfAuth.AuthMode = oc.IsisTypes_AUTH_MODE_MD5
		isisIntfAuth.AuthType = oc.KeychainTypes_AUTH_TYPE_SIMPLE_KEY

		isisIntfLevel := isisIntf.GetOrCreateLevel(2)
		isisIntfLevel.Enabled = ygot.Bool(true)

		isisIntfLevelTimers := isisIntfLevel.GetOrCreateTimers()
		isisIntfLevelTimers.HelloInterval = ygot.Uint32(1)
		isisIntfLevelTimers.HelloMultiplier = ygot.Uint8(5)

		isisIntfLevelAfi := isisIntfLevel.GetOrCreateAf(oc.IsisTypes_AFI_TYPE_IPV4, oc.IsisTypes_SAFI_TYPE_UNICAST)
		isisIntfLevelAfi.Metric = ygot.Uint32(200)

		// Configure ISIS AfiSafi enable flag at the global level
		if deviations.MissingIsisInterfaceAfiSafiEnable(dut) {
			isisIntf.GetOrCreateAf(oc.IsisTypes_AFI_TYPE_IPV4, oc.IsisTypes_SAFI_TYPE_UNICAST).Enabled = ygot.Bool(true)
		} else {
			isisIntfLevelAfi.Enabled = ygot.Bool(true)
		}
	}
	p := gnmi.OC()
	fptest.LogQuery(t, "DUT", p.Config(), d)

	return d
}

// ConfigureATE function is to configure ate ports with ipv4 , bgp
// and isis peers.
func ConfigureATE(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	topo := otg.NewConfig(t)

	for i, dp := range ate.Ports() {
		atePortAttr := attrs.Attributes{
			Name:    "ate" + dp.ID(),
			IPv4:    ATEIPList[dp.ID()].String(),
			IPv4Len: plenIPv4,
		}

		topo.Ports().Add().SetName(dp.ID())
		dev := topo.Devices().Add().SetName(dp.ID() + "dev")
		eth := dev.Ethernets().Add().SetName(dp.ID() + ".Eth")
		eth.Connection().SetPortName(dp.ID())
		mac := fmt.Sprintf("02:00:01:01:01:%02x", byte(i&0xff))

		eth.SetMac(mac)

		ip := eth.Ipv4Addresses().Add().SetName(dev.Name() + ".IPv4")
		ip.SetAddress(atePortAttr.IPv4).SetGateway(DUTIPList[dp.ID()].String()).SetPrefix(int32(atePortAttr.IPv4Len))

		// Add BGP routes and ISIS routes , ate port1 is ingress port.
		if dp.ID() == "port1" {
			// Add BGP on ATE
			bgpDut1 := dev.Bgp().SetRouterId(ip.Address())
			bgpDut1Peer := bgpDut1.Ipv4Interfaces().Add().SetIpv4Name(ip.Name()).Peers().Add().SetName(dp.ID() + ".BGP4.peer")
			bgpDut1Peer.SetPeerAddress(DUTIPList[dp.ID()].String()).SetAsNumber(ATEAs2).SetAsType(gosnappi.BgpV4PeerAsType.EBGP)

			bgpDut1Peer.Capability().SetIpv4Unicast(true)
			bgpDut1Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

			devIsis := dev.Isis().
				SetSystemId(strconv.FormatInt(int64(i), 16)).
				SetName("devIsis" + dp.Name())

			devIsis.Basic().
				SetHostname(devIsis.Name()).SetLearnedLspFilter(true)

			devIsis.Advanced().
				SetAreaAddresses([]string{"490002"})

			devIsisInt := devIsis.Interfaces().
				Add().
				SetEthName(eth.Name()).
				SetName("devIsisInt").
				SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
				SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_2)

			devIsisInt.Authentication().SetAuthType("md5")
			devIsisInt.Authentication().SetMd5(authPassword)

			devIsisInt.Advanced().
				SetAutoAdjustMtu(true).SetAutoAdjustArea(true).SetAutoAdjustSupportedProtocols(true)

			dstBgp4PeerRoutes := bgpDut1Peer.V4Routes().Add().SetName("bgpNeti1")
			dstBgp4PeerRoutes.SetNextHopIpv4Address(ip.Address()).
				SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
				SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
			dstBgp4PeerRoutes.Addresses().Add().
				SetAddress(advertiseBGPRoutesv4).
				SetPrefix(32).
				SetCount(RouteCount)

			devIsisRoutes := devIsis.V4Routes().Add().SetName("isisnet1").SetLinkMetric(20)
			devIsisRoutes.Addresses().Add().
				SetAddress(advertiseISISRoutesv4).
				SetPrefix(32).
				SetCount(RouteCount).
				SetStep(1)

			continue
		}

		// Add BGP on ATE
		bgpDut1 := dev.Bgp().SetRouterId(ip.Address())
		bgpDut1Peer := bgpDut1.Ipv4Interfaces().Add().SetIpv4Name(ip.Name()).Peers().Add().SetName(dp.ID() + ".BGP4.peer")
		bgpDut1Peer.SetPeerAddress(DUTIPList[dp.ID()].String()).SetAsNumber(ATEAs).SetAsType(gosnappi.BgpV4PeerAsType.EBGP)

		bgpDut1Peer.Capability().SetIpv4Unicast(true)
		bgpDut1Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

		// Add ISIS on ATE
		devIsis := dev.Isis().
			SetSystemId(strconv.FormatInt(int64(i), 16)).
			SetName("devIsis" + dp.Name())

		devIsis.Basic().
			SetHostname(devIsis.Name()).SetLearnedLspFilter(true)

		devIsis.Advanced().
			SetAreaAddresses([]string{"490002"})

		devIsisInt := devIsis.Interfaces().
			Add().
			SetEthName(eth.Name()).
			SetName("devIsisInt").
			SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
			SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_2)

		devIsisInt.Authentication().SetAuthType("md5")
		devIsisInt.Authentication().SetMd5(authPassword)

		devIsisInt.Advanced().
			SetAutoAdjustMtu(true).SetAutoAdjustArea(true).SetAutoAdjustSupportedProtocols(true)

	}

	t.Log("Pushing config to ATE...")
	otg.PushConfig(t, topo)
	t.Log("Starting protocols to ATE...")
	otg.StartProtocols(t)
	otgutils.WaitForARP(t, otg, topo, "IPv4")
}

// VerifyISISTelemetry function to used verify ISIS telemetry on DUT
// using OC isis telemetry path.
func VerifyISISTelemetry(t *testing.T, dut *ondatra.DUTDevice) {
	statePath := gnmi.OC().NetworkInstance(*deviations.DefaultNetworkInstance).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_ISIS, ISISInstance).Isis()
	for _, dp := range dut.Ports() {
		nbrPath := statePath.Interface(dp.Name())
		query := nbrPath.LevelAny().AdjacencyAny().AdjacencyState().State()
		_, ok := gnmi.WatchAll(t, dut, query, time.Minute, func(val *ygnmi.Value[oc.E_Isis_IsisInterfaceAdjState]) bool {
			state, present := val.Val()
			return present && state == oc.Isis_IsisInterfaceAdjState_UP
		}).Await(t)
		if !ok {
			t.Logf("IS-IS state on %v has no adjacencies", dp.Name())
			t.Fatal("No IS-IS adjacencies reported.")
		}
	}
}

// VerifyBgpTelemetry function is to verify BGP telemetry on DUT using
// BGP OC telemetry path.
func VerifyBgpTelemetry(t *testing.T, dut *ondatra.DUTDevice) {
	statePath := gnmi.OC().NetworkInstance(*deviations.DefaultNetworkInstance).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()
	for _, peerAddr := range ATEIPList {
		nbrIP := peerAddr.String()
		nbrPath := statePath.Neighbor(nbrIP)
		gnmi.Await(t, dut, nbrPath.SessionState().State(), time.Second*120, oc.Bgp_Neighbor_SessionState_ESTABLISHED)
	}

}
