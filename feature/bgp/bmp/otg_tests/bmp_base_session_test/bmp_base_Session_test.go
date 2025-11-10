package bmp_base_session_test

import (
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/cfgplugins"
	"github.com/openconfig/ygnmi/ygnmi"

	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
)

const (
	dutAS          = 64520
	ate1AS         = 64530
	plenIPv4       = 30
	plenIPv6       = 126
	bmpStationPort = 7039
	host1IPv4Start = "192.168.0.0"
	host1IPv6Start = "2001:db8:100::"
	host2IPv4Start = "10.200.0.0"
	host2IPv6Start = "2001:db8:110::"
	hostIPv4PfxLen = 24
	hostIPv6PfxLen = 64
	routeCountV4   = 10
	routeCountV6   = 10
	bmpName        = "atebmp"
)

var (
	dutP1 = attrs.Attributes{
		Desc:    "DUT to ATE Port 1",
		IPv4:    "192.0.2.1",
		IPv6:    "2001:db8:2::1",
		MAC:     "02:00:01:02:02:02",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}

	ateP1 = attrs.Attributes{
		Name:    "atePort1",
		IPv4:    "192.0.2.2",
		IPv6:    "2001:db8:2::2",
		MAC:     "02:00:01:01:01:01",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}

	dutP2 = attrs.Attributes{
		Desc:    "DUT to ATE Port 2",
		IPv4:    "192.0.3.1",
		IPv6:    "2001:db8:3::1",
		MAC:     "02:00:02:02:02:02",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}

	ateP2 = attrs.Attributes{
		Name:    "atePort2",
		IPv4:    "192.0.3.2",
		IPv6:    "2001:db8:3::2",
		MAC:     "02:00:02:01:01:01",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
)

type ateConfigParams struct {
	atePort       gosnappi.Port
	atePortAttrs  attrs.Attributes
	dutPortAttrs  attrs.Attributes
	ateAS         uint32
	bmpName       string
	hostIPv4Start string
	hostIPv6Start string
}

// TestMain is the entry point for the test suite.
func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// configureDUT configures all DUT aspects.
func configureDUT(t *testing.T, dut *ondatra.DUTDevice) *gnmi.SetBatch {
	t.Helper()
	p1 := dut.Port(t, "port1")
	p2 := dut.Port(t, "port2")

	bmpConfigParams := cfgplugins.BMPConfigParams{
		DutAS:       dutAS,
		Source:      p2.Name(),
		StationPort: bmpStationPort,
		StationAddr: ateP2.IPv4,
	}

	batch := &gnmi.SetBatch{}
	gnmi.BatchReplace(batch, gnmi.OC().Interface(p1.Name()).Config(), dutP1.NewOCInterface(p1.Name(), dut))
	gnmi.BatchReplace(batch, gnmi.OC().Interface(p2.Name()).Config(), dutP2.NewOCInterface(p2.Name(), dut))
	cfgBGP := cfgplugins.BGPConfig{DutAS: dutAS, RouterID: dutP1.IPv4}
	dutBgpConf := cfgplugins.ConfigureDUTBGP(t, dut, batch, cfgBGP)
	configureDUTBGPNeighbors(t, dut, batch, dutBgpConf.Bgp)
	cfgplugins.ConfigureBMP(t, dut, batch, bmpConfigParams)
	batch.Set(t, dut)
	fptest.ConfigureDefaultNetworkInstance(t, dut)
	return batch
}

// configureDUTBGPNeighbors appends multiple BGP neighbor configurations to an existing BGP protocol on the DUT. Instead of calling AppendBGPNeighbor repeatedly in the test, this helper iterates over a slice of BGPNeighborConfig and applies each neighbor configuration into the given gnmi.SetBatch.
func configureDUTBGPNeighbors(t *testing.T, dut *ondatra.DUTDevice, batch *gnmi.SetBatch, bgp *oc.NetworkInstance_Protocol_Bgp) {
	t.Helper()
	// Add BGP neighbors
	neighbors := []cfgplugins.BGPNeighborConfig{
		{
			AteAS:        ate1AS,
			PortName:     dutP1.Name,
			NeighborIPv4: ateP1.IPv4,
			NeighborIPv6: ateP1.IPv6,
			IsLag:        false,
		},
	}
	for _, n := range neighbors {
		cfgplugins.AppendBGPNeighbor(t, dut, batch, bgp, n)
	}
}

// configureATE builds and returns the OTG configuration for the ATE topology.
func configureATE(t *testing.T, ate *ondatra.ATEDevice, bmpName string) gosnappi.Config {
	t.Helper()
	ateConfig := gosnappi.NewConfig()

	// Create ATE Ports
	p1 := ate.Port(t, "port1")
	p2 := ate.Port(t, "port2")

	// First, define OTG ports
	atePort1 := ateConfig.Ports().Add().SetName(p1.ID())
	atePort2 := ateConfig.Ports().Add().SetName(p2.ID())

	ateP1ConfigParams := ateConfigParams{
		atePort:       atePort1,
		atePortAttrs:  ateP1,
		dutPortAttrs:  dutP1,
		ateAS:         ate1AS,
		hostIPv4Start: host1IPv4Start,
		hostIPv6Start: host1IPv6Start,
	}

	ateP2ConfigParams := ateConfigParams{
		atePort:       atePort2,
		atePortAttrs:  ateP2,
		dutPortAttrs:  dutP2,
		bmpName:       bmpName,
		hostIPv4Start: host2IPv4Start,
		hostIPv6Start: host2IPv6Start,
	}

	// ATE Device 1 (EBGP)
	configureBGPOnATEDevice(t, ateConfig, ateP1ConfigParams)
	// ATE Device 2 (BMP)
	configureBMPOnATEDevice(t, ateConfig, ateP2ConfigParams)
	return ateConfig
}

// configureATEDevice configures the ports along with the associated protocols.
func configureBGPOnATEDevice(t *testing.T, cfg gosnappi.Config, params ateConfigParams) {
	t.Helper()
	var peerTypeV4 gosnappi.BgpV4PeerAsTypeEnum
	var peerTypeV6 gosnappi.BgpV6PeerAsTypeEnum

	dev := cfg.Devices().Add().SetName(params.atePortAttrs.Name)
	eth := dev.Ethernets().Add().SetName(params.atePortAttrs.Name + "Eth").SetMac(params.atePortAttrs.MAC)
	eth.Connection().SetPortName(params.atePort.Name())

	ip4 := eth.Ipv4Addresses().Add().SetName(params.atePortAttrs.Name + ".IPv4")
	ip4.SetAddress(params.atePortAttrs.IPv4).SetGateway(params.dutPortAttrs.IPv4).SetPrefix(uint32(params.atePortAttrs.IPv4Len))

	ip6 := eth.Ipv6Addresses().Add().SetName(params.atePortAttrs.Name + ".IPv6")
	ip6.SetAddress(params.atePortAttrs.IPv6).SetGateway(params.dutPortAttrs.IPv6).SetPrefix(uint32(params.atePortAttrs.IPv6Len))

	bgp := dev.Bgp().SetRouterId(params.atePortAttrs.IPv4)
	peerTypeV4 = gosnappi.BgpV4PeerAsType.EBGP
	peerTypeV6 = gosnappi.BgpV6PeerAsType.EBGP

	bgpV4 := bgp.Ipv4Interfaces().Add().SetIpv4Name(ip4.Name())
	v4Peer := bgpV4.Peers().Add().SetName(params.atePortAttrs.Name + ".BGPv4.Peer").SetPeerAddress(params.dutPortAttrs.IPv4).SetAsNumber(params.ateAS).SetAsType(peerTypeV4)

	bgpV6 := bgp.Ipv6Interfaces().Add().SetIpv6Name(ip6.Name())
	v6Peer := bgpV6.Peers().Add().SetName(params.atePortAttrs.Name + ".BGPv6.Peer").SetPeerAddress(params.dutPortAttrs.IPv6).SetAsNumber(params.ateAS).SetAsType(peerTypeV6)

	// Advertise host routes
	addBGPRoutes(v4Peer.V4Routes().Add(), params.atePortAttrs.Name+".Host.v4", params.hostIPv4Start, hostIPv4PfxLen, routeCountV4, ip4.Address())
	addBGPRoutes(v6Peer.V6Routes().Add(), params.atePortAttrs.Name+".Host.v6", params.hostIPv6Start, hostIPv6PfxLen, routeCountV6, ip6.Address())

}

// configureATEDevice configures the ports along with the associated protocols.
func configureBMPOnATEDevice(t *testing.T, cfg gosnappi.Config, params ateConfigParams) {
	t.Helper()

	dev := cfg.Devices().Add().SetName(params.atePortAttrs.Name)
	eth := dev.Ethernets().Add().SetName(params.atePortAttrs.Name + "Eth").SetMac(params.atePortAttrs.MAC)
	eth.Connection().SetPortName(params.atePort.Name())

	ip4 := eth.Ipv4Addresses().Add().SetName(params.atePortAttrs.Name + ".IPv4")
	ip4.SetAddress(params.atePortAttrs.IPv4).SetGateway(params.dutPortAttrs.IPv4).SetPrefix(uint32(params.atePortAttrs.IPv4Len))

	ip6 := eth.Ipv6Addresses().Add().SetName(params.atePortAttrs.Name + ".IPv6")
	ip6.SetAddress(params.atePortAttrs.IPv6).SetGateway(params.dutPortAttrs.IPv6).SetPrefix(uint32(params.atePortAttrs.IPv6Len))

	// --- BMP Configuration ---
	bmpIntf := dev.Bmp().Ipv4Interfaces().Add()
	bmpIntf.SetIpv4Name(ip4.Name()) //Name of the IPv4 intf on which you want to run BMP
	bmpServer := bmpIntf.Servers().Add()
	bmpServer.SetName(params.bmpName)
	bmpServer.SetClientIp(params.dutPortAttrs.IPv4)                // Connected reachable DUT IP
	bmpServer.Connection().Passive().SetListenPort(bmpStationPort) // BMP port configured on DUT

}

// addBGPRoutes adds BGP route advertisements to an ATE device.
func addBGPRoutes[R any](routes R, name, startAddress string, prefixLen, count uint32, nextHop string) {
	switch r := any(routes).(type) {
	case gosnappi.BgpV4RouteRange:
		r.SetName(name).SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL).SetNextHopIpv4Address(nextHop)
		r.Addresses().Add().SetAddress(startAddress).SetPrefix(prefixLen).SetCount(count)
	case gosnappi.BgpV6RouteRange:
		r.SetName(name).SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6).SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL).SetNextHopIpv6Address(nextHop)
		r.Addresses().Add().SetAddress(startAddress).SetPrefix(prefixLen).SetCount(count)
	}
}

func verifyBMPSessionOnATE(t *testing.T, ate *ondatra.ATEDevice, bmpName string) {
	t.Helper()
	otg := ate.OTG()

	bmpServer := gnmi.OTG().BmpServer(bmpName)

	_, ok := gnmi.Watch(t, otg, bmpServer.SessionState().State(), 1*time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BmpServer_SessionState]) bool {
		state, ok := val.Val()
		return ok && state == otgtelemetry.BmpServer_SessionState_UP
	}).Await(t)
	if !ok {
		fptest.LogQuery(t, "ATE BMP session state", bmpServer.State(), gnmi.Get(t, otg, bmpServer.State()))
		t.Fatalf("BMP Session state is not UP")
	}
	fptest.LogQuery(t, "ATE BMP session state", bmpServer.State(), gnmi.Get(t, otg, bmpServer.State()))
	t.Log("BMP session is UP")
}

func verifyBMPStatisticsReporting(t *testing.T, ate *ondatra.ATEDevice, bmpName string) {
    t.Helper()
    t.Log("Checking BMP statistics reporting on ATE before and after the interval")

    bmpServer := gnmi.OTG().BmpServer(bmpName)

    initialStatCounter := gnmi.Get(t, ate.OTG(), bmpServer.Counters().StatisticsMessagesReceived().State())
    t.Logf("Initial BMP statistics counter: %v", initialStatCounter)

    time.Sleep(60 * time.Second)

    updatedStatCounter := gnmi.Get(t, ate.OTG(), bmpServer.Counters().StatisticsMessagesReceived().State())
    t.Logf("Updated BMP statistics counter: %v", updatedStatCounter)

    if updatedStatCounter <= initialStatCounter {
        t.Errorf("BMP statistics counter did not increment after 60 seconds. Initial: %v, Updated: %v", initialStatCounter, updatedStatCounter)
    } else {
        t.Log("BMP statistics counter incremented as expected.")
    }
}

func TestBMPBaseSession(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")

	t.Log("Start DUT Configuration")
	configureDUT(t, dut)
	t.Log("Start ATE Configuration")
	otgConfig := configureATE(t, ate, bmpName)
	ate.OTG().PushConfig(t, otgConfig)
	ate.OTG().StartProtocols(t)

	t.Log("Verify DUT BGP sessions up")
	cfgplugins.VerifyDUTBGPEstablished(t, dut)

	t.Log("Verify OTG BGP sessions up")
	cfgplugins.VerifyOTGBGPEstablished(t, ate)

	type testCase struct {
		name string
		fn   func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "1.1.1_Verify_BMP_Session_Establishment",
			fn: func(t *testing.T) {

				t.Log("Verify BMP session on ATE")
				verifyBMPSessionOnATE(t, ate, bmpName)
			},
		},
		{
			name: "1.1.2_Verify_Statisitics_Reporting",
			fn: func(t *testing.T) {
				t.Log("Verify BMP session on DUT")
				verifyBMPStatisticsReporting(t, ate, bmpName)
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t)
		})
	}
}
