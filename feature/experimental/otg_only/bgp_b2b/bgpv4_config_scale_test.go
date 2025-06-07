package tests

import (
	"fmt"
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	mac1                 = "00:00:02:02:02:02"
	mtu1                 = 1500
	ipv4Addr1            = "2.2.2.2"
	ipv4Gateway1         = "2.2.2.1"
	ipv4PrifixLen1       = 24
	rouderId1            = ipv4Addr1
	bgpv4As1             = 2222
	peerOfBgp1           = ipv4Gateway1
	peer1StartingRR      = "1.0.0.1"
	peer1RouteRangeCount = uint64(3)
	peer1RoutePrefixInRR = 32

	mac2                 = "00:00:03:03:03:02"
	mtu2                 = mtu1
	ipv4Addr2            = ipv4Gateway1
	ipv4Gateway2         = ipv4Addr1
	ipv4PrifixLen2       = ipv4PrifixLen1
	routerId2            = ipv4Addr2
	bgpv4As2             = 2223
	peerOfBgp2           = ipv4Gateway2
	peer2StartingRoute   = "33.33.33.3"
	peer2RouteCount      = 1
	peer2RouteStep       = 1
	peer2RoutePrefix     = 32

	minuitesToSessionUp  = 1

)



func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func TestBgpv4ScaleConfig(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	numRouteRange := peer1RouteRangeCount

	fmt.Println("Configuring and starting BGPv4 ..")
	otgConfig := Bgpv4ConfigScaleConfig(t, otg, numRouteRange)

	// print or write the json config in afile.
	//fmt.Println(config.Marshal().ToJson())
	configInJson, err := otgConfig.Marshal().ToJson()
	filename := "config.json"
	err = os.WriteFile(filename, []byte(configInJson), 0644)
	if err != nil {
		t.Fatal(err)
	}

	verifyMyOTGBGPTelemetry(t, otg, otgConfig, "ESTABLISHED")
}

// ------------------------------------------------------------------------------
// Function to convert IPv4 string given in dotted decimal format to uint32
// ------------------------------------------------------------------------------
func IPv4ToUint32(ipv4 string) uint32 {
	bytes := strings.Split(ipv4, ".")
	var ipDigits [4]uint32
	for i := 0; i < 4; i++ {
		digit, err := strconv.Atoi(bytes[i])
		if err != nil {
			panic("Invalid IP address")
		}
		ipDigits[3-i] = uint32(digit)
	}

	ipAd := (ipDigits[0]<<0 +
		ipDigits[1]<<8 +
		ipDigits[2]<<16 +
		ipDigits[3]<<24)

	return ipAd
}

// ------------------------------------------------------------------------------
// Function to convert uint32 to dotted decimal format fo IPv4 address.
// ------------------------------------------------------------------------------
func Uint32ToIPv4(ipaddr uint32) string {
	temp := ipaddr

	byte0 := temp % 256
	temp = temp / 256
	byte1 := temp % 256
	temp = temp / 256
	byte2 := temp % 256
	temp = temp / 256
	byte3 := temp % 256

	ip := (strconv.FormatUint(uint64(byte3), 10) + "." +
		strconv.FormatUint(uint64(byte2), 10) + "." +
		strconv.FormatUint(uint64(byte1), 10) + "." +
		strconv.FormatUint(uint64(byte0), 10))

	return ip
}

// -------------------------------------------------------------------------------
// Theoretically it should work
// 1. Get an IP
// 2. Convert it to int
// 3. Increment the integer
// 4. convert back to string
// -------------------------------------------------------------------------------
func NextIP4(ipv4 string) (next string) {
	tempIp := IPv4ToUint32(ipv4)
	tempIp++
	return Uint32ToIPv4(tempIp)
}

func Bgpv4ConfigScaleConfig(
	t *testing.T,
	otg *otg.OTG,
	numRouteRange uint64) gosnappi.Config {

	config := gosnappi.NewConfig()

	// add ports
	p2 := config.Ports().Add().SetName("port1")
	p3 := config.Ports().Add().SetName("port2")

	// add devices
	d2 := config.Devices().Add().SetName("d2")
	d3 := config.Devices().Add().SetName("d3")

	// add protocol stacks for device d2
	d2Eth1 := d2.Ethernets().
		Add().
		SetName("d2Eth").
		SetMac(mac1).
		SetMtu(mtu1)

	d2Eth1.Connection().SetPortName(p2.Name())

	d2Eth1.Ipv4Addresses().
		Add().
		SetName("p2d1ipv4").
		SetAddress(ipv4Addr1).
		SetGateway(ipv4Gateway1).
		SetPrefix(ipv4PrifixLen1)

	d2Bgp := d2.Bgp().
		SetRouterId(rouderId1)

	d2BgpIpv4Interface1 := d2Bgp.
		Ipv4Interfaces().Add().
		SetIpv4Name("p2d1ipv4")

	d2BgpIpv4Interface1Peer1 := d2BgpIpv4Interface1.
		Peers().
		Add().
		SetAsNumber(bgpv4As1).
		SetAsType(gosnappi.BgpV4PeerAsType.EBGP).
		SetPeerAddress(peerOfBgp1).
		SetName("p2BGPv4Peer1")

	//asNumber = 10
	ipaddr := peer1StartingRR
	for i := uint64(0); i < numRouteRange; i++ {
		d2BgpIpv4Interface1Peer1V4Route1 := d2BgpIpv4Interface1Peer1.
			V4Routes().
			Add().
			SetName("ip." + ipaddr)

		d2BgpIpv4Interface1Peer1V4Route1.Addresses().Add().
			SetAddress(ipaddr).
			SetPrefix(peer1RoutePrefixInRR).
			SetCount(1).
			SetStep(1)

		d2BgpIpv4Interface1Peer1V4Route1AsPath := d2BgpIpv4Interface1Peer1V4Route1.AsPath().
			SetAsSetMode(gosnappi.BgpAsPathAsSetMode.INCLUDE_AS_SET)

		d2BgpIpv4Interface1Peer1V4Route1AsPath.Segments().Add().
			SetAsNumbers([]uint32{200, 300, 400}).
			SetType(gosnappi.BgpAsPathSegmentType.AS_SEQ)

		ipaddr = NextIP4(ipaddr)
	}

	// add protocol stacks for device d3
	d3Eth1 := d3.Ethernets().
		Add().
		SetName("d3Eth").
		SetMac(mac2).
		SetMtu(mtu2)

	d3Eth1.Connection().SetPortName(p3.Name())

	d3Eth1.Ipv4Addresses().
		Add().
		SetName("p3d1ipv4").
		SetAddress(ipv4Addr2).
		SetGateway(ipv4Gateway2).
		SetPrefix(ipv4PrifixLen2)

	d3Bgp := d3.Bgp().
		SetRouterId(routerId2)

	d3BgpIpv4Interface1 := d3Bgp.
		Ipv4Interfaces().Add().
		SetIpv4Name("p3d1ipv4")

	d3BgpIpv4Interface1Peer1 := d3BgpIpv4Interface1.
		Peers().
		Add().
		SetAsNumber(bgpv4As2).
		SetAsType(gosnappi.BgpV4PeerAsType.EBGP).
		SetPeerAddress(peerOfBgp2).
		SetName("p3BGPv4Peer1")

	d3BgpIpv4Interface1Peer1V4Route1 := d3BgpIpv4Interface1Peer1.
		V4Routes().
		Add().
		SetName("p3d1peer1rrv4")

	d3BgpIpv4Interface1Peer1V4Route1.Addresses().Add().
		SetAddress(peer2StartingRoute).
		SetCount(peer2RouteCount).
		SetPrefix(peer2RoutePrefix).
		SetStep(peer2RouteStep)

	d3BgpIpv4Interface1Peer1V4Route1AsPath := d3BgpIpv4Interface1Peer1V4Route1.AsPath().
		SetAsSetMode(gosnappi.BgpAsPathAsSetMode.INCLUDE_AS_SET)

	d3BgpIpv4Interface1Peer1V4Route1AsPath.Segments().Add().
		SetAsNumbers([]uint32{3223, 3224, 3225}).
		SetType(gosnappi.BgpAsPathSegmentType.AS_SEQ)

	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	otg.StartProtocols(t)

	return config
}

func verifyMyOTGBGPTelemetry(t *testing.T, otg *otg.OTG, c gosnappi.Config, state string) {
	for _, d := range c.Devices().Items() {
		for _, ip := range d.Bgp().Ipv4Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(
					t,
					otg,
					nbrPath.SessionState().State(),
					time.Minute * minuitesToSessionUp,
					func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
						currState, ok := val.Val()
						return ok && currState.String() == state
					}).Await(t)
				if !ok {
					fptest.LogQuery(
						t,
						"BGP reported state",
						nbrPath.State(),
						gnmi.Get(t, otg, nbrPath.State()))

					t.Errorf("No BGP neighbor formed for peer %s",
						configPeer.Name())
				}
			}
		}
		for _, ip := range d.Bgp().Ipv6Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(
					t,
					otg,
					nbrPath.SessionState().State(),
					time.Minute,
					func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
						currState, ok := val.Val()
						return ok && currState.String() == state
					}).Await(t)
				if !ok {
					fptest.LogQuery(
						t,
						"BGP reported state",
						nbrPath.State(),
						gnmi.Get(t, otg, nbrPath.State()))

					t.Errorf("No BGP neighbor formed for peer %s",
						configPeer.Name())
				}
			}
		}
	}
}
