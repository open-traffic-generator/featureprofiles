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

package dhcpv6

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// The testbed consists of ate:port1 -> ate:port2
//
// RUN cmd:
// go test -v feature/dhcpv6/dhcpv6_client_server_b2b_test.go \
// -binding $HOME/featuresprofile-ci/otg-b2b/otg-otg.binding \
// -testbed $HOME/featuresprofile-ci/otg-b2b/otg-otg.testbed

const (
	NetworkInstance = "default"
	ServerPoolAddr  = "2000:0:0:100::1"
	NoOfDHCPClients = 10
)

var (
	atePort1 = attrs.Attributes{
		Name: "AtePort1",
		MAC:  "00:01:01:01:01:01",
	}
	atePort2 = attrs.Attributes{
		Name:    "AtePort2",
		IPv6:    "2000:0:0:1::2",
		MAC:     "00:03:01:01:01:01",
		IPv4Len: 64,
	}
)

func GenerateMacAddress(portNo uint32, deviceNo uint32) string {
	deviceNoAsCharFirstByte := deviceNo / 255
	deviceNoAsCharSecondByte := deviceNo % 255
	mac := fmt.Sprintf("00:%02x:00:%02x:%02x:00", portNo+1, deviceNoAsCharFirstByte, deviceNoAsCharSecondByte)
	return mac
}

func GenerateDhcpIp(deviceNo uint32) string {
	deviceNoAsCharSecondByte := deviceNo % 255
	dhcpIp := fmt.Sprintf("2000:0:0:100::%d", deviceNoAsCharSecondByte)
	return dhcpIp
}

func GenerateExpectedDhcpClientAddrList(t *testing.T) []string {
	DhcpAddrList := []string{}
	// for i := 0; i < 4; i++{
	for i := 1; i <= NoOfDHCPClients; i++ {
		dhcpIp := GenerateDhcpIp(uint32(i))
		DhcpAddrList = append(DhcpAddrList, dhcpIp)
		// t.Logf("DhcpAddrList %v", DhcpAddrList)
	}
	return DhcpAddrList
}

// WaitForDhcpClients maps through all the dhcpv6 clients to verify expected DHCP counters
func WaitForDhcpClients(t *testing.T, otg *otg.OTG, c gosnappi.Config) {
	dhcpNames := []string{}
	for _, d := range c.Devices().Items() {
		for _, e := range d.Ethernets().Items() {
			for _, dhcp := range e.Dhcpv6Interfaces().Items() {
				dhcpNames = append(dhcpNames, dhcp.Name())
			}
		}
	}

	for _, dhcpName := range dhcpNames {
		got, ok := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv6Client(dhcpName).Counters().SolicitsSent().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCPv6 SolicitsSent  %v %v", gnmi.OTG().Dhcpv6Client(dhcpName).Counters().SolicitsSent().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok {
			t.Fatalf("Did not receive DHCPv6 Expected stats for client %s, last got: %v", dhcpName, got)
		}
		got1, ok1 := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv6Client(dhcpName).Counters().AdvertisementsReceived().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCPv6 AdvertisementsReceived  %v %v", gnmi.OTG().Dhcpv6Client(dhcpName).Counters().AdvertisementsReceived().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok1 {
			t.Fatalf("Did not receive DHCPv6 Expected stats for client %s, last got: %v", dhcpName, got1)
		}
		got2, ok2 := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv4Client(dhcpName).Counters().RequestsSent().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCPv6 RequestsSent  %v %v", gnmi.OTG().Dhcpv4Client(dhcpName).Counters().RequestsSent().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok2 {
			t.Fatalf("Did not receive DHCPv6 Expected stats for client %s, last got: %v", dhcpName, got2)
		}
		got3, ok3 := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv6Client(dhcpName).Counters().RepliesReceived().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCPv6 RepliesReceived  %v %v", gnmi.OTG().Dhcpv6Client(dhcpName).Counters().RepliesReceived().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok3 {
			t.Fatalf("Did not receive DHCPv6 Expected stats for client %s, last got: %v", dhcpName, got3)
		}
	}
}

// configureOTG configures the interfaces,DHCP protocols on an OTG.
func configureOTG(t *testing.T, otg *otg.OTG) gosnappi.Config {
	config := gosnappi.NewConfig()
	port1 := config.Ports().Add().SetName("port1")
	port2 := config.Ports().Add().SetName("port2")
	// OTG DHCP Client configuration
	for i := 1; i <= NoOfDHCPClients; i++ {
		// ATE1 DHCP device
		deviceName := fmt.Sprintf("DHCPv6Client%d", i)
		devDhcp1 := config.Devices().Add().SetName(atePort1.Name + deviceName)
		// ATE1 DHCP ethernet
		ethName := fmt.Sprintf(".Eth%d", i)
		macAddr := GenerateMacAddress(0, uint32(i))
		devDhcpEth1 := devDhcp1.Ethernets().Add().SetName(atePort1.Name + ethName).SetMac(macAddr)
		devDhcpEth1.Connection().SetPortName(port1.Name())
		// ATE1  DHCP Client
		dhcpName := fmt.Sprintf("DHCPv6Client%d", i)
		dhcpv6client := devDhcpEth1.Dhcpv6Interfaces().Add().
			SetName(dhcpName)
		//iatype = iana, iata, iapd and ianapd
		dhcpv6client.IaType().Iana()
		dhcpv6client.DuidType().Llt()
	}

	// ATE2 DHCP Server connection
	devDhcpServer1 := config.Devices().Add().SetName(atePort2.Name + "DHCPv6Server")
	//ATE2 DHCP Server ethernet
	devDhcpServerEth := devDhcpServer1.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	devDhcpServerEth.Connection().SetPortName(port2.Name())
	// ATE2 DHCP Server IPv6
	devDhcpServerIPv6 := devDhcpServerEth.Ipv6Addresses().Add().SetName(atePort2.Name + ".IPv6")
	devDhcpServerIPv6.SetAddress(atePort2.IPv6).SetGateway("0::0").SetPrefix(uint32(atePort2.IPv6Len))

	// ATE2 DHCP Server
	d2Dhcpv6Server := devDhcpServer1.DhcpServer().Ipv6Interfaces().Add().
		SetName("DHCPv6Server1").
		SetRapidCommit(false).
		SetReconfigureViaRelayAgent(false)

	d1Dhcpv6ServerPool := d2Dhcpv6Server.SetIpv6Name(devDhcpServerIPv6.Name()).Leases().Add()
	d1Dhcpv6ServerPool.SetLeaseTime(3600)
	IaType := d1Dhcpv6ServerPool.IaType().Iana()
	IaType.
		SetPrefix(64).
		SetStartAddress(ServerPoolAddr).
		SetStep(1).
		SetSize(NoOfDHCPClients)

	t.Logf("Pushing config to OTG and starting protocols...")
	otg.PushConfig(t, config)
	otg.StartProtocols(t)
	return config
}

// verifyOTGDHCPv6ClientTelemetry to verify the DHCP interface values
func verifyOTGDHCPv6ClientTelemetry(t *testing.T, otg *otg.OTG, c gosnappi.Config, dhcpAddress []string) {
	currAddrList := []string{}
	for _, d := range c.Devices().Items() {
		for _, ip := range d.Ethernets().Items() {
			for _, configPeer := range ip.Dhcpv6Interfaces().Items() {
				nbrPath := gnmi.OTG().Dhcpv6Client(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.Interface().Address().State(), time.Minute, func(val *ygnmi.Value[string]) bool {
					currAddr, ok := val.Val()
					currAddrList = append(currAddrList, currAddr)
					t.Logf("DHCPv6 %v Addr: %v ", configPeer.Name(), currAddr)
					return ok
				}).Await(t)
				if len(currAddrList) != len(dhcpAddress) && !ok {
					t.Errorf("DHCPv6 clients didn't get address %v %v", currAddrList, dhcpAddress)
				}
			}
		}
	}
}

// LogDHCPv6ClientStates is displaying otg DHCP CLient states.
func LogDHCPv6ClientStates(t testing.TB, otg *otg.OTG, c gosnappi.Config) {
	t.Helper()
	var out strings.Builder
	out.WriteString("\nOTG DHCPv6 Client States\n")
	fmt.Fprintln(&out, strings.Repeat("-", 120))
	out.WriteString("\n")
	fmt.Fprintf(&out,
		"%-15s%-18s%-18s%-18s%-18s%-18s%-18s\n",
		"DHCPv6 Client",
		"IPv6 Address",
		"Gateway Address",
		"Prefix Length",
		"Lease Time",
		"Renew Time",
		"Rebind Time")

	for _, d := range c.Devices().Items() {
		for _, e := range d.Ethernets().Items() {
			for _, dhcp := range e.Dhcpv6Interfaces().Items() {
				dhcpState := gnmi.Lookup(t, otg, gnmi.OTG().Dhcpv6Client(dhcp.Name()).Interface().State())
				v, isPresent := dhcpState.Val()
				if isPresent {
					ipv4addr := v.GetAddress()
					gatewayAddr := v.GetGatewayAddress()
					prefix := v.GetPrefixLength()
					leaseTime := v.GetLeaseTime()
					renewTime := v.GetRenewTime()
					rebindTime := v.GetRebindTime()
					out.WriteString(fmt.Sprintf(
						"%-15v%-18s%-18s%-18v%-18v%-18v%-18v\n",
						dhcp.Name(), ipv4addr, gatewayAddr, prefix, leaseTime, renewTime, rebindTime,
					))
				}
			}
		}
	}
	fmt.Fprintln(&out, strings.Repeat("-", 120))
	out.WriteString("\n\n")
	t.Log(out.String())
}

// TestDHCPv6ClientServer brings up dhcpv6 client and Server
func TestDHCPv6ClientServer(t *testing.T) {
	// ATE Configuration.
	t.Logf("Start ATE Config")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	var otgConfig gosnappi.Config

	t.Run("Configure OTG", func(t *testing.T) {
		otgConfig = configureOTG(t, otg)
	})

	//print OTG config in json for debug
	// conf, _ := otgConfig.Marshal().ToJson()
	// t.Logf("Printing config ---> %v", conf)

	// for MINIMAL check, we can verify if dhcp IP address is received or not and
	// skip all dhcp Counter check
	// verifyOTGDHCPv6ClientTelemetry(t, otg, otgConfig, GenerateExpectedDhcpClientAddrList(t))
	// LogDHCPv6ClientStates(t, otg, otgConfig)

	// verify DHCP client Counter
	WaitForDhcpClients(t, otg, otgConfig)

	dhcpServer := gnmi.OTG().Dhcpv6Server("DHCPv6Server1")
	// Verify DHCPv6 Server Counter
	gnmi.Watch(t, otg, dhcpServer.Counters().SolicitsReceived().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCPv6 SolicitsReceived  %v %v", dhcpServer.Counters().SolicitsReceived().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)
	gnmi.Watch(t, otg, dhcpServer.Counters().AdvertisementsSent().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCPv6 AdvertisementsSent  %v %v", dhcpServer.Counters().AdvertisementsSent().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)

	gnmi.Watch(t, otg, dhcpServer.Counters().RequestsReceived().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCPv6 Request Received  %v %v", dhcpServer.Counters().RequestsReceived().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)

	gnmi.Watch(t, otg, dhcpServer.Counters().RepliesSent().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCPv6 Server Replies Sent  %v %v", dhcpServer.Counters().RepliesSent().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)

	t.Logf("Verify OTG DHCPv6 Client States")
	verifyOTGDHCPv6ClientTelemetry(t, otg, otgConfig, GenerateExpectedDhcpClientAddrList(t))
	LogDHCPv6ClientStates(t, otg, otgConfig)
}
