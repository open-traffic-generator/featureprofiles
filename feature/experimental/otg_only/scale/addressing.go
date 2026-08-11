package scale

import (
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// Addressing
//
// The arithmetic behind the per-session addressing the tests use. The scheme
// itself -- one subnet per session pair, the port1 side taking the low host and
// the port2 side the next one, so that each pair is its own broadcast domain --
// is the test's; these functions only implement it.
// ---------------------------------------------------------------------------

// SessionIPv4 returns host address `host` inside session i's own /24: session 1
// is base+256 (18.0.1.0/24 for the default base), session 2 is 18.0.2.0/24, and
// so on. An 18.0.0.0/8 base covers 65535 sessions.
func SessionIPv4(t *testing.T, base string, i uint32, host byte) net.IP {
	t.Helper()
	ip := net.ParseIP(base)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("subnet base %q is not a valid IPv4 address", base)
	}
	return nextIPv4(ip, uint(i)*256+uint(host))
}

// SessionIPv6 returns host address `host` inside session i's own /64: the base
// address with its 4th hextet set to the session index, e.g. session 1 ->
// 2001:db8:0:1::/64 holding ::1 (port1) and ::2 (port2). 65535 sessions fit.
func SessionIPv6(t *testing.T, base string, i uint32, host byte) net.IP {
	t.Helper()
	ip := net.ParseIP(base)
	if ip == nil || ip.To4() != nil {
		t.Fatalf("subnet base %q is not a valid IPv6 address", base)
	}
	if i > 0xFFFF {
		t.Fatalf("session index %d does not fit the 16-bit subnet id", i)
	}
	out := make(net.IP, net.IPv6len)
	copy(out, ip.To16())
	out[6], out[7] = byte(i>>8), byte(i)
	out[15] = host
	return out
}

// RouteStartIPv4 returns the first address of session i's block of `routes`
// contiguous IPv4 prefixes, counting from base.
func RouteStartIPv4(base string, i, routes uint32) string {
	return nextIPv4(net.ParseIP(base), uint((i-1)*routes)).String()
}

// RouteStartIPv6 is RouteStartIPv4 for IPv6 route ranges.
func RouteStartIPv6(base string, i, routes uint32) string {
	return nextIPv6(net.ParseIP(base), uint((i-1)*routes)).String()
}

// RouterIDFor returns the router ID for session index i: the session index
// added to an IPv4 base, so the router ID lines up with the device's subnet
// (2001:db8:0:i::/64 -> 10.1.0.i on port1). The OTG model validates router_id as
// an IPv4 address, which is why a v6 interface address cannot be used verbatim.
func RouterIDFor(t *testing.T, base string, i uint32) string {
	t.Helper()
	ip := net.ParseIP(base)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("router ID base %q is not a valid IPv4 address", base)
	}
	return nextIPv4(ip, uint(i)).String()
}

// MACFor returns macStart incremented by (i-1).
func MACFor(t *testing.T, macStart string, i uint32) string {
	t.Helper()
	hw, err := net.ParseMAC(macStart)
	if err != nil {
		t.Fatalf("cannot parse MAC %s: %v", macStart, err)
	}
	v := uint64(0)
	for _, b := range hw {
		v = v<<8 | uint64(b)
	}
	v += uint64(i - 1)
	for p := 5; p >= 0; p-- {
		hw[p] = byte(v & 0xFF)
		v >>= 8
	}
	return hw.String()
}

// VLANIDs maps a 1-based session index onto its (inner dot1q, outer QinQ) tag
// pair. The inner id cycles 1..4095 and the outer advances once per cycle, so
// both stay in range and stay unique up to 4095*4095 sessions.
func VLANIDs(i uint32) (inner, outer uint32) {
	if i == 0 {
		return 0, 1
	}
	band := (i - 1) / 4095
	return i - band*4095, band + 1
}

// nextIPv4 returns the IPv4 address ip incremented by inc.
func nextIPv4(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	return net.IPv4(byte((v>>24)&0xFF), byte((v>>16)&0xFF), byte((v>>8)&0xFF), byte(v&0xFF))
}

// nextIPv6 returns ip incremented by inc, carrying over the low 32 bits of the
// address. This keeps the increment simple while comfortably covering the
// address ranges these tests need (tens of thousands of sessions).
func nextIPv6(ip net.IP, inc uint) net.IP {
	i := ip.To16()
	out := make(net.IP, net.IPv6len)
	copy(out, i)
	v := uint(i[12])<<24 + uint(i[13])<<16 + uint(i[14])<<8 + uint(i[15])
	v += inc
	out[12] = byte((v >> 24) & 0xFF)
	out[13] = byte((v >> 16) & 0xFF)
	out[14] = byte((v >> 8) & 0xFF)
	out[15] = byte(v & 0xFF)
	return out
}
