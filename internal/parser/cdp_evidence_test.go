package parser

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ipnet(cidr string) net.IPNet {
	_, n, _ := net.ParseCIDR(cidr)
	return *n
}

func TestCDPNeighborFromInfo_FullFrame(t *testing.T) {
	info := &layers.CiscoDiscoveryInfo{
		DeviceID: "sw1.example", PortID: "GigabitEthernet1/0/1", Platform: "cisco WS-C3850", Version: "IOS 16.9",
		SysName:       "sw1",
		Capabilities:  layers.CDPCapabilities{L3Router: true, L2Switch: true, IGMPFilter: true},
		Addresses:     []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("2001:db8::1")},
		MgmtAddresses: []net.IP{net.ParseIP("10.0.0.2")},
		NativeVLAN:    10,
	}
	info.CDPHello.ManagementVLAN = 99

	n, ok := cdpNeighborFromInfo(info)
	require.True(t, ok)
	assert.Equal(t, "sw1.example", n.DeviceID)
	assert.Equal(t, "GigabitEthernet1/0/1", n.PortID)
	assert.Equal(t, "cisco WS-C3850", n.Platform)
	assert.Equal(t, "IOS 16.9", n.SoftwareVersion)
	assert.Equal(t, "sw1", n.SysName)
	assert.Equal(t, "igmp,router,switch", n.Capabilities)
	assert.Equal(t, "10.0.0.1,2001:db8::1", n.Addresses)
	assert.Equal(t, "10.0.0.2", n.MgmtAddresses)
	require.NotNil(t, n.NativeVLAN)
	assert.Equal(t, 10, *n.NativeVLAN)
	require.NotNil(t, n.ManagementVLAN)
	assert.Equal(t, 99, *n.ManagementVLAN)
}

func TestCDPNeighborFromInfo_VLANBounds(t *testing.T) {
	for _, tc := range []struct {
		wire uint16
		want bool
	}{{0, false}, {1, true}, {4094, true}, {4095, false}, {65535, false}} {
		info := &layers.CiscoDiscoveryInfo{DeviceID: "x", NativeVLAN: tc.wire}
		info.CDPHello.ManagementVLAN = tc.wire
		n, ok := cdpNeighborFromInfo(info)
		require.True(t, ok)
		assert.Equal(t, tc.want, n.NativeVLAN != nil, "native %d", tc.wire)
		assert.Equal(t, tc.want, n.ManagementVLAN != nil, "mgmt %d", tc.wire)
	}
}

func TestCDPCapabilityTokens(t *testing.T) {
	assert.Equal(t, "", cdpCapabilityTokens(layers.CDPCapabilities{}))
	all := layers.CDPCapabilities{L3Router: true, TBBridge: true, SPBridge: true, L2Switch: true, IsHost: true,
		IGMPFilter: true, L1Repeater: true, IsPhone: true, RemotelyManaged: true}
	assert.Equal(t, "bridge,host,igmp,phone,remote-managed,repeater,router,switch", cdpCapabilityTokens(all))
	assert.Equal(t, "bridge", cdpCapabilityTokens(layers.CDPCapabilities{SPBridge: true}))
}

func TestCDPNeighborFromInfo_SkipsAnonymous(t *testing.T) {
	_, ok := cdpNeighborFromInfo(&layers.CiscoDiscoveryInfo{Platform: "only platform"})
	assert.False(t, ok)
	_, ok = cdpNeighborFromInfo(&layers.CiscoDiscoveryInfo{DeviceID: "\x00\x01"})
	assert.False(t, ok, "device ID that is only control characters")
	_, ok = cdpNeighborFromInfo(nil)
	assert.False(t, ok)
	n, ok := cdpNeighborFromInfo(&layers.CiscoDiscoveryInfo{Addresses: []net.IP{net.ParseIP("10.0.0.1")}})
	require.True(t, ok, "addresses alone identify a neighbor")
	assert.Equal(t, "10.0.0.1", n.Addresses)
}

func TestCDPAddressList(t *testing.T) {
	got := cdpAddressList([]net.IP{
		net.ParseIP("10.0.0.1"),
		net.IP{1, 2, 3},                // malformed length: dropped
		net.ParseIP("::ffff:10.0.0.2"), // v4-in-v6 unmapped
		net.ParseIP("FE80::1"),         // canonical lowercase text
		nil,
	})
	assert.Equal(t, "10.0.0.1,10.0.0.2,fe80::1", got)
}

func TestSanitizeCDPString(t *testing.T) {
	assert.Equal(t, "abc", sanitizeCDPString("a\x00b\x1bc\n"))
	assert.Equal(t, "line one line two", sanitizeCDPString("line one\r\nline two"), "CRLF is one space")
	assert.Equal(t, "a b c", sanitizeCDPString("a\tb\nc"))
	assert.Equal(t, "x", sanitizeCDPString("  x \n"))
	assert.Equal(t, "", sanitizeCDPString("\x00\r\n \x01"))
	assert.Equal(t, "ab", sanitizeCDPString("a\xffb"), "invalid UTF-8 removed")
	assert.Equal(t, "ä ö", sanitizeCDPString("ä ö"))

	long := strings.Repeat("a", 1000)
	assert.Len(t, sanitizeCDPString(long), maxCDPStringBytes)

	// a multi-byte character straddling the limit is dropped whole
	s := strings.Repeat("a", maxCDPStringBytes-1) + "ä"
	got := sanitizeCDPString(s)
	assert.Equal(t, strings.Repeat("a", maxCDPStringBytes-1), got)
}

func TestCDPPrefixes(t *testing.T) {
	info := &layers.CiscoDiscoveryInfo{IPPrefixes: []net.IPNet{
		ipnet("10.0.1.0/24"),
		ipnet("192.168.5.77/16"), // masked by ParseCIDR already; stays canonical
		ipnet("10.9.9.9/32"),     // max length allowed
		ipnet("0.0.0.0/0"),       // length 0
		ipnet("0.0.0.0/8"),       // unspecified
		ipnet("127.0.0.0/8"),
		ipnet("169.254.0.0/16"),
		ipnet("224.0.0.0/4"),
		{IP: net.IP{10, 0, 0, 0}, Mask: net.IPMask{255, 0, 255, 0}}, // non-contiguous mask
		{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)},           // malformed address
	}}
	got := cdpPrefixes(info)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.9.9.9/32"),
	}, got)
	assert.Nil(t, cdpPrefixes(nil))
}
