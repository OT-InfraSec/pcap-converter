package parser

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The frames below follow the CDP wire layout (TLV list behind 802.3 + LLC/SNAP 00000c/2000)
// as sent by Cisco switches. They are synthesized, not captured from a device.

// cdpAddrEntry encodes one entry of an Address TLV: protocol type, protocol bytes, address.
func cdpAddrEntry(protoType byte, proto, addr []byte) []byte {
	out := []byte{protoType, byte(len(proto))}
	out = append(out, proto...)
	out = append(out, u16(uint16(len(addr)))...)
	return append(out, addr...)
}

func cdpAddrTLV(typ uint16, entries ...[]byte) []byte {
	v := u32(uint32(len(entries)))
	for _, e := range entries {
		v = append(v, e...)
	}
	return tlv(typ, v)
}

var (
	protoIPv4NLPID  = []byte{0xcc}
	protoGopacketV6 = []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00} // the value gopacket decodes as IPv6
	protoSNAPIPv6   = []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd} // what real devices send for IPv6
)

// decodeLikeParser decodes a frame with the options ParseFile uses.
func decodeLikeParser(frame []byte) gopacket.Packet {
	return gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
}

func TestCDPInfoFromPacket(t *testing.T) {
	good := []byte("sw")
	untagged := func(tlvs ...[]byte) []byte { return cdpFrame(cdpSrcMAC, -1, tlvs...) }
	tagged := func(vlan int, tlvs ...[]byte) []byte { return cdpFrame(cdpSrcMAC, vlan, tlvs...) }

	qinq := func() []byte {
		f := tagged(40, tlv(0x0001, good))
		out := append([]byte{}, f[:12]...)
		out = append(out, 0x88, 0xa8, 0x00, 100)
		return append(out, f[12:]...)
	}()

	// tagged frame whose LLC/SNAP header carries another Cisco protocol (DTP, PID 0x2004)
	dtp := tagged(40, tlv(0x0001, good))
	copy(dtp[12+4+2+6:], []byte{0x20, 0x04}) // PID: after tag(4)+len(2)+LLC(3)+OUI(3) counted from the frame start
	// tagged IPv4 frame: the tag holds a real EtherType, not a length
	ipv4 := append(append([]byte{}, tagged(40, tlv(0x0001, good))[:12]...), 0x81, 0x00, 0x00, 40, 0x08, 0x00, 0x45, 0x00, 0, 20)
	// tagged STP-style LLC (42 42 03)
	stp := tagged(40, tlv(0x0001, good))
	copy(stp[12+4+2:], []byte{0x42, 0x42, 0x03})

	for _, tc := range []struct {
		name  string
		frame []byte
		want  string // device ID, empty = no info expected
	}{
		{"untagged", untagged(tlv(0x0001, good)), "sw"},
		{"tagged", tagged(40, tlv(0x0001, good)), "sw"},
		{"priority tag VID 0", tagged(0, tlv(0x0001, good)), "sw"},
		{"reserved VID 4095", tagged(4095, tlv(0x0001, good)), "sw"},
		{"QinQ", qinq, "sw"},
		{"tagged DTP", dtp, ""},
		{"tagged IPv4", ipv4, ""},
		{"tagged STP LLC", stp, ""},
		{"untagged hostile prefix length", untagged(tlv(0x0001, good), tlv(0x0007, []byte{10, 0, 0, 0, 200})), ""},
		{"tagged hostile prefix length", tagged(40, tlv(0x0001, good), tlv(0x0007, []byte{10, 0, 0, 0, 200})), ""},
		{"untagged hostile address length", untagged(tlv(0x0002, append(u32(1), 1, 1, 0xcc, 0, 200, 10, 0, 0, 1))), ""},
		{"tagged hostile address length", tagged(40, tlv(0x0002, append(u32(1), 1, 1, 0xcc, 0, 200, 10, 0, 0, 1))), ""},
		{"truncated TLV untagged", untagged(tlv(0x0001, good))[:len(untagged(tlv(0x0001, good)))-1], ""},
		{"truncated TLV tagged", tagged(40, tlv(0x0001, good))[:len(tagged(40, tlv(0x0001, good)))-1], ""},
		{"TLV shorter than its header", untagged([]byte{0x00, 0x01, 0x00, 0x02}), ""},
		{"garbage", []byte{1, 2, 3, 4, 5}, ""},
		{"empty", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var info *layers.CiscoDiscoveryInfo
			require.NotPanics(t, func() { info = cdpInfoFromPacket(decodeLikeParser(tc.frame)) })
			if tc.want == "" {
				assert.Nil(t, info)
				return
			}
			require.NotNil(t, info)
			assert.Equal(t, tc.want, info.DeviceID)
		})
	}
}

func TestCDPProtocol_CapabilityBits(t *testing.T) {
	for _, tc := range []struct {
		mask  uint32
		token string
	}{
		{0x001, "router"}, {0x002, "bridge"}, {0x004, "bridge"}, {0x008, "switch"}, {0x010, "host"},
		{0x020, "igmp"}, {0x040, "repeater"}, {0x080, "phone"}, {0x100, "remote-managed"}, {0x000, ""},
		{0x200, ""}, // bit gopacket does not know
		{0x009, "router,switch"},
	} {
		repo := importFrames(t, [][]byte{cdpFrame(cdpSrcMAC, -1, tlv(0x0001, []byte("sw")), tlv(0x0004, u32(tc.mask)))})
		got := cdpNeighbors(t, repo)
		require.Len(t, got, 1, "mask %#x", tc.mask)
		assert.Equal(t, tc.token, got[0].Capabilities, "mask %#x", tc.mask)
	}
}

func TestCDPProtocol_AddressEncodings(t *testing.T) {
	v6 := net.ParseIP("2001:db8::10")
	repo := importFrames(t, [][]byte{cdpFrame(cdpSrcMAC, -1,
		tlv(0x0001, []byte("sw")),
		cdpAddrTLV(0x0002,
			cdpAddrEntry(1, protoIPv4NLPID, net.ParseIP("10.0.0.1").To4()),
			cdpAddrEntry(2, protoGopacketV6, v6),                        // decoded by gopacket
			cdpAddrEntry(2, protoSNAPIPv6, net.ParseIP("2001:db8::99")), // real encoding: ignored
			cdpAddrEntry(1, []byte{0x81}, []byte{1, 2, 3}),              // CLNP: ignored
			cdpAddrEntry(1, protoIPv4NLPID, net.ParseIP("10.0.0.7").To4()),
		),
		cdpAddrTLV(0x0016, cdpAddrEntry(1, protoIPv4NLPID, net.ParseIP("192.0.2.9").To4())),
	)})
	got := cdpNeighbors(t, repo)
	require.Len(t, got, 1)
	// Known limitation, pinned here: gopacket matches IPv6 on SNAP type 0x0800, so addresses sent
	// with the real 0x86dd are dropped. Order of the remaining entries is the advertised order.
	assert.Equal(t, "10.0.0.1,2001:db8::10,10.0.0.7", got[0].Addresses)
	assert.Equal(t, "192.0.2.9", got[0].MgmtAddresses)
}

func TestCDPProtocol_VersionAndFraming(t *testing.T) {
	build := func(version byte) []byte {
		f := cdpFrame(cdpSrcMAC, -1, tlv(0x0001, []byte("sw")))
		f[14+8] = version // 14 = 802.3 header, 8 = LLC + SNAP
		return f
	}
	for _, tc := range []struct {
		version byte
		want    int
	}{{1, 1}, {2, 1}, {0, 0}, {3, 0}, {255, 0}} {
		repo := importFrames(t, [][]byte{build(tc.version)})
		assert.Len(t, cdpNeighbors(t, repo), tc.want, "version %d", tc.version)
	}
}

func TestCDPProtocol_UnknownAndDuplicateTLVs(t *testing.T) {
	repo := importFrames(t, [][]byte{cdpFrame(cdpSrcMAC, -1,
		tlv(0x0001, []byte("first")),
		tlv(0x7fff, []byte{1, 2, 3, 4}), // unknown type: ignored
		tlv(0x0001, []byte("second")),   // duplicate: gopacket keeps the last
		tlv(0x0009, []byte("VTPDOMAIN")),
		tlv(0x000b, []byte{1}),           // duplex
		tlv(0x0010, u16(150)),            // power
		tlv(0x0012, []byte{0}),           // extended trust
		tlv(0x0013, []byte{0}),           // untrusted COS
		tlv(0x0017, []byte{1, 'r', '1'}), // location
	)})
	got := cdpNeighbors(t, repo)
	require.Len(t, got, 1)
	assert.Equal(t, "second", got[0].DeviceID)
}

func TestCDPProtocol_RealisticSwitchFrame(t *testing.T) {
	version := "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)\r\n" +
		"Technical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2020 by Cisco Systems, Inc.\r\n"
	frame := cdpFrame(cdpSrcMAC, -1,
		tlv(0x0001, []byte("SW-ACCESS-01.plant.example")),
		cdpAddrTLV(0x0002, cdpAddrEntry(1, protoIPv4NLPID, net.ParseIP("10.10.0.5").To4())),
		tlv(0x0003, []byte("GigabitEthernet1/0/24")),
		tlv(0x0004, u32(0x28)),
		tlv(0x0005, []byte(version)),
		tlv(0x0006, []byte("cisco WS-C2960X-24PS-L")),
		tlv(0x0009, []byte("PLANT")),
		tlv(0x000a, u16(1)),
		tlv(0x000b, []byte{1}),
		tlv(0x0010, u16(0)),
		tlv(0x0012, []byte{0}),
		tlv(0x0013, []byte{0}),
		tlv(0x0014, []byte("SW-ACCESS-01")),
		cdpAddrTLV(0x0016, cdpAddrEntry(1, protoIPv4NLPID, net.ParseIP("10.10.0.5").To4())),
		tlv(0x0017, append([]byte{1}, "Building 4, rack 2"...)),
		tlv(0x00ff, []byte{0xde, 0xad}),
	)
	repo := importFrames(t, [][]byte{frame, frame})

	got := cdpNeighbors(t, repo)
	require.Len(t, got, 1)
	n := got[0]
	assert.Equal(t, "SW-ACCESS-01.plant.example", n.DeviceID)
	assert.Equal(t, "GigabitEthernet1/0/24", n.PortID)
	assert.Equal(t, "igmp,switch", n.Capabilities)
	assert.Equal(t, "cisco WS-C2960X-24PS-L", n.Platform)
	assert.Equal(t, "SW-ACCESS-01", n.SysName)
	assert.Equal(t, "10.10.0.5", n.Addresses)
	assert.Equal(t, "10.10.0.5", n.MgmtAddresses)
	require.NotNil(t, n.NativeVLAN)
	assert.Equal(t, 1, *n.NativeVLAN)
	assert.Nil(t, n.ManagementVLAN, "no cluster-management TLV")
	assert.Nil(t, n.VlanID)
	assert.LessOrEqual(t, len(n.SoftwareVersion), maxCDPStringBytes)
	assert.True(t, strings.HasPrefix(n.SoftwareVersion, "Cisco IOS Software, C2960X Software"))
	assert.NotContains(t, n.SoftwareVersion, "\r")
	assert.NotContains(t, n.SoftwareVersion, "\n")
	assert.Contains(t, n.SoftwareVersion, "RELEASE SOFTWARE (fc3) Technical Support", "line breaks became spaces")
	assert.Empty(t, subnetKeys(t, repo), "no IP Prefix TLV, no subnets")
}

func TestCDPProtocol_FrameVLANs(t *testing.T) {
	repo := importFrames(t, [][]byte{
		fullCDPFrame(cdpSrcMAC, 4095, 10), // reserved ID is a legal tag value: stored, import continues
		fullCDPFrame(cdpSrcMAC, 0, 10),    // priority tag only: untagged
		fullCDPFrame(cdpSrcMAC, 1, 10),
		fullCDPFrame(cdpSrcMAC, 4094, 10),
		vlanFrame(t, 10), // other traffic after the CDP frames is still imported
	})
	byVLAN := map[string]bool{}
	for _, n := range cdpNeighbors(t, repo) {
		byVLAN[model_token(n.VlanID)] = true
	}
	assert.Equal(t, map[string]bool{"4095": true, "untagged": true, "1": true, "4094": true}, byVLAN)

	keys := subnetKeys(t, repo)
	assert.True(t, keys[subnetKey{"10.0.1.0/24", "4095", "cdp", "advertised"}])
	assert.True(t, keys[subnetKey{"10.0.1.0/24", "untagged", "cdp", "advertised"}])
}

func model_token(v *int) string {
	if v == nil {
		return "untagged"
	}
	return fmt.Sprint(*v)
}

func TestCDPProtocol_SameAdvertisementInTwoVLANsIsTwoRows(t *testing.T) {
	repo := importFrames(t, [][]byte{fullCDPFrame(cdpSrcMAC, 10, 10), fullCDPFrame(cdpSrcMAC, 20, 10)})
	assert.Len(t, cdpNeighbors(t, repo), 2)
}

func TestCDPProtocol_CDPAndDHCPSamePrefixAreSeparateRows(t *testing.T) {
	repo := importFrames(t, [][]byte{
		dhcpv4ReplyFrame(t, -1, "10.0.1.50", "255.255.255.0", "10.0.1.1"),
		fullCDPFrame(cdpSrcMAC, -1, 10),
	})
	keys := subnetKeys(t, repo)
	assert.True(t, keys[subnetKey{"10.0.1.0/24", "untagged", "dhcp", "on-link"}])
	assert.True(t, keys[subnetKey{"10.0.1.0/24", "untagged", "cdp", "advertised"}])
	assert.True(t, keys[subnetKey{"10.0.2.0/24", "untagged", "cdp", "advertised"}])
	assert.Len(t, keys, 3)
}

func TestCDPProtocol_HostileStringsAreStoredClean(t *testing.T) {
	long := strings.Repeat("ä", 400) // 800 bytes
	repo := importFrames(t, [][]byte{cdpFrame(cdpSrcMAC, -1,
		tlv(0x0001, []byte("dev\x00ice\x1b[31m\xff")),
		tlv(0x0003, []byte(long)),
		tlv(0x0006, []byte("a\r\nb")),
		tlv(0x0014, []byte("\x01\x02")),
	)})
	got := cdpNeighbors(t, repo)
	require.Len(t, got, 1)
	assert.Equal(t, "device[31m", got[0].DeviceID)
	assert.LessOrEqual(t, len(got[0].PortID), maxCDPStringBytes)
	assert.True(t, strings.HasPrefix(long, got[0].PortID), "cut on a character boundary")
	assert.Equal(t, "a b", got[0].Platform)
	assert.Equal(t, "", got[0].SysName)
}

func TestCDPProtocol_EmptyAndAnonymousFramesYieldNothing(t *testing.T) {
	repo := importFrames(t, [][]byte{
		cdpFrame(cdpSrcMAC, -1),                                             // no TLVs at all
		cdpFrame(cdpSrcMAC, -1, tlv(0x0004, u32(0x08))),                     // capabilities only
		cdpFrame(cdpSrcMAC, 10, tlv(0x0003, []byte("Gi1/0/1"))),             // port only
		cdpFrame(cdpSrcMAC, -1, tlv(0x0007, cdpPrefixValue("10.5.0.0/16"))), // prefixes only
	})
	assert.Empty(t, cdpNeighbors(t, repo))
	// a prefix alone is still subnet evidence even without a neighbor identity
	assert.Equal(t, map[subnetKey]bool{{"10.5.0.0/16", "untagged", "cdp", "advertised"}: true}, subnetKeys(t, repo))
}

func TestCDPProtocol_ManagementVLANVariants(t *testing.T) {
	for _, tc := range []struct {
		wire uint16
		want int // 0 = NULL
	}{{0, 0}, {1, 1}, {99, 99}, {4094, 4094}, {4095, 0}, {9999, 0}} {
		repo := importFrames(t, [][]byte{cdpFrame(cdpSrcMAC, -1, tlv(0x0001, []byte("sw")), tlv(0x0008, cdpHelloValue(tc.wire)))})
		got := cdpNeighbors(t, repo)
		require.Len(t, got, 1)
		if tc.want == 0 {
			assert.Nil(t, got[0].ManagementVLAN, "wire %d", tc.wire)
		} else {
			require.NotNil(t, got[0].ManagementVLAN, "wire %d", tc.wire)
			assert.Equal(t, tc.want, *got[0].ManagementVLAN)
		}
	}
	// a Hello TLV that is too short fails decoding; the frame is skipped
	repo := importFrames(t, [][]byte{cdpFrame(cdpSrcMAC, -1, tlv(0x0001, []byte("sw")), tlv(0x0008, make([]byte, 10)))})
	assert.Empty(t, cdpNeighbors(t, repo))
}

func TestCDPProtocol_PrefixTLVShapes(t *testing.T) {
	// the TLV is a list of 5-byte entries; any other length fails decoding
	repo := importFrames(t, [][]byte{
		cdpFrame(cdpSrcMAC, -1, tlv(0x0001, []byte("a")), tlv(0x0007, []byte{10, 0, 0, 0, 24, 1})),
		cdpFrame(cdpSrcMAC, -1, tlv(0x0001, []byte("b")), tlv(0x0007, nil)),
		cdpFrame(cdpSrcMAC, -1, tlv(0x0001, []byte("c")), tlv(0x0007, cdpPrefixValue("172.16.0.0/12", "224.0.0.0/4", "127.0.0.0/8", "169.254.0.0/16"))),
	})
	assert.Equal(t, map[subnetKey]bool{{"172.16.0.0/12", "untagged", "cdp", "advertised"}: true}, subnetKeys(t, repo))
	got := cdpNeighbors(t, repo)
	require.Len(t, got, 1, "only the well-formed frame is a neighbor")
	assert.Equal(t, "c", got[0].DeviceID)
}
