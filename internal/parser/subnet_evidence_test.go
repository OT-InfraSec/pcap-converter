package parser

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dhcp4Reply(yourIP string, opts ...layers.DHCPOption) *layers.DHCPv4 {
	return &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		YourClientIP: net.ParseIP(yourIP).To4(),
		Options:      opts,
	}
}

func optMask(m string) layers.DHCPOption {
	return layers.NewDHCPOption(layers.DHCPOptSubnetMask, net.ParseIP(m).To4())
}

func optRouters(ips ...string) layers.DHCPOption {
	var data []byte
	for _, ip := range ips {
		data = append(data, net.ParseIP(ip).To4()...)
	}
	return layers.NewDHCPOption(layers.DHCPOptRouter, data)
}

func TestDHCPv4SubnetEvidence(t *testing.T) {
	tests := []struct {
		name string
		pkt  *layers.DHCPv4
		want string // "" = no evidence
	}{
		{"valid", dhcp4Reply("10.0.1.77", optMask("255.255.255.0"), optRouters("10.0.1.1")), "10.0.1.0/24"},
		{"second router inside prefix is enough", dhcp4Reply("10.0.1.77", optMask("255.255.255.0"), optRouters("192.168.9.1", "10.0.1.1")), "10.0.1.0/24"},
		{"router outside prefix drops evidence", dhcp4Reply("10.0.1.77", optMask("255.255.255.0"), optRouters("10.0.2.1")), ""},
		{"no router option drops evidence", dhcp4Reply("10.0.1.77", optMask("255.255.255.0")), ""},
		{"no mask", dhcp4Reply("10.0.1.77", optRouters("10.0.1.1")), ""},
		{"zero offered address (NAK)", dhcp4Reply("0.0.0.0", optMask("255.255.255.0"), optRouters("10.0.1.1")), ""},
		{"non-contiguous mask", dhcp4Reply("10.0.1.77", optMask("255.0.255.0"), optRouters("10.0.1.1")), ""},
		{"/32 mask", dhcp4Reply("10.0.1.77", optMask("255.255.255.255"), optRouters("10.0.1.1")), ""},
		{"/0 mask", dhcp4Reply("10.0.1.77", optMask("0.0.0.0"), optRouters("10.0.1.1")), ""},
		{"truncated mask option", dhcp4Reply("10.0.1.77", layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255}), optRouters("10.0.1.1")), ""},
		{"truncated router tail is ignored", dhcp4Reply("10.0.1.77", optMask("255.255.255.0"), layers.NewDHCPOption(layers.DHCPOptRouter, []byte{10, 0, 1})), ""},
		{"request is not evidence", func() *layers.DHCPv4 {
			d := dhcp4Reply("10.0.1.77", optMask("255.255.255.0"), optRouters("10.0.1.1"))
			d.Operation = layers.DHCPOpRequest
			return d
		}(), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dhcpv4SubnetEvidence(tt.pkt)
			if tt.want == "" {
				assert.False(t, ok)
				return
			}
			assert.True(t, ok)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

// raPrefixOption builds the data of an ICMPv6 Prefix Information option (after type/length).
func raPrefixOption(plen byte, flags byte, prefix string) layers.ICMPv6Option {
	data := make([]byte, 30)
	data[0] = plen
	data[1] = flags
	binary.BigEndian.PutUint32(data[2:], 2592000)
	binary.BigEndian.PutUint32(data[6:], 604800)
	copy(data[14:], net.ParseIP(prefix).To16())
	return layers.ICMPv6Option{Type: layers.ICMPv6OptPrefixInfo, Data: data}
}

func TestRouterAdvertisementPrefixes(t *testing.T) {
	const L, A = 0x80, 0x40
	opts := layers.ICMPv6Options{
		raPrefixOption(64, L|A, "2001:db8:1::"),
		raPrefixOption(64, A, "2001:db8:2::"),                         // autonomous only: not on-link
		raPrefixOption(64, L|A, "fe80::"),                             // link-local
		raPrefixOption(129, L, "2001:db8:3::"),                        // invalid length
		raPrefixOption(0, L, "2001:db8:4::"),                          // /0
		{Type: layers.ICMPv6OptPrefixInfo, Data: []byte{64, L, 0, 0}}, // truncated
		{Type: layers.ICMPv6OptMTU, Data: make([]byte, 6)},
		raPrefixOption(48, L, "2001:db8:5:7::9"), // host bits masked
	}
	got := routerAdvertisementPrefixes(opts)
	want := []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:5::/48")}
	assert.Equal(t, want, got)
}

func dhcp6Opt(code layers.DHCPv6Opt, data []byte) layers.DHCPv6Option {
	return layers.DHCPv6Option{Code: code, Length: uint16(len(data)), Data: data}
}

func iaPrefix(plen byte, prefix string) []byte {
	d := make([]byte, 4+25)
	binary.BigEndian.PutUint16(d[0:], 26) // IAPREFIX
	binary.BigEndian.PutUint16(d[2:], 25)
	d[4+8] = plen
	copy(d[4+9:], net.ParseIP(prefix).To16())
	return d
}

func iaPD(subopts ...[]byte) layers.DHCPv6Option {
	data := make([]byte, 12) // IAID, T1, T2
	for _, s := range subopts {
		data = append(data, s...)
	}
	return dhcp6Opt(layers.DHCPv6OptIAPD, data)
}

func TestDHCPv6DelegatedPrefixes(t *testing.T) {
	reply := func(opts ...layers.DHCPv6Option) *layers.DHCPv6 {
		return &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeReply, Options: opts}
	}

	t.Run("IA_PD yields prefix", func(t *testing.T) {
		got := dhcpv6DelegatedPrefixes(reply(iaPD(iaPrefix(56, "2001:db8:aa00::"))))
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("2001:db8:aa00::/56")}, got)
	})
	t.Run("multiple prefixes", func(t *testing.T) {
		got := dhcpv6DelegatedPrefixes(reply(iaPD(iaPrefix(56, "2001:db8:aa00::"), iaPrefix(60, "2001:db8:bb00::"))))
		assert.Len(t, got, 2)
	})
	t.Run("IA_NA yields nothing", func(t *testing.T) {
		assert.Empty(t, dhcpv6DelegatedPrefixes(reply(dhcp6Opt(layers.DHCPv6OptIANA, make([]byte, 40)))))
	})
	t.Run("solicit is not evidence", func(t *testing.T) {
		d := reply(iaPD(iaPrefix(56, "2001:db8:aa00::")))
		d.MsgType = layers.DHCPv6MsgTypeSolicit
		assert.Empty(t, dhcpv6DelegatedPrefixes(d))
	})
	t.Run("truncated and invalid sub-options", func(t *testing.T) {
		short := iaPD(iaPrefix(56, "2001:db8:aa00::")[:20])
		tooLong := iaPD(iaPrefix(129, "2001:db8:aa00::"))
		zero := iaPD(iaPrefix(0, "2001:db8:aa00::"))
		lenLies := iaPD([]byte{0, 26, 0xff, 0xff, 1, 2, 3})
		tiny := dhcp6Opt(layers.DHCPv6OptIAPD, []byte{1, 2, 3})
		assert.Empty(t, dhcpv6DelegatedPrefixes(reply(short, tooLong, zero, lenLies, tiny)))
	})
}

// relayReply wraps an encoded inner message in a Relay-Reply (RFC 8415 section 9).
func relayReply(t *testing.T, inner *layers.DHCPv6) *layers.DHCPv6 {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, inner.SerializeTo(buf, gopacket.SerializeOptions{}))
	return &layers.DHCPv6{
		MsgType: layers.DHCPv6MsgTypeRelayReply, LinkAddr: net.ParseIP("2001:db8::1"), PeerAddr: net.ParseIP("fe80::2"),
		Options: layers.DHCPv6Options{dhcp6Opt(layers.DHCPv6OptRelayMessage, buf.Bytes())},
	}
}

func TestDHCPv6DelegatedPrefixes_UnwrapsRelayReply(t *testing.T) {
	inner := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeReply, TransactionID: []byte{1, 2, 3},
		Options: layers.DHCPv6Options{iaPD(iaPrefix(56, "2001:db8:aa00::"))}}
	want := []netip.Prefix{netip.MustParsePrefix("2001:db8:aa00::/56")}

	t.Run("single relay", func(t *testing.T) {
		assert.Equal(t, want, dhcpv6DelegatedPrefixes(relayReply(t, inner)))
	})
	t.Run("nested relays", func(t *testing.T) {
		assert.Equal(t, want, dhcpv6DelegatedPrefixes(relayReply(t, relayReply(t, inner))))
	})
	t.Run("relay-forward carries client messages, not evidence", func(t *testing.T) {
		fwd := relayReply(t, inner)
		fwd.MsgType = layers.DHCPv6MsgTypeRelayForward
		assert.Empty(t, dhcpv6DelegatedPrefixes(fwd))
	})
	t.Run("relayed solicit is not evidence", func(t *testing.T) {
		solicit := *inner
		solicit.MsgType = layers.DHCPv6MsgTypeSolicit
		assert.Empty(t, dhcpv6DelegatedPrefixes(relayReply(t, &solicit)))
	})
	t.Run("garbage relay message", func(t *testing.T) {
		bad := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeRelayReply,
			Options: layers.DHCPv6Options{dhcp6Opt(layers.DHCPv6OptRelayMessage, []byte{7, 1})}}
		assert.Empty(t, dhcpv6DelegatedPrefixes(bad))
	})
	t.Run("nesting beyond the hop limit is dropped", func(t *testing.T) {
		wrapped := inner
		for i := 0; i < maxDHCPv6RelayDepth+2; i++ {
			wrapped = relayReply(t, wrapped)
		}
		assert.Empty(t, dhcpv6DelegatedPrefixes(wrapped))
	})
}
