package parser

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// The decoders read untrusted packet bytes. These fuzz targets assert the
// invariants that matter: no panic, and every returned prefix is valid, masked
// and within bounds.

func checkPrefix(t *testing.T, p netip.Prefix, v6 bool) {
	t.Helper()
	if !p.IsValid() || p != p.Masked() {
		t.Fatalf("returned invalid or unmasked prefix %v", p)
	}
	if v6 && (p.Addr().Is4() || p.Bits() < 1 || p.Bits() > 128) {
		t.Fatalf("bad IPv6 prefix %v", p)
	}
	if !v6 && (!p.Addr().Is4() || p.Bits() < 1 || p.Bits() > 31) {
		t.Fatalf("bad IPv4 prefix %v", p)
	}
}

func FuzzDHCPv4SubnetEvidence(f *testing.F) {
	f.Add([]byte{255, 255, 255, 0}, []byte{10, 0, 1, 1}, []byte{10, 0, 1, 50})
	f.Add([]byte{255, 0, 255, 0}, []byte{10, 0, 1}, []byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, mask, routers, yourIP []byte) {
		d := &layers.DHCPv4{Operation: layers.DHCPOpReply, YourClientIP: yourIP, Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptSubnetMask, mask),
			layers.NewDHCPOption(layers.DHCPOptRouter, routers),
		}}
		if p, ok := dhcpv4SubnetEvidence(d); ok {
			checkPrefix(t, p, false)
		}
	})
}

func FuzzRouterAdvertisementPrefixes(f *testing.F) {
	f.Add(raPrefixOption(64, 0xc0, "2001:db8:1::").Data)
	f.Add([]byte{64, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, p := range routerAdvertisementPrefixes(layers.ICMPv6Options{{Type: layers.ICMPv6OptPrefixInfo, Data: data}}) {
			checkPrefix(t, p, true)
		}
	})
}

func FuzzDHCPv6DelegatedPrefixes(f *testing.F) {
	f.Add([]byte{7, 1, 2, 3, 0, 25, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{13, 0, 0, 0})
	f.Fuzz(func(t *testing.T, msg []byte) {
		d := &layers.DHCPv6{}
		if d.DecodeFromBytes(msg, gopacket.NilDecodeFeedback) != nil {
			return // the layer decoder rejected it; nothing reaches our code
		}
		for _, p := range dhcpv6DelegatedPrefixes(d) {
			checkPrefix(t, p, true)
		}
	})
}
