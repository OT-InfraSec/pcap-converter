package parser

import (
	"encoding/binary"
	"math/bits"
	"net/netip"

	"github.com/google/gopacket/layers"
)

// The functions below turn protocol options into subnet prefixes. They are pure
// and treat all bytes as untrusted: every length is checked before use and
// malformed evidence is dropped, never reported as an error.

const (
	raFlagOnLink     = 0x80
	raPrefixInfoSize = 30 // prefix length, flags, 2 lifetimes, reserved, 16-byte prefix (after type/length)
	dhcpv6IAPrefix   = 26
	dhcpv6IAPDHeader = 12 // IAID, T1, T2
	dhcpv6IAPrefixSz = 25 // preferred, valid, prefix length, 16-byte prefix
)

// dhcpv4SubnetEvidence derives the client's subnet from a DHCP reply: the
// offered address masked with option 1. It requires a router (option 3) inside
// that prefix as a plausibility check; without one the evidence is dropped.
func dhcpv4SubnetEvidence(d *layers.DHCPv4) (netip.Prefix, bool) {
	if d.Operation != layers.DHCPOpReply {
		return netip.Prefix{}, false
	}
	offered, ok := netip.AddrFromSlice(d.YourClientIP)
	if !ok || !offered.Is4() || offered.IsUnspecified() {
		return netip.Prefix{}, false
	}

	var mask []byte
	var routers [][]byte
	for _, opt := range d.Options {
		switch opt.Type {
		case layers.DHCPOptSubnetMask:
			if len(opt.Data) == 4 {
				mask = opt.Data
			}
		case layers.DHCPOptRouter:
			for i := 0; i+4 <= len(opt.Data); i += 4 {
				routers = append(routers, opt.Data[i:i+4])
			}
		}
	}
	if mask == nil {
		return netip.Prefix{}, false
	}

	m := binary.BigEndian.Uint32(mask)
	ones := bits.OnesCount32(m)
	// A contiguous mask is ones followed by zeros; /0 and /32 carry no subnet.
	if ones == 0 || ones == 32 || bits.LeadingZeros32(^m) != ones {
		return netip.Prefix{}, false
	}
	prefix := netip.PrefixFrom(offered, ones).Masked()

	for _, r := range routers {
		if addr, ok := netip.AddrFromSlice(r); ok && prefix.Contains(addr) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

// routerAdvertisementPrefixes returns the on-link prefixes announced in the
// Prefix Information options of a Router Advertisement (RFC 4861 4.6.2).
// Prefixes with only the autonomous flag, link-local prefixes and malformed
// options are skipped.
func routerAdvertisementPrefixes(opts layers.ICMPv6Options) []netip.Prefix {
	var out []netip.Prefix
	for _, opt := range opts {
		if opt.Type != layers.ICMPv6OptPrefixInfo || len(opt.Data) < raPrefixInfoSize {
			continue
		}
		plen := int(opt.Data[0])
		if plen == 0 || plen > 128 || opt.Data[1]&raFlagOnLink == 0 {
			continue
		}
		addr, ok := netip.AddrFromSlice(opt.Data[14:30])
		if !ok || addr.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, netip.PrefixFrom(addr, plen).Masked())
	}
	return out
}

// dhcpv6DelegatedPrefixes returns the prefixes of IA_PD options in a DHCPv6
// Reply. IA_NA carries no prefix length and yields nothing. A delegated prefix
// is meant for downstream use and need not be on-link where it was observed.
func dhcpv6DelegatedPrefixes(d *layers.DHCPv6) []netip.Prefix {
	if d.MsgType != layers.DHCPv6MsgTypeReply {
		return nil
	}
	var out []netip.Prefix
	for _, opt := range d.Options {
		if opt.Code != layers.DHCPv6OptIAPD || len(opt.Data) < dhcpv6IAPDHeader {
			continue
		}
		sub := opt.Data[dhcpv6IAPDHeader:]
		for len(sub) >= 4 {
			code := binary.BigEndian.Uint16(sub[0:2])
			length := int(binary.BigEndian.Uint16(sub[2:4]))
			if 4+length > len(sub) {
				break // sub-option claims more bytes than present
			}
			body := sub[4 : 4+length]
			sub = sub[4+length:]
			if code != dhcpv6IAPrefix || len(body) < dhcpv6IAPrefixSz {
				continue
			}
			plen := int(body[8])
			addr, ok := netip.AddrFromSlice(body[9:25])
			if !ok || plen == 0 || plen > 128 {
				continue
			}
			out = append(out, netip.PrefixFrom(addr, plen).Masked())
		}
	}
	return out
}
