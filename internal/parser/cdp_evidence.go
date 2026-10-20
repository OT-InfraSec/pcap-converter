package parser

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// The functions below turn a decoded CDP info layer into a neighbor record and
// subnet prefixes. They are pure and treat the input as untrusted: strings are
// bounded and cleaned, and malformed values are dropped, never reported as an error.

// maxCDPStringBytes bounds every stored text field.
const maxCDPStringBytes = 255

// sanitizeCDPString removes control characters (including NUL) and invalid UTF-8,
// then truncates to maxCDPStringBytes without splitting a character.
func sanitizeCDPString(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	if len(s) <= maxCDPStringBytes {
		return s
	}
	cut := maxCDPStringBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// cdpCapabilityTokens returns the set capability flags as sorted tokens.
func cdpCapabilityTokens(c layers.CDPCapabilities) string {
	var tokens []string // kept in alphabetical order by construction
	add := func(set bool, token string) {
		if set {
			tokens = append(tokens, token)
		}
	}
	add(c.TBBridge || c.SPBridge, "bridge")
	add(c.IsHost, "host")
	add(c.IGMPFilter, "igmp")
	add(c.IsPhone, "phone")
	add(c.RemotelyManaged, "remote-managed")
	add(c.L1Repeater, "repeater")
	add(c.L3Router, "router")
	add(c.L2Switch, "switch")
	return strings.Join(tokens, ",")
}

// cdpAddressList returns the valid addresses in advertised order, in canonical
// text form with IPv4-in-IPv6 unmapped.
func cdpAddressList(ips []net.IP) string {
	var out []string
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		out = append(out, addr.Unmap().String())
	}
	return strings.Join(out, ",")
}

// cdpNeighborFromInfo builds the neighbor record from a CDP advertisement. The
// caller fills the source MAC, VLAN and time range. Frames that identify nobody
// (no device ID and no addresses) yield false.
func cdpNeighborFromInfo(info *layers.CiscoDiscoveryInfo) (*model.CDPNeighbor, bool) {
	if info == nil {
		return nil, false
	}
	n := &model.CDPNeighbor{
		PortID:          sanitizeCDPString(info.PortID),
		DeviceID:        sanitizeCDPString(info.DeviceID),
		Platform:        sanitizeCDPString(info.Platform),
		SoftwareVersion: sanitizeCDPString(info.Version),
		SysName:         sanitizeCDPString(info.SysName),
		Capabilities:    cdpCapabilityTokens(info.Capabilities),
		Addresses:       cdpAddressList(info.Addresses),
		MgmtAddresses:   cdpAddressList(info.MgmtAddresses),
		NativeVLAN:      model.VLANFromWire(info.NativeVLAN),
		ManagementVLAN:  model.VLANFromWire(info.CDPHello.ManagementVLAN),
	}
	if n.DeviceID == "" && n.Addresses == "" && n.MgmtAddresses == "" {
		return nil, false
	}
	return n, true
}

// cdpPrefixes returns the valid entries of the IP Prefix TLV. Host-less
// networks only: length 1..max, no link-local, loopback, multicast or
// unspecified networks.
func cdpPrefixes(info *layers.CiscoDiscoveryInfo) []netip.Prefix {
	if info == nil {
		return nil
	}
	var out []netip.Prefix
	for _, ipnet := range info.IPPrefixes {
		ones, bits := ipnet.Mask.Size()
		if bits == 0 { // non-canonical mask
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if bits == 32 && addr.Is6() {
			continue
		}
		max := addr.BitLen()
		if ones < 1 || ones > max || bits != max {
			continue
		}
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out
}

// cdpSNAPHeader is LLC (AA AA 03) + SNAP with Cisco's OUI and PID 0x2000.
var cdpSNAPHeader = []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}

// cdpInfoFromPacket returns the CDP info of a frame. gopacket decodes CDP behind
// an untagged 802.3 header only; behind an 802.1Q tag the tag holds a length
// instead of an EtherType and decoding stops, so that case is decoded here from
// the tag's payload. Frames with decode errors are skipped: gopacket fills the
// info layer while decoding, so a failure leaves it half-filled.
func cdpInfoFromPacket(packet gopacket.Packet) *layers.CiscoDiscoveryInfo {
	if l := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo); l != nil {
		if packet.ErrorLayer() != nil {
			return nil
		}
		return l.(*layers.CiscoDiscoveryInfo)
	}

	all := packet.Layers()
	if len(all) == 0 {
		return nil
	}
	tag, ok := all[len(all)-1].(*layers.Dot1Q)
	if !ok || tag.Type >= 0x0600 || !bytes.HasPrefix(tag.LayerPayload(), cdpSNAPHeader) {
		return nil
	}
	// Default options keep decode-panic recovery on: the lazy path of ParseFile has none.
	inner := gopacket.NewPacket(tag.LayerPayload(), layers.LayerTypeLLC, gopacket.Default)
	if inner.ErrorLayer() != nil {
		return nil
	}
	if l := inner.Layer(layers.LayerTypeCiscoDiscoveryInfo); l != nil {
		return l.(*layers.CiscoDiscoveryInfo)
	}
	return nil
}
