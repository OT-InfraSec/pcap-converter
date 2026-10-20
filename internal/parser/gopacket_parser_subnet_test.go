package parser

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	subnetSrcMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	subnetDstMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
)

// subnetFrame serializes payload layers (network layer first) behind an Ethernet header,
// optionally tagged with one 802.1Q VLAN (vlan < 0 = untagged).
func subnetFrame(t *testing.T, vlan int, ethType layers.EthernetType, payload ...gopacket.SerializableLayer) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: subnetSrcMAC, DstMAC: subnetDstMAC, EthernetType: ethType}
	stack := []gopacket.SerializableLayer{eth}
	if vlan >= 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{VLANIdentifier: uint16(vlan), Type: ethType})
	}
	stack = append(stack, payload...)
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, stack...))
	return buf.Bytes()
}

func dhcpv4ReplyFrame(t *testing.T, vlan int, yourIP, mask, router string) []byte {
	t.Helper()
	ip := &layers.IPv4{SrcIP: net.ParseIP("10.0.1.1").To4(), DstIP: net.IPv4bcast.To4(), Protocol: layers.IPProtocolUDP, TTL: 64, Version: 4, IHL: 5}
	udp := &layers.UDP{SrcPort: 67, DstPort: 68}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	dhcp := &layers.DHCPv4{
		Operation: layers.DHCPOpReply, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6,
		YourClientIP: net.ParseIP(yourIP).To4(), ClientHWAddr: subnetSrcMAC,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)}),
			layers.NewDHCPOption(layers.DHCPOptSubnetMask, net.ParseIP(mask).To4()),
			layers.NewDHCPOption(layers.DHCPOptRouter, net.ParseIP(router).To4()),
		},
	}
	return subnetFrame(t, vlan, layers.EthernetTypeIPv4, ip, udp, dhcp)
}

func raFrame(t *testing.T, vlan int, prefix string, plen byte, flags byte) []byte {
	t.Helper()
	ip := &layers.IPv6{Version: 6, SrcIP: net.ParseIP("fe80::1"), DstIP: net.ParseIP("ff02::1"), NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0)}
	require.NoError(t, icmp.SetNetworkLayerForChecksum(ip))
	ra := &layers.ICMPv6RouterAdvertisement{
		HopLimit: 64, RouterLifetime: 1800,
		Options: layers.ICMPv6Options{raPrefixOption(plen, flags, prefix)},
	}
	return subnetFrame(t, vlan, layers.EthernetTypeIPv6, ip, icmp, ra)
}

func dhcpv6ReplyFrame(t *testing.T, vlan int, plen byte, prefix string) []byte {
	t.Helper()
	ip := &layers.IPv6{Version: 6, SrcIP: net.ParseIP("fe80::1"), DstIP: net.ParseIP("fe80::2"), NextHeader: layers.IPProtocolUDP, HopLimit: 64}
	udp := &layers.UDP{SrcPort: 547, DstPort: 546}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	pd := iaPD(iaPrefix(plen, prefix))
	dhcp := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeReply, TransactionID: []byte{1, 2, 3}, Options: layers.DHCPv6Options{pd}}
	return subnetFrame(t, vlan, layers.EthernetTypeIPv6, ip, udp, dhcp)
}

func importFrames(t *testing.T, frames [][]byte) repository.Repository {
	t.Helper()
	repo, err := repository.NewSQLiteRepositoryWithCanonicalizer(filepath.Join(t.TempDir(), "out.sqlite"), helper.NewFlowCanonicalizer())
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Close() })
	require.NoError(t, NewGopacketParser(writeVLANPCAP(t, frames), repo, "t").ParseFile())
	return repo
}

type subnetKey struct {
	cidr, vlan, source, kind string
}

func subnetKeys(t *testing.T, repo repository.Repository) map[subnetKey]bool {
	t.Helper()
	subnets, err := repo.GetSubnets("t", nil)
	require.NoError(t, err)
	out := map[subnetKey]bool{}
	for _, s := range subnets {
		out[subnetKey{s.CIDR, model.VLANToken(s.VlanID, nil), s.Source, s.Kind}] = true
	}
	return out
}

func TestIntegration_SubnetsEndToEnd(t *testing.T) {
	repo := importFrames(t, [][]byte{
		dhcpv4ReplyFrame(t, -1, "10.0.1.50", "255.255.255.0", "10.0.1.1"),
		dhcpv4ReplyFrame(t, -1, "10.0.1.51", "255.255.255.0", "10.0.1.1"), // same prefix: one row
		dhcpv4ReplyFrame(t, 10, "10.0.1.60", "255.255.255.0", "10.0.1.1"), // same prefix, other VLAN
		dhcpv4ReplyFrame(t, 20, "10.0.9.60", "255.255.255.0", "10.0.1.1"), // router outside: dropped
		raFrame(t, 20, "2001:db8:1::", 64, 0xc0),
		raFrame(t, 20, "2001:db8:2::", 64, 0x40), // autonomous only: dropped
		dhcpv6ReplyFrame(t, -1, 56, "2001:db8:aa00::"),
	})

	assert.Equal(t, map[subnetKey]bool{
		{"10.0.1.0/24", "untagged", "dhcp", "on-link"}:          true,
		{"10.0.1.0/24", "10", "dhcp", "on-link"}:                true,
		{"2001:db8:1::/64", "20", "ra", "on-link"}:              true,
		{"2001:db8:aa00::/56", "untagged", "dhcp", "delegated"}: true,
	}, subnetKeys(t, repo))

	untagged, err := repo.GetSubnets("t", map[string]interface{}{"vlan_id": nil})
	require.NoError(t, err)
	for _, s := range untagged {
		assert.Nil(t, s.VlanID, "untagged must be NULL, never 1")
		assert.False(t, s.FirstSeen.After(s.LastSeen))
	}
}

func TestIntegration_NoSubnetEvidenceNoRows(t *testing.T) {
	repo := importFrames(t, [][]byte{vlanFrame(t), vlanFrame(t, 10)})
	subnets, err := repo.GetSubnets("t", nil)
	require.NoError(t, err)
	assert.Empty(t, subnets)
}

// A relayed client's Reply reaches the capture as a Relay-Reply to the relay agent (UDP 547 -> 547).
func TestIntegration_RelayedDHCPv6ReplyYieldsSubnet(t *testing.T) {
	inner := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeReply, TransactionID: []byte{1, 2, 3},
		Options: layers.DHCPv6Options{iaPD(iaPrefix(56, "2001:db8:aa00::"))}}
	relay := relayReply(t, inner)

	ip := &layers.IPv6{Version: 6, SrcIP: net.ParseIP("fe80::1"), DstIP: net.ParseIP("fe80::2"), NextHeader: layers.IPProtocolUDP, HopLimit: 64}
	udp := &layers.UDP{SrcPort: 547, DstPort: 547}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	repo := importFrames(t, [][]byte{subnetFrame(t, 30, layers.EthernetTypeIPv6, ip, udp, relay)})

	assert.Equal(t, map[subnetKey]bool{{"2001:db8:aa00::/56", "30", "dhcp", "delegated"}: true}, subnetKeys(t, repo))
}
