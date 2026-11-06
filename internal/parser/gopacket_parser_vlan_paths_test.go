package parser

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vlanUDPFrame serializes a UDP frame from srcIP to dstIP. A nil vlan means untagged.
func vlanUDPFrame(t *testing.T, vlan *uint16, srcIP, dstIP net.IP, dstPort layers.UDPPort, payload ...gopacket.SerializableLayer) []byte {
	t.Helper()
	ip := &layers.IPv4{SrcIP: srcIP.To4(), DstIP: dstIP.To4(), Protocol: layers.IPProtocolUDP, TTL: 64, Version: 4, IHL: 5}
	udp := &layers.UDP{SrcPort: 40000, DstPort: dstPort}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 0x11, 0x22, 0x33, 0x44, srcIP.To4()[3]},
		DstMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, dstIP.To4()[3]},
		EthernetType: layers.EthernetTypeIPv4,
	}
	stack := []gopacket.SerializableLayer{eth}
	if vlan != nil {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{VLANIdentifier: *vlan, Type: layers.EthernetTypeIPv4})
	}
	stack = append(stack, ip, udp)
	stack = append(stack, payload...)

	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, stack...))
	return buf.Bytes()
}

func uint16Ptr(v uint16) *uint16 { return &v }

// devicesVLANs imports the pcap and returns each device's VLAN set by address.
func devicesVLANs(t *testing.T, pcap string) map[string]string {
	t.Helper()
	repo, err := repository.NewSQLiteRepositoryWithCanonicalizer(filepath.Join(t.TempDir(), "out.sqlite"), helper.NewFlowCanonicalizer())
	require.NoError(t, err)
	defer repo.Close()

	require.NoError(t, NewGopacketParser(pcap, repo, "t").ParseFile())

	devices, err := repo.GetDevices("t", nil)
	require.NoError(t, err)
	out := map[string]string{}
	for _, d := range devices {
		out[d.Address] = d.VLANSet.ToString()
	}
	return out
}

// Guard for the DNS device path: both IPs of a DNS answer tagged with VLAN 10
// must carry VLAN 10. The main packet loop records this for every Ethernet frame,
// and the DNS path reuses the same addresses.
func TestIntegration_DNSDevicesKeepFrameVLAN(t *testing.T) {
	server := net.IPv4(10, 0, 0, 2)
	client := net.IPv4(10, 0, 0, 1)
	dns := &layers.DNS{
		ID: 7, QR: true, OpCode: layers.DNSOpCodeQuery, RD: true, RA: true,
		QDCount: 1, ANCount: 1,
		Questions: []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers: []layers.DNSResourceRecord{{
			Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60,
			IP: net.IPv4(93, 184, 216, 34).To4(),
		}},
	}
	frame := vlanUDPFrame(t, uint16Ptr(10), server, client, 40000, dns)

	got := devicesVLANs(t, writeVLANPCAP(t, [][]byte{frame}))
	assert.Equal(t, "10", got[server.String()])
	assert.Equal(t, "10", got[client.String()])
}

// Guard for the SSDP device path: the querying device of an M-SEARCH tagged with
// VLAN 10 must carry VLAN 10.
func TestIntegration_SSDPDeviceKeepsFrameVLAN(t *testing.T) {
	client := net.IPv4(10, 0, 0, 1)
	multicast := net.IPv4(239, 255, 255, 250)
	msearch := gopacket.Payload([]byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n"))
	frame := vlanUDPFrame(t, uint16Ptr(10), client, multicast, 1900, msearch)

	got := devicesVLANs(t, writeVLANPCAP(t, [][]byte{frame}))
	assert.Equal(t, "10", got[client.String()])
}
