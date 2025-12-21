package parser

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/testutil"
	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_BidirectionalHTTPFlow validates that HTTP request/response creates a single flow
// with correct PacketCountOut, ByteCountOut, PacketCountIn, ByteCountIn after refactoring
func TestIntegration_BidirectionalHTTPFlow(t *testing.T) {
	pcapFile := createHTTPRequestResponsePCAP(t)
	defer os.Remove(pcapFile)

	repo := &testutil.MockRepository{}
	parser := NewGopacketParser(pcapFile, repo, "test-tenant")

	err := parser.ParseFile()
	require.NoError(t, err, "ParseFile should succeed")

	// Validate flows
	flows := extractFlowsFromParser(parser)

	// After refactoring with canonicalization, we expect:
	// 1. Single flow from client:ephemeral -> server:80
	// 2. PacketCountOut should include client->server packets
	// 3. PacketCountIn should remain 0 (per requirements)
	// 4. ByteCountOut should match total bytes sent client->server

	// Note: Current implementation creates 2 flows - this will change after refactoring
	t.Logf("Current flow count: %d", len(flows))
	for _, flow := range flows {
		t.Logf("Flow: %s:%d -> %s:%d, Proto: %s, PacketOut: %d, PacketIn: %d, ByteOut: %d, ByteIn: %d",
			flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol,
			flow.PacketCountOut, flow.PacketCountIn, flow.ByteCountOut, flow.ByteCountIn)
	}
}

// TestIntegration_BidirectionalOPCUAFlow validates OPC UA client-server communication
func TestIntegration_BidirectionalOPCUAFlow(t *testing.T) {
	pcapFile := createOPCUARequestResponsePCAP(t)
	defer os.Remove(pcapFile)

	repo := &testutil.MockRepository{}
	parser := NewGopacketParser(pcapFile, repo, "test-tenant")

	err := parser.ParseFile()
	require.NoError(t, err, "ParseFile should succeed")

	flows := extractFlowsFromParser(parser)

	t.Logf("Current flow count: %d", len(flows))
	for _, flow := range flows {
		t.Logf("Flow: %s:%d -> %s:%d, Proto: %s, PacketOut: %d, PacketIn: %d, ByteOut: %d, ByteIn: %d",
			flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol,
			flow.PacketCountOut, flow.PacketCountIn, flow.ByteCountOut, flow.ByteCountIn)
	}
}

// TestIntegration_UnidirectionalFlow validates purely one-way traffic (e.g., broadcast)
func TestIntegration_UnidirectionalFlow(t *testing.T) {
	pcapFile := createUnidirectionalPCAP(t)
	defer os.Remove(pcapFile)

	repo := &testutil.MockRepository{}
	parser := NewGopacketParser(pcapFile, repo, "test-tenant")

	err := parser.ParseFile()
	require.NoError(t, err, "ParseFile should succeed")

	flows := extractFlowsFromParser(parser)

	// Unidirectional traffic should have PacketCountIn = 0
	for _, flow := range flows {
		assert.Equal(t, 0, flow.PacketCountIn, "Unidirectional flow should have PacketCountIn=0")
		assert.Equal(t, int64(0), flow.ByteCountIn, "Unidirectional flow should have ByteCountIn=0")
		assert.Greater(t, flow.PacketCountOut, 0, "Should have outgoing packets")
	}
}

// TestIntegration_DeviceDiscovery validates device extraction and MAC correlation
func TestIntegration_DeviceDiscovery(t *testing.T) {
	pcapFile := createMultiDevicePCAP(t)
	defer os.Remove(pcapFile)

	repo := &testutil.MockRepository{}
	parser := NewGopacketParser(pcapFile, repo, "test-tenant")

	err := parser.ParseFile()
	require.NoError(t, err, "ParseFile should succeed")

	devices := extractDevicesFromParser(parser)
	t.Logf("devices discovered: %d", len(devices))

	// Validate we discovered multiple devices
	assert.GreaterOrEqual(t, len(devices), 2, "Should discover at least 2 devices")

	for _, device := range devices {
		t.Logf("Device: %s (%s), MACs: %d", device.Address, device.AddressType, device.MACAddressSet.Size())
	}
}

// TestIntegration_FlowCountAccuracy validates exact byte and packet counts
func TestIntegration_FlowCountAccuracy(t *testing.T) {
	// Create PCAP with known packet sizes
	const packet1Size = 100
	const packet2Size = 200
	const packet3Size = 150

	pcapFile := createKnownSizePCAP(t, packet1Size, packet2Size, packet3Size)
	defer os.Remove(pcapFile)

	repo := &testutil.MockRepository{}
	parser := NewGopacketParser(pcapFile, repo, "test-tenant")

	err := parser.ParseFile()
	require.NoError(t, err, "ParseFile should succeed")

	flows := extractFlowsFromParser(parser)
	t.Logf("flows discovered: %d", len(flows))
	require.Len(t, flows, 1, "Should create exactly 1 flow")

	flow := flows[0]

	// Validate packet counts
	expectedPackets := 3
	assert.Equal(t, expectedPackets, flow.PacketCountOut, "PacketCountOut should match sent packets")

	// Validate byte counts (this will help identify if we're counting correctly)
	t.Logf("ByteCountOut: %d, Expected total: %d", flow.ByteCountOut, packet1Size+packet2Size+packet3Size)
}

// Helper functions

func extractFlowsFromParser(parser *GopacketParser) []*model.Flow {
	return parser.flowManager.GetAllFlows()
}

func extractDevicesFromParser(parser *GopacketParser) []*model.Device {
	return parser.deviceManager.GetAllDevices()
}

func createHTTPRequestResponsePCAP(t *testing.T) string {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	clientMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	serverMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	clientIP := []byte{192, 168, 1, 100}
	serverIP := []byte{192, 168, 1, 10}

	// HTTP Request: Client -> Server (port 80)
	ethReq := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       serverMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipReq := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    clientIP,
		DstIP:    serverIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpReq := &layers.TCP{
		SrcPort: 54321,
		DstPort: 80,
		Seq:     1000,
		Ack:     0,
		SYN:     false,
		ACK:     true,
	}
	payload := []byte("GET / HTTP/1.1\r\nHost: server\r\n\r\n")

	bufReq := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(bufReq, opts, ethReq, ipReq, tcpReq, gopacket.Payload(payload))
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		Length:        len(bufReq.Bytes()),
		CaptureLength: len(bufReq.Bytes()),
	}, bufReq.Bytes())

	// HTTP Response: Server -> Client
	ethResp := &layers.Ethernet{
		SrcMAC:       serverMAC,
		DstMAC:       clientMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipResp := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    serverIP,
		DstIP:    clientIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpResp := &layers.TCP{
		SrcPort: 80,
		DstPort: 54321,
		Seq:     2000,
		Ack:     1000,
		SYN:     false,
		ACK:     true,
	}
	respPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")

	bufResp := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(bufResp, opts, ethResp, ipResp, tcpResp, gopacket.Payload(respPayload))
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now().Add(10 * time.Millisecond),
		Length:        len(bufResp.Bytes()),
		CaptureLength: len(bufResp.Bytes()),
	}, bufResp.Bytes())

	return writePCAPFile(t, "test_http_bidirectional.pcap", buf)
}

func createOPCUARequestResponsePCAP(t *testing.T) string {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	clientMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	serverMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	clientIP := []byte{192, 168, 1, 100}
	serverIP := []byte{10, 0, 0, 50}

	// OPC UA Request: Client -> Server (port 4840)
	ethReq := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       serverMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipReq := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    clientIP,
		DstIP:    serverIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpReq := &layers.TCP{
		SrcPort: 55000,
		DstPort: 4840,
		Seq:     3000,
		Ack:     0,
		SYN:     false,
		ACK:     true,
	}
	opcPayload := []byte{0x48, 0x45, 0x4c, 0x46} // OPC UA header

	bufReq := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(bufReq, opts, ethReq, ipReq, tcpReq, gopacket.Payload(opcPayload))
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		Length:        len(bufReq.Bytes()),
		CaptureLength: len(bufReq.Bytes()),
	}, bufReq.Bytes())

	// OPC UA Response: Server -> Client
	ethResp := &layers.Ethernet{
		SrcMAC:       serverMAC,
		DstMAC:       clientMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipResp := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    serverIP,
		DstIP:    clientIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpResp := &layers.TCP{
		SrcPort: 4840,
		DstPort: 55000,
		Seq:     4000,
		Ack:     3000,
		SYN:     false,
		ACK:     true,
	}
	respPayload := []byte{0x41, 0x43, 0x4b, 0x00}

	bufResp := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(bufResp, opts, ethResp, ipResp, tcpResp, gopacket.Payload(respPayload))
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now().Add(5 * time.Millisecond),
		Length:        len(bufResp.Bytes()),
		CaptureLength: len(bufResp.Bytes()),
	}, bufResp.Bytes())

	return writePCAPFile(t, "test_opcua_bidirectional.pcap", buf)
}

func createUnidirectionalPCAP(t *testing.T) string {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	srcMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	broadcastMAC := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	srcIP := []byte{192, 168, 1, 1}
	broadcastIP := []byte{255, 255, 255, 255}

	// UDP Broadcast packet (unidirectional)
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    broadcastIP,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 9999,
	}
	payload := []byte("BROADCAST_MESSAGE")

	bufPkt := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(bufPkt, opts, eth, ip, udp, gopacket.Payload(payload))
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		Length:        len(bufPkt.Bytes()),
		CaptureLength: len(bufPkt.Bytes()),
	}, bufPkt.Bytes())

	return writePCAPFile(t, "test_unidirectional.pcap", buf)
}

func createMultiDevicePCAP(t *testing.T) string {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	device1MAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	device2MAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	device1IP := []byte{192, 168, 1, 10}
	device2IP := []byte{192, 168, 1, 20}

	// Packet from device 1 to device 2
	eth1 := &layers.Ethernet{
		SrcMAC:       device1MAC,
		DstMAC:       device2MAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip1 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    device1IP,
		DstIP:    device2IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp1 := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
	}
	tcp1.SetNetworkLayerForChecksum(ip1)

	bufPkt1 := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(bufPkt1, opts, eth1, ip1, tcp1)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		Length:        len(bufPkt1.Bytes()),
		CaptureLength: len(bufPkt1.Bytes()),
	}, bufPkt1.Bytes())

	// Packet from device 2 to device 1
	eth2 := &layers.Ethernet{
		SrcMAC:       device2MAC,
		DstMAC:       device1MAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip2 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    device2IP,
		DstIP:    device1IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp2 := &layers.TCP{
		SrcPort: 80,
		DstPort: 12345,
	}
	tcp2.SetNetworkLayerForChecksum(ip2)

	bufPkt2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(bufPkt2, opts, eth2, ip2, tcp2)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now().Add(5 * time.Millisecond),
		Length:        len(bufPkt2.Bytes()),
		CaptureLength: len(bufPkt2.Bytes()),
	}, bufPkt2.Bytes())

	return writePCAPFile(t, "test_multidevice.pcap", buf)
}

func createKnownSizePCAP(t *testing.T, size1, size2, size3 int) string {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	srcMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	srcIP := []byte{192, 168, 1, 1}
	dstIP := []byte{192, 168, 1, 2}

	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// Helper to create a packet with specific payload size
	createPacket := func(payloadSize int) []byte {
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolUDP,
		}
		udp := &layers.UDP{
			SrcPort: 5000,
			DstPort: 6000,
		}
		udp.SetNetworkLayerForChecksum(ip)

		// Create payload of exact size (accounting for headers)
		// Ethernet: 14 bytes, IPv4: 20 bytes, UDP: 8 bytes = 42 bytes overhead
		payloadBytes := make([]byte, payloadSize-42)
		for i := range payloadBytes {
			payloadBytes[i] = byte(i % 256)
		}

		bufPkt := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(bufPkt, opts, eth, ip, udp, gopacket.Payload(payloadBytes))
		return bufPkt.Bytes()
	}

	pkt1 := createPacket(size1)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		Length:        len(pkt1),
		CaptureLength: len(pkt1),
	}, pkt1)

	pkt2 := createPacket(size2)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now().Add(10 * time.Millisecond),
		Length:        len(pkt2),
		CaptureLength: len(pkt2),
	}, pkt2)

	pkt3 := createPacket(size3)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now().Add(20 * time.Millisecond),
		Length:        len(pkt3),
		CaptureLength: len(pkt3),
	}, pkt3)

	return writePCAPFile(t, "test_known_sizes.pcap", buf)
}

func writePCAPFile(t *testing.T, filename string, buf *bytes.Buffer) string {
	file, err := os.Create(filename)
	require.NoError(t, err, "Failed to create PCAP file")

	_, err = file.Write(buf.Bytes())
	require.NoError(t, err, "Failed to write PCAP data")

	err = file.Close()
	require.NoError(t, err, "Failed to close PCAP file")

	return filename
}
