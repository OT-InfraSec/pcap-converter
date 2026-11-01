package parser

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enipEncap(cmd uint16, length uint16, body []byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:], cmd)
	binary.LittleEndian.PutUint16(b[2:], length)
	return append(b, body...)
}

func buildTransportPacket(t *testing.T, tcp *layers.TCP, udp *layers.UDP, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var err error
	if tcp != nil {
		ip.Protocol = layers.IPProtocolTCP
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	} else {
		ip.Protocol = layers.IPProtocolUDP
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	}
	require.NoError(t, err)
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Unix(1700000000, 0)
	return p
}

func newENIPTestParser(t *testing.T) *IndustrialProtocolParserImpl {
	t.Helper()
	impl, ok := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)
	require.True(t, ok)
	return impl
}

func TestParseEtherNetIP_Detection(t *testing.T) {
	p := newENIPTestParser(t)
	ts := time.Unix(1700000000, 0)
	listIdentity := enipEncap(0x63, 0, nil)

	t.Run("TCP 44818 with valid header", func(t *testing.T) {
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, ACK: true}, nil, listIdentity)
		info := p.parseEtherNetIP(pkt, ts)
		require.NotNil(t, info)
		assert.Equal(t, "EtherNet/IP(TCP)", info.Protocol)
		assert.Equal(t, 0.9, info.Confidence)
		assert.Equal(t, uint16(44818), info.Port)
	})

	t.Run("F-01: UDP 44818 ListIdentity is detected", func(t *testing.T) {
		pkt := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 50000, DstPort: 44818}, listIdentity)
		info := p.parseEtherNetIP(pkt, ts)
		require.NotNil(t, info)
		assert.Equal(t, "EtherNet/IP(UDP)", info.Protocol)
		assert.Equal(t, 0.9, info.Confidence)
		assert.Equal(t, uint16(44818), info.Port)
		assert.Equal(t, "udp", info.AdditionalData["transport"])
	})

	t.Run("UDP 2222 implicit I/O still detected", func(t *testing.T) {
		pkt := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 2222, DstPort: 2222}, enipEncap(0x70, 0, nil))
		info := p.parseEtherNetIP(pkt, ts)
		require.NotNil(t, info)
		assert.Equal(t, uint16(2222), info.Port)
	})

	t.Run("content match on an unusual port gets lower confidence", func(t *testing.T) {
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 50001, ACK: true}, nil, listIdentity)
		info := p.parseEtherNetIP(pkt, ts)
		require.NotNil(t, info)
		assert.Equal(t, 0.8, info.Confidence)
	})

	t.Run("F-02: non-zero first word is not enough", func(t *testing.T) {
		garbage := make([]byte, 40)
		garbage[0] = 0x01 // command 0x0001 is not an ENIP command
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, ACK: true}, nil, garbage)
		// A fresh parser: on a connection already recognised as ENIP, anything is
		// framed by its length field.
		assert.Nil(t, newENIPTestParser(t).parseEtherNetIP(pkt, ts))
	})

	t.Run("F-02: Nop is accepted", func(t *testing.T) {
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, ACK: true}, nil, enipEncap(0, 0, nil))
		assert.NotNil(t, p.parseEtherNetIP(pkt, ts))
	})

	t.Run("handshake segment on the port is below the default threshold", func(t *testing.T) {
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, SYN: true}, nil, nil)
		info := p.parseEtherNetIP(pkt, ts)
		require.NotNil(t, info)
		assert.Less(t, info.Confidence, DefaultIndustrialParserConfig().ConfidenceThreshold)
		got, err := p.ParseIndustrialProtocols(pkt)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("F-03: TCP header bytes are not read as an ENIP header", func(t *testing.T) {
		// Destination port 256 makes the TCP header bytes 2..3 read as length 1
		// in little endian, and 40 option bytes make the header 60 bytes long.
		// The old check read these header bytes instead of the payload and
		// reported EtherNet/IP for traffic that is not.
		opts := []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		}
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 256, ACK: true, Options: opts}, nil, []byte("not enip"))
		assert.Nil(t, p.parseEtherNetIP(pkt, ts))
	})

	t.Run("garbage on the port is rejected even with a valid-looking length", func(t *testing.T) {
		pkt := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 50000, DstPort: 44818}, []byte("some random udp payload, 40+ bytes long"))
		assert.Nil(t, p.parseEtherNetIP(pkt, ts))
	})
}

func TestDetermineDirection_ENIPUDP(t *testing.T) {
	p := newENIPTestParser(t)
	req := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 50000, DstPort: 44818}, enipEncap(0x63, 0, nil))
	rsp := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 44818, DstPort: 50000}, enipEncap(0x63, 0, nil))
	assert.Equal(t, "outbound", p.determineDirection(req))
	assert.Equal(t, "inbound", p.determineDirection(rsp))
}
