package parser

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dnp3TestCRC(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c ^= uint16(x)
		for i := 0; i < 8; i++ {
			if c&1 != 0 {
				c = c>>1 ^ 0xa6bc
			} else {
				c >>= 1
			}
		}
	}
	return ^c
}

// dnp3TestFrame is a link frame holding one transport segment with FIR and FIN.
func dnp3TestFrame(control byte, src, dst uint16, app []byte) []byte {
	user := append([]byte{0xc0}, app...)
	h := []byte{5, 0x64, byte(5 + len(user)), control, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(h[4:], dst)
	binary.LittleEndian.PutUint16(h[6:], src)
	out := binary.LittleEndian.AppendUint16(h, dnp3TestCRC(h))
	for len(user) > 0 {
		n := min(len(user), 16)
		out = append(out, user[:n]...)
		out = binary.LittleEndian.AppendUint16(out, dnp3TestCRC(user[:n]))
		user = user[n:]
	}
	return out
}

func TestParseDNP3(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	newParser := func() *IndustrialProtocolParserImpl { return newENIPTestParser(t) }

	t.Run("read request on the port", func(t *testing.T) {
		p := newParser()
		f := dnp3TestFrame(0xc4, 3, 10, []byte{0xc1, 0x01, 60, 1, 0x06})
		info := p.parseDNP3(buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 20000, ACK: true, Seq: 100}, nil, f), ts)
		require.NotNil(t, info)
		assert.Equal(t, "dnp3", info.Protocol)
		assert.Equal(t, 0.9, info.Confidence)
		assert.Equal(t, "Read", info.MessageType)
		assert.Equal(t, uint16(3), info.AdditionalData["source_address"])
		assert.Equal(t, uint16(10), info.AdditionalData["destination_address"])
		assert.Equal(t, byte(60), info.AdditionalData["group"])
		assert.False(t, info.IsConfiguration)
		assert.Equal(t, "outbound", info.Direction)
	})
	t.Run("direct operate is configuration; response carries IIN", func(t *testing.T) {
		p := newParser()
		op := dnp3TestFrame(0xc4, 3, 10, []byte{0xc2, 0x05, 12, 1, 0x17, 1, 3, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		info := p.parseDNP3(buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 20000, ACK: true, Seq: 1}, nil, op), ts)
		require.NotNil(t, info)
		assert.True(t, info.IsConfiguration)
		assert.Equal(t, "Direct Operate", info.AdditionalData["function_name"])
		assert.Equal(t, 1, info.AdditionalData["object_count"])

		resp := dnp3TestFrame(0x44, 10, 3, []byte{0xc2, 0x81, 0x10, 0x00})
		info = p.parseDNP3(buildTransportPacket(t, &layers.TCP{SrcPort: 20000, DstPort: 50000, ACK: true, Seq: 1}, nil, resp), ts)
		require.NotNil(t, info)
		assert.Equal(t, "Response", info.MessageType)
		assert.Equal(t, uint16(0x1000), info.AdditionalData["iin"])
		assert.Equal(t, uint16(10), info.DeviceIdentity["dnp3_outstation_address"])
		assert.Equal(t, "inbound", info.Direction)
	})
	t.Run("UDP datagram", func(t *testing.T) {
		p := newParser()
		f := dnp3TestFrame(0xc4, 3, 10, []byte{0xc1, 0x0d})
		info := p.parseDNP3(buildTransportPacket(t, nil, &layers.UDP{SrcPort: 50000, DstPort: 20000}, f), ts)
		require.NotNil(t, info)
		assert.Equal(t, "Cold Restart", info.AdditionalData["function_name"])
		assert.True(t, info.IsConfiguration)
	})
	t.Run("off the DNP3 port the DIR bit gives the direction", func(t *testing.T) {
		p := newParser()
		f := dnp3TestFrame(0xc4, 3, 10, []byte{0xc1, 0x01, 60, 1, 0x06})
		info := p.parseDNP3(buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 50001, ACK: true, Seq: 1}, nil, f), ts)
		require.NotNil(t, info)
		assert.Equal(t, 0.8, info.Confidence)
		assert.Equal(t, "outbound", info.Direction)
		r := dnp3TestFrame(0x44, 10, 3, []byte{0xc1, 0x81, 0, 0})
		info = p.parseDNP3(buildTransportPacket(t, &layers.TCP{SrcPort: 50001, DstPort: 50000, ACK: true, Seq: 1}, nil, r), ts)
		require.NotNil(t, info)
		assert.Equal(t, "inbound", info.Direction)
	})
	t.Run("UDP on the port has a direction", func(t *testing.T) {
		p := newParser()
		f := dnp3TestFrame(0x44, 10, 3, []byte{0xc1, 0x81, 0, 0})
		info := p.parseDNP3(buildTransportPacket(t, nil, &layers.UDP{SrcPort: 20000, DstPort: 40000}, f), ts)
		require.NotNil(t, info)
		assert.Equal(t, "inbound", info.Direction)
	})
	t.Run("not DNP3 on its port", func(t *testing.T) {
		p := newParser()
		assert.Nil(t, p.parseDNP3(buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 20000, ACK: true, Seq: 1}, nil, []byte("GET / HTTP/1.1\r\n\r\n")), ts))
	})
	t.Run("bad link CRC is an event, not a rejection", func(t *testing.T) {
		p := newParser()
		f := dnp3TestFrame(0xc4, 3, 10, []byte{0xc1, 0x01, 60, 1, 0x06})
		f[8] ^= 0xff
		info := p.parseDNP3(buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 20000, ACK: true, Seq: 1}, nil, f), ts)
		require.NotNil(t, info)
		assert.Contains(t, info.AdditionalData["events"], "bad_link_crc")
	})
}

func TestConnectionLabeler_DNP3(t *testing.T) {
	f := dnp3TestFrame(0xc4, 3, 10, []byte{0xc1, 0x01, 60, 1, 0x06})
	l := newConnectionLabeler(detect.Default())
	assert.Equal(t, "dnp3", tcpPkt(t, 50000, 20000, f, false)(l))
	assert.Equal(t, "dnp3", tcpPkt(t, 50000, 20000, nil, false)(l), "label sticks")
	// Content decides: other data on the port is not labelled DNP3.
	l2 := newConnectionLabeler(detect.Default())
	assert.Equal(t, "", tcpPkt(t, 50001, 20000, []byte("GET / HTTP/1.1\r\n\r\n"), false)(l2))
	// And DNP3 off the port is found by content.
	l3 := newConnectionLabeler(detect.Default())
	assert.Equal(t, "dnp3", tcpPkt(t, 50002, 50003, f, false)(l3))
}
