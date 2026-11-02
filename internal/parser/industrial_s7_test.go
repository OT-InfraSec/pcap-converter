package parser

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func s7Cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func s7TPKT(body ...[]byte) []byte {
	b := s7Cat(body...)
	return append([]byte{3, 0, byte((len(b) + 4) >> 8), byte(len(b) + 4)}, b...)
}

func s7DT(pdu []byte) []byte { return s7TPKT([]byte{2, 0xf0, 0x80}, pdu) }

func s7PDU(rosctr byte, ref uint16, param, data []byte) []byte {
	h := []byte{0x32, rosctr, 0, 0, byte(ref >> 8), byte(ref), byte(len(param) >> 8), byte(len(param)), byte(len(data) >> 8), byte(len(data))}
	if rosctr == 2 || rosctr == 3 {
		h = append(h, 0, 0)
	}
	return s7Cat(h, param, data)
}

func s7CR(dst, src []byte) []byte {
	params := s7Cat([]byte{0xc0, 1, 0x0a, 0xc1, byte(len(src))}, src, []byte{0xc2, byte(len(dst))}, dst)
	return s7TPKT([]byte{byte(6 + len(params)), 0xe0, 0, 0, 0, 1, 0}, params)
}

func TestParseS7(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	newParser := func() (*IndustrialProtocolParserImpl, func(src, dst uint16, payload []byte) gopacket.Packet) {
		seqs := map[[2]uint16]uint32{}
		return newENIPTestParser(t), func(src, dst uint16, payload []byte) gopacket.Packet {
			k := [2]uint16{src, dst}
			pkt := buildTransportPacket(t, &layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst), ACK: true, Seq: 7000 + seqs[k]}, nil, payload)
			seqs[k] += uint32(len(payload))
			return pkt
		}
	}
	setup := s7DT(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 0x01, 0xe0}, nil))

	t.Run("setup communication", func(t *testing.T) {
		p, tcp := newParser()
		info := p.parseS7(tcp(50000, 102, setup), ts)
		require.NotNil(t, info)
		assert.Equal(t, "s7", info.Protocol)
		assert.Equal(t, 0.9, info.Confidence)
		assert.Equal(t, "Job", info.MessageType)
		assert.Equal(t, "Setup communication", info.AdditionalData["function_name"])
		assert.Equal(t, uint16(480), info.AdditionalData["pdu_length"])
		assert.Equal(t, "outbound", info.Direction)
	})
	t.Run("a connection request alone is below the threshold, but its rack and slot are kept", func(t *testing.T) {
		p, tcp := newParser()
		cr := p.parseS7(tcp(50000, 102, s7CR([]byte{0x01, 0x02}, []byte{0x01, 0x00})), ts)
		require.NotNil(t, cr)
		assert.Less(t, cr.Confidence, DefaultIndustrialParserConfig().ConfidenceThreshold)
		got, err := p.ParseIndustrialProtocols(tcp(50001, 102, nil))
		require.NoError(t, err)
		for _, g := range got {
			assert.NotEqual(t, "s7", g.Protocol)
		}
		info := p.parseS7(tcp(50000, 102, setup), ts)
		require.NotNil(t, info)
		assert.Equal(t, 0, info.AdditionalData["rack"])
		assert.Equal(t, 2, info.AdditionalData["slot"])
	})
	t.Run("S7CommPlus is its own protocol", func(t *testing.T) {
		p, tcp := newParser()
		d := []byte{0x31, 0, 0, 0x04, 0xbb, 0, 0, 0, 5, 0, 0, 0, 9, 0x34, 0}
		pdu := s7Cat([]byte{0x72, 1, 0, byte(len(d))}, d, []byte{0x72, 1, 0, 0})
		info := p.parseS7(tcp(50000, 102, s7DT(pdu)), ts)
		require.NotNil(t, info)
		assert.Equal(t, "s7commplus", info.Protocol)
		assert.Equal(t, 0.9, info.Confidence)
		assert.Equal(t, "Request", info.MessageType)
		assert.Equal(t, "Explore", info.AdditionalData["s7plus_function_name"])
		assert.Equal(t, uint16(5), info.AdditionalData["s7plus_sequence"])
		assert.Equal(t, uint32(9), info.AdditionalData["s7plus_session_id"])
	})
	t.Run("read var and write var", func(t *testing.T) {
		p, tcp := newParser()
		item := []byte{0x12, 0x0a, 0x10, 0x02, 0, 2, 0, 1, 0x84, 0, 0, 0x20} // DB1, byte address 4
		rd := p.parseS7(tcp(50000, 102, s7DT(s7PDU(1, 2, s7Cat([]byte{4, 1}, item), nil))), ts)
		require.NotNil(t, rd)
		assert.Equal(t, "Read Var", rd.AdditionalData["function_name"])
		assert.Equal(t, "Data block", rd.AdditionalData["area_name"])
		assert.Equal(t, uint16(1), rd.AdditionalData["db_number"])
		assert.Equal(t, uint32(4), rd.AdditionalData["address"])
		assert.False(t, rd.IsConfiguration)

		wr := p.parseS7(tcp(50000, 102, s7DT(s7PDU(1, 3, s7Cat([]byte{5, 1}, item), []byte{0, 4, 0, 16, 1, 2}))), ts)
		require.NotNil(t, wr)
		assert.Equal(t, "Write Var", wr.AdditionalData["function_name"])
		assert.True(t, wr.IsConfiguration)
	})
	t.Run("PLC stop is configuration", func(t *testing.T) {
		p, tcp := newParser()
		stop := s7Cat([]byte{0x29, 0, 0, 0, 0, 0, 9}, []byte("P_PROGRAM"))
		info := p.parseS7(tcp(50000, 102, s7DT(s7PDU(1, 4, stop, nil))), ts)
		require.NotNil(t, info)
		assert.True(t, info.IsConfiguration)
		assert.Equal(t, "P_PROGRAM", info.AdditionalData["plc_service"])
	})
	t.Run("an SZL reply gives the CPU identity", func(t *testing.T) {
		p, tcp := newParser()
		pad := func(s string, n int) []byte { b := make([]byte, n); copy(b, s); return b }
		rec := func(idx byte, s string) []byte { return s7Cat([]byte{0, idx}, pad(s, 32)) }
		body := s7Cat([]byte{0, 0x1c, 0, 0, 0, 34, 0, 2}, rec(1, "Station 1"), rec(2, "CPU 1214C"))
		data := s7Cat([]byte{0xff, 9, 0, byte(len(body))}, body)
		param := []byte{0, 1, 0x12, 8, 0x12, 0x84, 1, 0, 0, 0, 0, 0}
		info := p.parseS7(tcp(102, 50000, s7DT(s7PDU(7, 5, param, data))), ts)
		require.NotNil(t, info)
		assert.True(t, info.IsDiscovery)
		assert.Equal(t, "Station 1", info.DeviceIdentity["system_name"])
		assert.Equal(t, "CPU 1214C", info.DeviceIdentity["module_name"])
		assert.Equal(t, uint16(0x1c), info.AdditionalData["szl_id"])
	})
	t.Run("a PDU split across segments", func(t *testing.T) {
		p, tcp := newParser()
		require.NotNil(t, p.parseS7(tcp(50000, 102, setup), ts))
		next := s7DT(s7PDU(1, 9, []byte{0xf0, 0, 0, 1, 0, 1, 0x01, 0xe0}, nil))
		first := p.parseS7(tcp(50000, 102, next[:10]), ts)
		require.NotNil(t, first, "the segment still belongs to an S7 connection")
		assert.NotContains(t, first.AdditionalData, "function")
		rest := p.parseS7(tcp(50000, 102, next[10:]), ts)
		require.NotNil(t, rest)
		assert.Equal(t, uint16(9), rest.AdditionalData["pdu_reference"])
	})
	t.Run("a retransmission is not counted twice", func(t *testing.T) {
		p, _ := newParser()
		at := func(seq uint32) gopacket.Packet {
			return buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 102, ACK: true, Seq: seq}, nil, setup)
		}
		first := p.parseS7(at(900), ts)
		require.NotNil(t, first)
		assert.Equal(t, 1, first.AdditionalData["message_count"])
		again := p.parseS7(at(900), ts)
		require.NotNil(t, again)
		assert.NotContains(t, again.AdditionalData, "function")
	})
	t.Run("MMS on port 102 is not S7", func(t *testing.T) {
		p, tcp := newParser()
		mms := s7DT([]byte{0x01, 0x01, 0x01, 0x00, 0x61, 0x02, 0x02, 0x01})
		assert.Nil(t, p.parseS7(tcp(50000, 102, mms), ts))
	})
	t.Run("a malformed PDU carries the event", func(t *testing.T) {
		p, tcp := newParser()
		require.NotNil(t, p.parseS7(tcp(50000, 102, setup), ts))
		// Parameter length 50, no parameter bytes.
		bad := s7DT([]byte{0x32, 1, 0, 0, 0, 1, 0, 50, 0, 0})
		info := p.parseS7(tcp(50000, 102, bad), ts)
		require.NotNil(t, info)
		assert.Equal(t, []string{"invalid_s7"}, info.AdditionalData["events"])
	})
	t.Run("the flow label on port 102 is neutral", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 102, ACK: true}, nil, setup)
		assert.Equal(t, "s7+s7commplus", l.Label(pkt, "10.0.0.1", "10.0.0.2", model.VLANTag{}))
		mms := buildTransportPacket(t, &layers.TCP{SrcPort: 50001, DstPort: 102, ACK: true}, nil, s7DT([]byte{0x01, 0x01, 0x01, 0x00, 0x61, 0x02, 0x02, 0x01}))
		assert.Equal(t, "", l.Label(mms, "10.0.0.1", "10.0.0.2", model.VLANTag{}))
	})
}
