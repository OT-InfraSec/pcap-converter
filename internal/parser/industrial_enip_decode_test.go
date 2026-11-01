package parser

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real messages from the minicps testbed capture m13e880-br-seg1.pcap.
func enipHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

const (
	enipRegisterReq = "65000400000000000000000000000000000000000000000001000000"
	enipGetAttrReq  = "6f0018000100000000000000020000000000000000000000000000000000020000000000b20008000e03200424013003"
	enipGetAttrResp = "6f0016000100000000000000020000000000000000000000000000000000020000000000b20006008e0000003200"
	enipSetAttrReq  = "6f001a000600000000000000020000000000000000000000000000000000020000000000b2000a0010032004240130033c00"
)

func TestParseEtherNetIP_DecodesMessages(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	seqs := map[[2]uint16]uint32{}
	tcp := func(src, dst uint16, payload []byte) gopacket.Packet {
		k := [2]uint16{src, dst}
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst), ACK: true, Seq: 5000 + seqs[k]}, nil, payload)
		seqs[k] += uint32(len(payload))
		return pkt
	}

	t.Run("register session", func(t *testing.T) {
		p := newENIPTestParser(t)
		info := p.parseEtherNetIP(tcp(50000, 44818, enipHex(t, enipRegisterReq)), ts)
		require.NotNil(t, info)
		assert.Equal(t, "register_session", info.MessageType)
		assert.Equal(t, uint16(1), info.AdditionalData["protocol_version"])
		assert.Equal(t, "success", info.AdditionalData["status_name"])
	})
	t.Run("CIP request and reply", func(t *testing.T) {
		p := newENIPTestParser(t)
		req := p.parseEtherNetIP(tcp(50001, 44818, enipHex(t, enipGetAttrReq)), ts)
		require.NotNil(t, req)
		assert.Equal(t, "send_r_r_data", req.MessageType)
		assert.Equal(t, uint8(0x0e), req.AdditionalData["cip_service"])
		assert.Equal(t, "Get Attribute Single", req.AdditionalData["cip_service_name"])
		assert.Equal(t, 4, req.AdditionalData["cip_class"])
		assert.Equal(t, 1, req.AdditionalData["cip_instance"])
		assert.Equal(t, 3, req.AdditionalData["cip_attribute"])
		assert.False(t, req.IsConfiguration)

		resp := p.parseEtherNetIP(tcp(44818, 50001, enipHex(t, enipGetAttrResp)), ts)
		require.NotNil(t, resp)
		assert.Equal(t, true, resp.AdditionalData["cip_is_response"])
		assert.Equal(t, "Success", resp.AdditionalData["cip_status_name"])
	})
	t.Run("a write is configuration", func(t *testing.T) {
		p := newENIPTestParser(t)
		info := p.parseEtherNetIP(tcp(50002, 44818, enipHex(t, enipSetAttrReq)), ts)
		require.NotNil(t, info)
		assert.Equal(t, "Set Attribute Single", info.AdditionalData["cip_service_name"])
		assert.True(t, info.IsConfiguration)
	})
	t.Run("a message split across segments", func(t *testing.T) {
		p := newENIPTestParser(t)
		whole := enipHex(t, enipGetAttrReq)
		require.NotNil(t, p.parseEtherNetIP(tcp(50003, 44818, enipHex(t, enipRegisterReq)), ts))
		first := p.parseEtherNetIP(tcp(50003, 44818, whole[:30]), ts)
		require.NotNil(t, first, "the segment still belongs to an ENIP connection")
		assert.NotContains(t, first.AdditionalData, "cip_service")
		rest := p.parseEtherNetIP(tcp(50003, 44818, whole[30:]), ts)
		require.NotNil(t, rest)
		assert.Equal(t, uint8(0x0e), rest.AdditionalData["cip_service"])
	})
	t.Run("a retransmitted segment is not counted twice", func(t *testing.T) {
		p := newENIPTestParser(t)
		at := func(seq uint32, payload []byte) gopacket.Packet {
			return buildTransportPacket(t, &layers.TCP{SrcPort: 50004, DstPort: 44818, ACK: true, Seq: seq}, nil, payload)
		}
		first := p.parseEtherNetIP(at(900, enipHex(t, enipRegisterReq)), ts)
		require.NotNil(t, first)
		assert.Equal(t, 1, first.AdditionalData["message_count"])
		again := p.parseEtherNetIP(at(900, enipHex(t, enipRegisterReq)), ts)
		require.NotNil(t, again)
		assert.NotContains(t, again.AdditionalData, "command")
	})
	t.Run("list identity over UDP gives the device identity", func(t *testing.T) {
		p := newENIPTestParser(t)
		item := append([]byte{1, 0, 0, 2, 0xaf, 0x12, 10, 1, 1, 22, 0, 0, 0, 0, 0, 0, 0, 0},
			1, 0, 12, 0, 0x36, 0, 5, 1, 0x30, 0, 0x78, 0x56, 0x34, 0x12, 11)
		item = append(item, []byte("1756-ENBT/A")...)
		item = append(item, 3)
		data := append([]byte{1, 0, 0x0c, 0, byte(len(item)), 0}, item...)
		hdr := enipEncap(0x63, uint16(len(data)), data)
		pkt := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 44818, DstPort: 50005}, hdr)
		info := p.parseEtherNetIP(pkt, ts)
		require.NotNil(t, info)
		assert.True(t, info.IsDiscovery)
		assert.Equal(t, "list_identity", info.MessageType)
		assert.Equal(t, uint16(1), info.DeviceIdentity["vendor_id"])
		assert.Equal(t, "1756-ENBT/A", info.DeviceIdentity["product_name"])
		assert.Equal(t, "5.1", info.DeviceIdentity["revision"])
		assert.Equal(t, uint32(0x12345678), info.DeviceIdentity["serial"])
		assert.Equal(t, "10.1.1.22", info.DeviceIdentity["ip_address"])
	})
	t.Run("a malformed payload carries the event", func(t *testing.T) {
		p := newENIPTestParser(t)
		require.NotNil(t, p.parseEtherNetIP(tcp(50006, 44818, enipHex(t, enipRegisterReq)), ts))
		// A ListIdentity reply that promises five items and has none.
		info := p.parseEtherNetIP(tcp(44818, 50006, enipEncap(0x63, 2, []byte{5, 0})), ts)
		require.NotNil(t, info)
		assert.Equal(t, []string{"invalid_pdu"}, info.AdditionalData["events"])
	})
}
