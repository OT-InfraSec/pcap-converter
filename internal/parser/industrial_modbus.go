package parser

import (
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseModbusTCP parses Modbus TCP protocol.
//
// A connection is recognised as Modbus by content (an MBAP header with
// protocol ID 0, a consistent length and a valid function code); port 502 only
// raises confidence. From then on every segment of it is Modbus: malformed
// frames are decoded and reported as events (as Suricata does), and a message
// split across segments is decoded when its last segment arrives. See
// detect.ModbusTracker. A packet on port 502 without payload, such as a
// handshake segment, is reported below the default confidence threshold.
func (p *IndustrialProtocolParserImpl) parseModbusTCP(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok || transport != detect.TCP {
		return nil
	}
	m := p.detectProtocol(packet, "Modbus")

	var msgs []detect.ModbusMessage
	known := false
	if nl := packet.NetworkLayer(); nl != nil {
		key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
		hint := srcPort == detect.ModbusPort || dstPort == detect.ModbusPort
		p.modbusMu.Lock()
		if p.modbus == nil {
			p.modbus = detect.NewModbusTracker()
		}
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		msgs = p.modbus.FeedTCP(key, dstPort == detect.ModbusPort, detect.TCPSegment{
			Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
		}, hint)
		known = p.modbus.Known(key)
		p.modbusMu.Unlock()
	}
	if m == nil && !known {
		return nil
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "modbus",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	portErr := p.extractPortInfo(packet, info, []uint16{detect.ModbusPort})

	switch {
	case m != nil && m.Result == detect.Recognized && m.PortHint && portErr == nil:
		info.Confidence = 0.9
	case m != nil && m.Result == detect.Recognized:
		info.Confidence = 0.8
	case known && len(payload) > 0 && portErr == nil:
		// Inside a recognised connection: a continuation segment, a bare
		// header or a malformed frame.
		info.Confidence = 0.9
	case known && len(payload) > 0:
		info.Confidence = 0.8
	default:
		info.Confidence = 0.5
	}
	decodeModbusInto(msgs, info)
	return info
}

// decodeModbusInto adds the function-level view of the segment's messages:
// what was asked (function, address range) or answered (exception). The
// details come from the first message; the access class, function codes and
// events cover all of them.
func decodeModbusInto(msgs []detect.ModbusMessage, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var codes []uint8
	var events []string
	access := detect.ModbusUnknown
	rank := map[detect.ModbusAccess]int{detect.ModbusUnknown: 0, detect.ModbusOther: 1, detect.ModbusRead: 2,
		detect.ModbusDiagnostic: 3, detect.ModbusReadWrite: 4, detect.ModbusWrite: 5}
	for i, m := range msgs {
		codes = append(codes, m.FunctionCode)
		events = append(events, m.Events...)
		if rank[m.Access] > rank[access] {
			access = m.Access
		}
		if i > 0 {
			continue
		}
		info.MessageType = m.FunctionName
		info.AdditionalData["function_code"] = m.FunctionCode
		info.AdditionalData["transaction_id"] = m.TransactionID
		info.AdditionalData["unit_id"] = m.UnitID
		info.AdditionalData["is_exception"] = m.IsException
		if m.IsException {
			info.AdditionalData["exception_code"] = m.ExceptionCode
			if m.ExceptionName != "" {
				info.AdditionalData["exception"] = m.ExceptionName
			}
		}
		if m.Address >= 0 {
			info.AdditionalData["address"] = m.Address
			info.AdditionalData["quantity"] = m.Quantity
		}
		if m.WriteAddress >= 0 {
			info.AdditionalData["write_address"] = m.WriteAddress
			info.AdditionalData["write_quantity"] = m.WriteQuantity
		}
	}
	info.AdditionalData["access"] = string(access)
	info.AdditionalData["message_count"] = len(codes)
	info.AdditionalData["function_codes"] = codes
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	info.IsConfiguration = access == detect.ModbusWrite || access == detect.ModbusReadWrite
}
