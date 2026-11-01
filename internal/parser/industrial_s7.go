package parser

import (
	"fmt"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseS7 parses S7comm (Siemens, ISO-on-TCP). A connection is S7 when its data
// TPDUs carry the S7 protocol id; port 102 alone proves nothing (MMS uses it).
// The connection request on that port is decoded for its rack and slot, which
// later S7 messages of the connection carry, but it is not reported as S7 on
// its own: the result is below the default confidence threshold until a PDU
// shows the protocol.
func (p *IndustrialProtocolParserImpl) parseS7(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok || transport != detect.TCP {
		return nil
	}
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	nl := packet.NetworkLayer()
	if tcp == nil || nl == nil {
		return nil
	}
	key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
	hint := srcPort == detect.S7Port || dstPort == detect.S7Port
	p.s7Mu.Lock()
	if p.s7 == nil {
		p.s7 = detect.NewS7Tracker()
	}
	msgs := p.s7.FeedTCP(key, dstPort == detect.S7Port, detect.TCPSegment{
		Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
	}, hint)
	plus := p.s7.SawS7Plus(key)
	known := p.s7.SawS7(key) || plus
	p.s7Mu.Unlock()
	if len(msgs) == 0 && !known {
		return nil
	}
	hasS7 := false
	for _, m := range msgs {
		hasS7 = hasS7 || m.HasS7 || m.Plus != nil
		plus = plus || m.Plus != nil
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "s7",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	portErr := p.extractPortInfo(packet, info, []uint16{detect.S7Port})
	switch {
	case hasS7 && portErr == nil:
		info.Confidence = 0.9
	case hasS7:
		info.Confidence = 0.8
	case known && len(payload) > 0 && portErr == nil:
		// A continuation segment of a connection that has shown S7 PDUs.
		info.Confidence = 0.8
	default:
		info.Confidence = 0.5
	}
	if plus {
		// S7CommPlus (S7-1200 fw 4+, S7-1500): same port and framing, different PDU.
		info.Protocol = "s7commplus"
	}
	decodeS7Into(msgs, info)
	return info
}

// decodeS7Into adds the decoded view of the packet's messages: the S7 service
// (function, items, data), the connection's rack and slot, and for an SZL reply
// the identity of the CPU. Details come from the first S7 message; events cover
// all messages.
func decodeS7Into(msgs []detect.S7Message, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var events []string
	var first *detect.S7Message
	for i, m := range msgs {
		events = append(events, m.Events...)
		if first == nil && (m.HasS7 || m.Plus != nil) {
			first = &msgs[i]
		}
	}
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	info.AdditionalData["message_count"] = len(msgs)
	m := msgs[0]
	if first != nil {
		m = *first
	}
	info.AdditionalData["cotp_type"] = m.COTPName
	if m.Rack >= 0 {
		info.AdditionalData["rack"] = m.Rack
		info.AdditionalData["slot"] = m.Slot
	}
	if m.TPDUSize > 0 {
		info.AdditionalData["tpdu_size"] = m.TPDUSize
	}
	if h := m.Plus; h != nil {
		info.AdditionalData["s7plus_version"] = h.Version
		info.AdditionalData["s7plus_opcode"] = h.Opcode
		info.AdditionalData["s7plus_opcode_name"] = h.OpcodeName
		info.MessageType = h.OpcodeName
		if h.HasFields {
			info.AdditionalData["s7plus_function"] = h.Function
			info.AdditionalData["s7plus_function_name"] = h.FunctionName
			info.AdditionalData["s7plus_sequence"] = h.Sequence
			info.AdditionalData["s7plus_session_id"] = h.SessionID
		}
		return
	}
	if !m.HasS7 {
		return
	}
	info.MessageType = m.ROSCTRName
	info.AdditionalData["rosctr"] = m.ROSCTR
	info.AdditionalData["rosctr_name"] = m.ROSCTRName
	info.AdditionalData["pdu_reference"] = m.PDURef
	info.AdditionalData["function"] = m.Function
	info.AdditionalData["function_name"] = m.FunctionName
	if m.ErrorClass != 0 || m.ErrorCode != 0 {
		info.AdditionalData["error_class"] = m.ErrorClass
		info.AdditionalData["error_code"] = m.ErrorCode
	}
	if m.Setup != nil {
		info.AdditionalData["pdu_length"] = m.Setup.PDULength
	}
	if len(m.Items) > 0 {
		it := m.Items[0]
		info.AdditionalData["item_count"] = len(m.Items)
		info.AdditionalData["area"] = it.Area
		info.AdditionalData["area_name"] = it.AreaName
		info.AdditionalData["db_number"] = it.DB
		info.AdditionalData["address"] = it.ByteAddress
		info.AdditionalData["bit"] = it.Bit
		info.AdditionalData["length"] = it.Length
	}
	if m.PLCService != "" {
		info.AdditionalData["plc_service"] = m.PLCService
	}
	switch {
	case m.ROSCTR == 1 && (m.Function == 0x05 || m.Function == 0x28 || m.Function == 0x29 ||
		(m.Function >= 0x1a && m.Function <= 0x1f)):
		info.IsConfiguration = true // writes, PLC start and stop, program transfer
	}
	if u := m.Userdata; u != nil {
		info.AdditionalData["function_group"] = u.FunctionGroup
		info.AdditionalData["function_group_name"] = u.FunctionGroupName
		info.AdditionalData["userdata_type"] = u.TypeName
		if u.SZLID != 0 {
			info.AdditionalData["szl_id"] = u.SZLID
			info.AdditionalData["szl_index"] = u.SZLIndex
		}
		if u.FunctionGroup == 4 && u.SubFunction == 1 {
			info.IsDiscovery = true
		}
		if u.FunctionGroup == 7 && (u.SubFunction == 2 || u.SubFunction == 4) {
			info.IsConfiguration = true // set clock
		}
		if id := u.Identity; id != nil {
			names := map[uint16]string{1: "system_name", 2: "module_name", 3: "plant_id", 4: "copyright", 5: "serial_number", 7: "module_type_name", 8: "memory_card_serial"}
			for idx, v := range id.Strings {
				if k, ok := names[idx]; ok {
					info.DeviceIdentity[k] = v
				}
			}
			if id.OrderNumber != "" {
				info.DeviceIdentity["order_number"] = id.OrderNumber
				info.DeviceIdentity["module_type"] = id.ModuleType
				info.DeviceIdentity["version"] = fmt.Sprintf("%d.%d", id.Version[0], id.Version[1])
			}
		}
	}
}
