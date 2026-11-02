package parser

import (
	"fmt"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseEtherNetIP parses EtherNet/IP (ENIP) protocol.
//
// Detection is by content (see detect.ProbeENIPEncapsulation); the port only
// raises confidence. A packet on an EtherNet/IP port that carries no payload
// (for example a TCP handshake segment) or only a partial header is reported
// with low confidence, which the default threshold filters out.
func (p *IndustrialProtocolParserImpl) parseEtherNetIP(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	m := p.detectEtherNetIP(packet)
	msgs, known := p.enipMessages(packet)
	if m == nil && !known {
		return nil
	}

	protocolName := "EtherNet/IP"
	ports := []uint16{detect.ENIPPortExplicit, detect.ENIPPortImplicit}
	switch packet.TransportLayer().(type) {
	case *layers.TCP:
		protocolName = "EtherNet/IP(TCP)"
		ports = []uint16{detect.ENIPPortExplicit}
	case *layers.UDP:
		protocolName = "EtherNet/IP(UDP)"
		ports = []uint16{detect.ENIPPortExplicit, detect.ENIPPortImplicit}
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       protocolName,
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	// Port and direction are best effort; a content match on another port is
	// still EtherNet/IP.
	portErr := p.extractPortInfo(packet, info, ports)

	switch {
	case m != nil && m.Result == detect.Recognized && m.PortHint && portErr == nil:
		info.Confidence = 0.9
	case m != nil && m.Result == detect.Recognized:
		info.Confidence = 0.8
	case known && portErr == nil:
		// Inside a recognised connection: a continuation segment, or a message
		// the strict probe would not accept first.
		info.Confidence = 0.9
	case known:
		info.Confidence = 0.8
	default:
		// Hint port with an empty or partial payload: not enough evidence.
		info.Confidence = 0.5
	}
	decodeENIPInto(msgs, info)
	return info
}

// enipMessages returns the encapsulation messages the packet completes, and
// whether its TCP connection is known to be EtherNet/IP. A UDP datagram stands
// alone; implicit I/O (UDP 2222) has no encapsulation header and is not decoded.
func (p *IndustrialProtocolParserImpl) enipMessages(packet gopacket.Packet) ([]detect.ENIPMessage, bool) {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok {
		return nil, false
	}
	if transport == detect.UDP {
		if msg, ok := detect.DecodeENIPDatagram(payload); ok {
			return []detect.ENIPMessage{msg}, false
		}
		return nil, false
	}
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	nl := packet.NetworkLayer()
	if tcp == nil || nl == nil {
		return nil, false
	}
	key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
	hint := srcPort == detect.ENIPPortExplicit || dstPort == detect.ENIPPortExplicit
	p.enipMu.Lock()
	defer p.enipMu.Unlock()
	if p.enip == nil {
		p.enip = detect.NewENIPTracker()
	}
	msgs := p.enip.FeedTCP(key, dstPort == detect.ENIPPortExplicit, detect.TCPSegment{
		Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
	}, hint)
	return msgs, p.enip.Known(key)
}

// decodeENIPInto adds the decoded view of the packet's messages: the command,
// the CIP request or reply, and, for a ListIdentity reply, the identity of the
// device that answered. Details come from the first message; events cover all.
func decodeENIPInto(msgs []detect.ENIPMessage, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var events []string
	for _, m := range msgs {
		events = append(events, m.Events...)
	}
	m := msgs[0]
	info.MessageType = m.CommandName
	info.AdditionalData["command"] = m.Command
	info.AdditionalData["command_name"] = m.CommandName
	info.AdditionalData["status"] = m.Status
	info.AdditionalData["status_name"] = m.StatusName
	info.AdditionalData["session_handle"] = m.Session
	info.AdditionalData["message_count"] = len(msgs)
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	switch m.Command {
	case detect.ENIPListIdentity, detect.ENIPListServices, detect.ENIPListInterfaces:
		info.IsDiscovery = true
	}
	if m.RegisterSession != nil {
		info.AdditionalData["protocol_version"] = m.RegisterSession.ProtocolVersion
	}
	for _, it := range m.Items {
		if id := it.Identity; id != nil {
			info.DeviceIdentity["vendor_id"] = id.VendorID
			info.DeviceIdentity["device_type"] = id.DeviceType
			info.DeviceIdentity["product_code"] = id.ProductCode
			info.DeviceIdentity["revision"] = fmt.Sprintf("%d.%d", id.RevisionMajor, id.RevisionMinor)
			info.DeviceIdentity["serial"] = id.Serial
			info.DeviceIdentity["product_name"] = id.ProductName
			info.DeviceIdentity["status"] = id.Status
			info.DeviceIdentity["state"] = id.State
			info.DeviceIdentity["ip_address"] = id.IP
			break
		}
	}
	if c := m.CIP; c != nil {
		info.AdditionalData["cip_service"] = c.Service
		info.AdditionalData["cip_service_name"] = c.ServiceName
		info.AdditionalData["cip_is_response"] = c.IsResponse
		if c.IsResponse {
			info.AdditionalData["cip_status"] = c.GeneralStatus
			info.AdditionalData["cip_status_name"] = c.GeneralStatusName
		} else {
			if c.Class >= 0 {
				info.AdditionalData["cip_class"] = c.Class
			}
			if c.Instance >= 0 {
				info.AdditionalData["cip_instance"] = c.Instance
			}
			if c.Attribute >= 0 {
				info.AdditionalData["cip_attribute"] = c.Attribute
			}
			if c.Symbol != "" {
				info.AdditionalData["cip_symbol"] = c.Symbol
			}
		}
		switch c.Service {
		case 0x02, 0x04, 0x10, 0x4d, 0x53:
			info.IsConfiguration = true // writes
		}
	}
}
