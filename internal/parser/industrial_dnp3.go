package parser

import (
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseDNP3 parses DNP3 (IEEE 1815) over TCP and UDP. A connection is DNP3
// when a payload starts with a link frame (start bytes 0x05 0x64 and a valid
// length), as in Suricata; the port only raises the confidence.
func (p *IndustrialProtocolParserImpl) parseDNP3(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok {
		return nil
	}
	var msgs []detect.DNP3Message
	known := false
	switch transport {
	case detect.UDP:
		msgs = detect.DecodeDNP3Datagram(payload)
	case detect.TCP:
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		nl := packet.NetworkLayer()
		if tcp == nil || nl == nil {
			return nil
		}
		key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
		hint := srcPort == detect.DNP3Port || dstPort == detect.DNP3Port
		p.dnp3Mu.Lock()
		if p.dnp3 == nil {
			p.dnp3 = detect.NewDNP3Tracker()
		}
		msgs = p.dnp3.FeedTCP(key, dstPort == detect.DNP3Port, detect.TCPSegment{
			Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
		}, hint)
		known = p.dnp3.Known(key)
		p.dnp3Mu.Unlock()
	}
	if len(msgs) == 0 && !known {
		return nil
	}
	info := &model.IndustrialProtocolInfo{
		Protocol:       "dnp3",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	portErr := p.extractPortInfo(packet, info, []uint16{detect.DNP3Port})
	switch {
	case len(msgs) > 0 && portErr == nil:
		info.Confidence = 0.9
	case len(msgs) > 0:
		info.Confidence = 0.8
	case portErr == nil:
		info.Confidence = 0.8 // continuation segment of a recognised connection
	default:
		info.Confidence = 0.5
	}
	decodeDNP3Into(msgs, info)
	return info
}

// decodeDNP3Into adds the decoded view of the packet's frames: link addresses
// and function, and the application function, IIN and object headers of the
// first completed fragment. Events cover all frames.
func decodeDNP3Into(msgs []detect.DNP3Message, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var events []string
	var app *detect.DNP3Message
	for i, m := range msgs {
		events = append(events, m.Events...)
		if app == nil && m.App != nil {
			app = &msgs[i]
		}
	}
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	info.AdditionalData["message_count"] = len(msgs)
	m := msgs[0]
	if app != nil {
		m = *app
	}
	f := m.Frame
	info.AdditionalData["source_address"] = f.Src
	info.AdditionalData["destination_address"] = f.Dest
	info.AdditionalData["from_master"] = f.FromMaster()
	if info.Direction == "" {
		// Not on the DNP3 port: the link layer's DIR bit says which side sent it,
		// the master being the client.
		info.Direction = "inbound"
		if f.FromMaster() {
			info.Direction = "outbound"
		}
	}
	info.AdditionalData["link_function"] = f.LinkFunction()
	info.AdditionalData["link_function_name"] = m.LinkName
	info.MessageType = m.LinkName
	if m.HasTransport {
		info.AdditionalData["transport_seq"] = m.TransportSeq
	}
	a := m.App
	if a == nil {
		return
	}
	info.MessageType = a.FunctionName
	info.AdditionalData["function"] = a.Function
	info.AdditionalData["function_name"] = a.FunctionName
	info.AdditionalData["app_sequence"] = a.Sequence()
	info.AdditionalData["unsolicited"] = a.Unsolicited()
	info.AdditionalData["confirm_requested"] = a.Confirm()
	if a.IsResponse {
		info.AdditionalData["iin"] = a.IIN
	}
	info.AdditionalData["object_count"] = len(a.Objects)
	if len(a.Objects) > 0 {
		o := a.Objects[0]
		info.AdditionalData["group"] = o.Group
		info.AdditionalData["variation"] = o.Variation
		info.AdditionalData["qualifier"] = o.Qualifier
		info.AdditionalData["points"] = o.Count
	}
	switch a.Function {
	case 2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 25, 26, 27, 31:
		// Writes, controls, restarts, application and unsolicited control,
		// class assignment, file changes and configuration activation.
		info.IsConfiguration = true
	}
	if f.FromMaster() {
		info.DeviceIdentity["dnp3_master_address"] = f.Src
	} else {
		info.DeviceIdentity["dnp3_outstation_address"] = f.Src
	}
}
