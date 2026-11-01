// Command enip_dump prints one JSON line per EtherNet/IP encapsulation message
// found in a classic pcap, using the same trackers as the importer.
// scripts/compare_enip.py diffs it against Suricata's eve.json enip records.
//
//	go run ./scripts/enip_dump capture.pcap > ours.jsonl
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func record(n int, src, dst string, sport, dport uint16, request bool, m detect.ENIPMessage) map[string]any {
	r := map[string]any{
		"pkt": n, "src": src, "dst": dst, "sport": sport, "dport": dport, "request": request,
		"command": m.CommandName, "status": m.StatusName, "session": m.Session, "events": m.Events,
	}
	if rs := m.RegisterSession; rs != nil {
		r["register_session"] = map[string]any{"protocol_version": rs.ProtocolVersion, "options": rs.Options}
	}
	for _, it := range m.Items {
		if id := it.Identity; id != nil {
			r["identity"] = map[string]any{
				"protocol_version": id.ProtocolVersion, "revision": fmt.Sprintf("%d.%d", id.RevisionMajor, id.RevisionMinor),
				"vendor_id": id.VendorID, "device_type": id.DeviceType, "product_code": id.ProductCode,
				"status": id.Status, "serial": id.Serial, "product_name": id.ProductName, "state": id.State,
				"ip": id.IP, "port": id.Port,
			}
			break
		}
		if s := it.Services; s != nil {
			r["list_services"] = map[string]any{"protocol_version": s.ProtocolVersion, "capabilities": s.Capabilities, "service_name": s.Name}
			break
		}
	}
	if c := m.CIP; c != nil {
		r["cip"] = cipRecord(c)
	}
	return r
}

func cipRecord(c *detect.CIPMessage) map[string]any {
	r := map[string]any{"service": c.Service, "response": c.IsResponse, "service_name": c.ServiceName}
	if c.IsResponse {
		r["status"] = c.GeneralStatus
		r["status_name"] = c.GeneralStatusName
		r["extended"] = c.ExtendedStatus
	} else {
		var path [][2]any
		for _, s := range c.Path {
			path = append(path, [2]any{s.Kind, s.Value})
		}
		r["path"] = path
		r["class"], r["instance"], r["attribute"] = c.Class, c.Instance, c.Attribute
		r["symbol"] = c.Symbol
		r["truncated"] = c.PathTruncated
	}
	var multi []map[string]any
	for _, s := range c.Multiple {
		multi = append(multi, cipRecord(s))
	}
	if multi != nil {
		r["multiple"] = multi
	}
	return r
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: enip_dump capture.pcap")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	tracker := detect.NewENIPTracker()
	const port = detect.ENIPPortExplicit
	for n := 1; ; n++ {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
		nl := pkt.NetworkLayer()
		if nl == nil {
			continue
		}
		src, dst := nl.NetworkFlow().Src().String(), nl.NetworkFlow().Dst().String()
		if tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); tcp != nil {
			if uint16(tcp.SrcPort) != port && uint16(tcp.DstPort) != port {
				continue
			}
			request := uint16(tcp.DstPort) == port
			key := fmt.Sprintf("%s:%d|%s:%d", src, tcp.SrcPort, dst, tcp.DstPort)
			if !request {
				key = fmt.Sprintf("%s:%d|%s:%d", dst, tcp.DstPort, src, tcp.SrcPort)
			}
			for _, m := range tracker.FeedTCP(key, request, detect.TCPSegment{
				Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: tcp.Payload,
			}, true) {
				enc.Encode(record(n, src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort), request, m))
			}
		} else if udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); udp != nil {
			if uint16(udp.SrcPort) != port && uint16(udp.DstPort) != port {
				continue
			}
			m, ok := detect.DecodeENIPDatagram(udp.Payload)
			if !ok {
				continue
			}
			// Both ports can be 44818 (discovery): then an empty list command is
			// the request and a reply carries items.
			request := uint16(udp.DstPort) == port && (uint16(udp.SrcPort) != port || m.Length == 0)
			enc.Encode(record(n, src, dst, uint16(udp.SrcPort), uint16(udp.DstPort), request, m))
		}
	}
}
