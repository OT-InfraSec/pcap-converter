// Command dnp3_dump prints one JSON line per DNP3 link frame found in a classic
// pcap (TCP, and UDP datagrams, on port 20000 or anywhere the probe recognises
// a frame), using the importer's tracker. scripts/compare_dnp3.py diffs it
// against tshark's DNP3 dissector.
//
//	go run ./scripts/dnp3_dump capture.pcap > ours.jsonl
package main

import (
	"encoding/json"
	"os"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/scripts/internal/dumpcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func record(n int, src, dst string, sport, dport uint16, request bool, transport string, m detect.DNP3Message) map[string]any {
	f := m.Frame
	r := map[string]any{
		"pkt": n, "src": src, "dst": dst, "sport": sport, "dport": dport, "request": request, "transport": transport,
		"len": f.Length, "ctl": f.Control, "dest": f.Dest, "source": f.Src, "events": m.Events,
		"invalid": m.Frame.Invalid, "fir": m.FIR, "fin": m.FIN, "tseq": m.TransportSeq, "has_transport": m.HasTransport,
	}
	if a := m.App; a != nil {
		var objs [][7]uint64
		for _, o := range a.Objects {
			start, stop, count := uint64(0), uint64(0), uint64(0)
			if o.Range <= 5 {
				start, stop = uint64(o.Start), uint64(o.Stop)
			} else {
				count = uint64(o.Count)
			}
			objs = append(objs, [7]uint64{uint64(o.Group), uint64(o.Variation), uint64(o.Prefix), uint64(o.Range), start, stop, count})
		}
		r["app"] = map[string]any{
			"ctl": a.Control, "func": a.Function, "iin": a.IIN, "response": a.IsResponse,
			"objects": objs, "complete": a.ObjectsComplete,
		}
	}
	return r
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	tracker := detect.NewDNP3Tracker()
	const port = detect.DNP3Port
	dumpcap.ForEachPacket("dnp3_dump", func(n int, pkt gopacket.Packet) {
		nl := pkt.NetworkLayer()
		if nl == nil {
			return
		}
		src, dst := nl.NetworkFlow().Src().String(), nl.NetworkFlow().Dst().String()
		if udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); udp != nil {
			request := uint16(udp.DstPort) == port
			for _, m := range detect.DecodeDNP3Datagram(udp.Payload) {
				enc.Encode(record(n, src, dst, uint16(udp.SrcPort), uint16(udp.DstPort), request, "udp", m))
			}
			return
		}
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp == nil {
			return
		}
		request := uint16(tcp.DstPort) == port
		key := dumpcap.Key(src, tcp.SrcPort, dst, tcp.DstPort, request)
		for _, m := range tracker.FeedTCP(key, request, dumpcap.Segment(tcp), true) {
			enc.Encode(record(n, src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort), request, "tcp", m))
		}
	})
}
