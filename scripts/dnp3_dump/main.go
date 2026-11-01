// Command dnp3_dump prints one JSON line per DNP3 link frame found in a classic
// pcap (TCP, and UDP datagrams, on port 20000 or anywhere the probe recognises
// a frame), using the importer's tracker. scripts/compare_dnp3.py diffs it
// against tshark's DNP3 dissector.
//
//	go run ./scripts/dnp3_dump capture.pcap > ours.jsonl
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
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dnp3_dump capture.pcap")
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
	tracker := detect.NewDNP3Tracker()
	const port = detect.DNP3Port
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
		if udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); udp != nil {
			request := uint16(udp.DstPort) == port
			for _, m := range detect.DecodeDNP3Datagram(udp.Payload) {
				enc.Encode(record(n, src, dst, uint16(udp.SrcPort), uint16(udp.DstPort), request, "udp", m))
			}
			continue
		}
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp == nil {
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
			enc.Encode(record(n, src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort), request, "tcp", m))
		}
	}
}
