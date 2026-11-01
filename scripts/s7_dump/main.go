// Command s7_dump prints one JSON line per S7comm message and COTP connection
// frame found in a classic pcap on TCP port 102, using the importer's tracker.
// scripts/compare_s7.py diffs it against tshark's S7comm dissector.
//
//	go run ./scripts/s7_dump capture.pcap > ours.jsonl
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func record(n int, src, dst string, sport, dport uint16, request bool, m detect.S7Message) map[string]any {
	r := map[string]any{
		"pkt": n, "src": src, "dst": dst, "sport": sport, "dport": dport, "request": request,
		"cotp": m.COTPName, "events": m.Events, "has_s7": m.HasS7,
	}
	if m.SrcTSAP != nil || m.DstTSAP != nil {
		r["src_tsap"], r["dst_tsap"] = hex.EncodeToString(m.SrcTSAP), hex.EncodeToString(m.DstTSAP)
	}
	if !m.HasS7 {
		return r
	}
	r["rosctr"], r["pduref"], r["function"] = m.ROSCTR, m.PDURef, m.Function
	r["error_class"], r["error_code"] = m.ErrorClass, m.ErrorCode
	var items [][5]uint64
	for _, it := range m.Items {
		items = append(items, [5]uint64{uint64(it.Area), uint64(it.DB), uint64(it.ByteAddress)*8 + uint64(it.Bit), uint64(it.Length), uint64(it.TransportSize)})
	}
	r["items"] = items
	var rcs []int
	for _, d := range m.Data {
		rcs = append(rcs, int(d.ReturnCode))
	}
	r["return_codes"] = rcs
	if u := m.Userdata; u != nil {
		r["userdata"] = map[string]any{"group": u.FunctionGroup, "sub": u.SubFunction, "szl_id": u.SZLID, "szl_index": u.SZLIndex}
		if id := u.Identity; id != nil {
			ident := map[string]any{}
			for k, v := range id.Strings {
				ident[fmt.Sprintf("s%d", k)] = v
			}
			if len(id.Modules) > 0 {
				mod := id.Modules[0]
				ident["order_number"], ident["module_type"] = mod.OrderNumber, mod.ModuleType
				ident["ausbg"], ident["ausbe"] = mod.Version[0], mod.Version[1]
			}
			r["identity"] = ident
		}
	}
	return r
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: s7_dump capture.pcap")
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
	tracker := detect.NewS7Tracker()
	const port = detect.S7Port
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
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if nl == nil || tcp == nil || (uint16(tcp.SrcPort) != port && uint16(tcp.DstPort) != port) {
			continue
		}
		src, dst := nl.NetworkFlow().Src().String(), nl.NetworkFlow().Dst().String()
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
	}
}
