// Command modbus_dump prints one JSON line per Modbus ADU found in a classic
// pcap, using lib/detect. scripts/compare_modbus.py diffs it against
// Suricata's eve.json modbus records.
//
//	go run ./scripts/modbus_dump capture.pcap > ours.jsonl
package main

import (
	"encoding/json"
	"os"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/scripts/internal/dumpcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	enc := json.NewEncoder(os.Stdout)
	// The same tracker the importer uses, so the dump shows what it would see.
	tracker := detect.NewModbusTracker()
	dumpcap.ForEachPacket("modbus_dump", func(n int, pkt gopacket.Packet) {
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		nl := pkt.NetworkLayer()
		if tcp == nil || nl == nil {
			return
		}
		request := uint16(tcp.DstPort) == detect.ModbusPort
		if !request && uint16(tcp.SrcPort) != detect.ModbusPort {
			return
		}
		src, dst := nl.NetworkFlow().Src().String(), nl.NetworkFlow().Dst().String()
		key := dumpcap.Key(src, tcp.SrcPort, dst, tcp.DstPort, request)
		for _, m := range tracker.FeedTCP(key, request, dumpcap.Segment(tcp), true) {
			enc.Encode(map[string]any{
				"pkt": n, "src": src, "dst": dst,
				"sport": uint16(tcp.SrcPort), "dport": uint16(tcp.DstPort),
				"request": request, "txn": m.TransactionID, "unit": m.UnitID, "fc": m.FunctionCode, "raw_fc": m.RawFunction,
				"exception": m.IsException, "exc_code": m.ExceptionCode, "addr": m.Address, "qty": m.Quantity,
				"access": m.Access, "events": m.Events,
			})
		}
	})
}
