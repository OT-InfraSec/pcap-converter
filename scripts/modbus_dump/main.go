// Command modbus_dump prints one JSON line per Modbus ADU found in a classic
// pcap, using lib/detect. scripts/compare_modbus.py diffs it against
// Suricata's eve.json modbus records.
//
//	go run ./scripts/modbus_dump capture.pcap > ours.jsonl
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: modbus_dump capture.pcap")
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
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		nl := pkt.NetworkLayer()
		if tcp == nil || nl == nil || len(tcp.Payload) == 0 {
			continue
		}
		request := uint16(tcp.DstPort) == detect.ModbusPort
		if !request && uint16(tcp.SrcPort) != detect.ModbusPort {
			continue
		}
		adus, _ := detect.SplitModbusADUs(tcp.Payload)
		for _, adu := range adus {
			m, ok := detect.DecodeModbusADU(adu, request)
			if !ok {
				continue
			}
			enc.Encode(map[string]any{
				"pkt": n, "src": nl.NetworkFlow().Src().String(), "dst": nl.NetworkFlow().Dst().String(),
				"request": request, "txn": m.TransactionID, "unit": m.UnitID, "fc": m.FunctionCode,
				"exception": m.IsException, "exc_code": m.ExceptionCode, "addr": m.Address, "qty": m.Quantity,
				"access": m.Access, "events": m.Events,
			})
		}
	}
}
