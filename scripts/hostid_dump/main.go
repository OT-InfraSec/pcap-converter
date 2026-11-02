// Command hostid_dump prints one JSON line per NetBIOS name service message
// (UDP 137) and per SMB / NetBIOS session service message (TCP 445 and 139) that
// lib/hostid decodes from a classic pcap. scripts/compare_hostid.py diffs it
// against tshark's dissectors.
//
//	go run ./scripts/hostid_dump capture.pcap > ours.jsonl
//
// Only the first PDU of a TCP segment is read, as the importer does.
package main

import (
	"encoding/json"
	"os"

	"github.com/InfraSecConsult/pcap-importer-go/lib/hostid"
	"github.com/InfraSecConsult/pcap-importer-go/scripts/internal/dumpcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns

func filetime(t interface {
	IsZero() bool
	UnixNano() int64
}) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano()/100) + epochDiff
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	dumpcap.ForEachPacket("hostid_dump", func(n int, pkt gopacket.Packet) {
		if udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); udp != nil {
			if udp.SrcPort != 137 && udp.DstPort != 137 {
				return
			}
			m, ok := hostid.DecodeNBNS(udp.Payload)
			if !ok {
				return
			}
			rec := map[string]any{"pkt": n, "kind": "nbns"}
			var bind, status [][]any
			for _, b := range m.Names {
				bind = append(bind, []any{b.String()[:len(b.Name)+4], b.Group, b.IP})
			}
			for _, s := range m.Status {
				status = append(status, []any{s.String()[:len(s.Name)+4], s.Group})
			}
			rec["bind"], rec["status"], rec["mac"] = bind, status, m.StatusMAC
			enc.Encode(rec)
			return
		}
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp == nil || len(tcp.Payload) == 0 || (tcp.SrcPort != 445 && tcp.DstPort != 445 && tcp.SrcPort != 139 && tcp.DstPort != 139) {
			return
		}
		h, ok := hostid.ParseNBSS(tcp.Payload)
		if !ok {
			return
		}
		body := tcp.Payload[4:]
		if h.Length < len(body) {
			body = body[:h.Length]
		}
		rec := map[string]any{"pkt": n, "kind": "smb", "nbss": h.Type}
		switch h.Type {
		case hostid.NBSSRequest:
			r, ok := hostid.DecodeSessionRequest(body)
			if !ok {
				return
			}
			rec["called"], rec["calling"] = r.Called.String()[:len(r.Called.Name)+4], r.Calling.String()[:len(r.Calling.Name)+4]
		case hostid.NBSSMessage:
			info, ok := hostid.DecodeSMB(body)
			if !ok {
				return
			}
			rec["smb_kind"], rec["command"], rec["response"] = info.Kind, info.Command, info.Response
			rec["dialect"], rec["offered"] = info.Dialect, info.OfferedDialects
			rec["signing_enabled"], rec["signing_required"], rec["guid"] = info.SigningEnabled, info.SigningRequired, info.GUID
			rec["system_time"], rec["start_time"] = filetime(info.SystemTime), filetime(info.ServerStartTime)
			if m := info.NTLM; m != nil {
				nt := map[string]any{"type": m.Type, "target": m.TargetName, "nb_computer": m.NetBIOSComputer, "nb_domain": m.NetBIOSDomain,
					"dns_computer": m.DNSComputer, "dns_domain": m.DNSDomain, "domain": m.Domain, "user": m.User, "workstation": m.Workstation}
				if m.Version != nil {
					nt["version"] = []int{int(m.Version.Major), int(m.Version.Minor), int(m.Version.Build)}
				}
				rec["ntlm"] = nt
			}
		default:
			return
		}
		enc.Encode(rec)
	})
}
