package detect

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestCorpusModbus runs the Modbus probe over real captures. Skipped unless
// PCAP_CORPUS names a directory of .pcap files.
//
//	PCAP_CORPUS=/path/to/captures go test ./lib/detect -run TestCorpusModbus -v
//
// Every payload on TCP 502 must be recognised, and no TCP payload on any other
// port may be. The log shows how payloads split into ADUs, which says how much
// TCP reassembly matters for this traffic.
func TestCorpusModbus(t *testing.T) {
	dir := os.Getenv("PCAP_CORPUS")
	if dir == "" {
		t.Skip("PCAP_CORPUS not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) == 0 {
		t.Skipf("no .pcap files in %s", dir)
	}
	for _, file := range files {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			f, err := os.Open(file)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			r, err := pcapgo.NewReader(f)
			if err != nil {
				t.Skipf("not a classic pcap: %v", err)
			}
			var onPort, recognized, unrecognized, incomplete int
			var oneADU, severalADUs, partialTail, noADU int
			var otherChecked, otherFalse int
			var firstBad, firstFalse []byte
			for {
				data, _, err := r.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
				l := pkt.Layer(layers.LayerTypeTCP)
				if l == nil {
					continue
				}
				tc := l.(*layers.TCP)
				if len(tc.Payload) == 0 {
					continue
				}
				if tc.SrcPort != 502 && tc.DstPort != 502 {
					otherChecked++
					if ProbeModbusTCP(tc.Payload) == Recognized {
						otherFalse++
						if firstFalse == nil {
							firstFalse = append([]byte(nil), tc.Payload...)
						}
					}
					continue
				}
				onPort++
				switch ProbeModbusTCP(tc.Payload) {
				case Recognized:
					recognized++
				case Incomplete:
					incomplete++
				default:
					unrecognized++
					if firstBad == nil {
						firstBad = append([]byte(nil), tc.Payload...)
					}
				}
				adus, rest := SplitModbusADUs(tc.Payload)
				switch {
				case len(adus) == 0:
					noADU++
				case len(adus) == 1:
					oneADU++
				default:
					severalADUs++
				}
				if len(adus) > 0 && len(rest) > 0 {
					partialTail++
				}
			}
			t.Logf("tcp/502 payloads=%d recognized=%d incomplete=%d unrecognized=%d", onPort, recognized, incomplete, unrecognized)
			t.Logf("  split: one ADU=%d several ADUs=%d ADU plus partial tail=%d no complete ADU=%d", oneADU, severalADUs, partialTail, noADU)
			t.Logf("other TCP payloads checked=%d false positives=%d", otherChecked, otherFalse)
			if unrecognized > 0 {
				t.Errorf("%d payloads on tcp/502 not recognised, first: % x", unrecognized, firstBad)
			}
			if otherFalse > 0 {
				t.Errorf("%d payloads on other ports recognised as Modbus, first: % x", otherFalse, firstFalse)
			}
		})
	}
}
