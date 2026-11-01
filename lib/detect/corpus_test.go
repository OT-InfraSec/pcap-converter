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

// TestCorpusENIP runs the ENIP probes over real captures. It is skipped unless
// PCAP_CORPUS names a directory of .pcap files, for example:
//
//	PCAP_CORPUS=/path/to/captures go test ./lib/detect -run TestCorpusENIP -v
//
// Every UDP 2222 datagram must be recognised (implicit I/O), and no payload on
// non-EtherNet/IP port may be recognised as EtherNet/IP.
func TestCorpusENIP(t *testing.T) {
	dir := os.Getenv("PCAP_CORPUS")
	if dir == "" {
		t.Skip("PCAP_CORPUS not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) == 0 {
		t.Skipf("no .pcap files in %s", dir)
	}
	enip, _ := Default().Lookup("EtherNet/IP")

	type tally struct{ rec, inc, unrec int }
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
			var udp2222, udp44818, tcp44818 tally
			var otherChecked, otherFalsePositives int
			var firstFalsePositive []byte
			var firstBadUDP []byte
			for {
				data, _, err := r.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
				var payload []byte
				var transport Transport
				var port uint16
				if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
					u := l.(*layers.UDP)
					transport, payload = UDP, u.Payload
					switch {
					case u.SrcPort == 2222 || u.DstPort == 2222:
						port = 2222
					case u.SrcPort == 44818 || u.DstPort == 44818:
						port = 44818
					}
				} else if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
					tc := l.(*layers.TCP)
					transport, payload = TCP, tc.Payload
					if tc.SrcPort == 44818 || tc.DstPort == 44818 {
						port = 44818
					}
				}
				if len(payload) == 0 {
					continue
				}
				if port == 0 {
					// Not on an EtherNet/IP port: none of this may be recognised.
					if transport != 0 {
						otherChecked++
						if enip.ProbeFor(transport)(payload) == Recognized {
							otherFalsePositives++
							if firstFalsePositive == nil {
								firstFalsePositive = append([]byte(nil), payload...)
							}
						}
					}
					continue
				}
				res := enip.ProbeFor(transport)(payload)
				var tl *tally
				switch {
				case transport == UDP && port == 2222:
					tl = &udp2222
				case transport == UDP:
					tl = &udp44818
				default:
					tl = &tcp44818
				}
				switch res {
				case Recognized:
					tl.rec++
				case Incomplete:
					tl.inc++
				default:
					tl.unrec++
					if transport == UDP && port == 2222 && firstBadUDP == nil {
						firstBadUDP = append([]byte(nil), payload...)
					}
				}
			}
			t.Logf("udp/2222  : recognized=%d incomplete=%d unrecognized=%d", udp2222.rec, udp2222.inc, udp2222.unrec)
			t.Logf("udp/44818 : recognized=%d incomplete=%d unrecognized=%d", udp44818.rec, udp44818.inc, udp44818.unrec)
			t.Logf("tcp/44818 : recognized=%d incomplete=%d unrecognized=%d (non-recognized segments are mid-message data until TCP reassembly exists)", tcp44818.rec, tcp44818.inc, tcp44818.unrec)
			t.Logf("other traffic: checked=%d false positives=%d", otherChecked, otherFalsePositives)
			if otherFalsePositives > 0 {
				t.Errorf("%d payloads on other ports were recognised as EtherNet/IP, first: % x", otherFalsePositives, firstFalsePositive)
			}
			if udp2222.unrec > 0 {
				t.Errorf("%d implicit I/O datagrams on UDP 2222 were not recognised, first: % x", udp2222.unrec, firstBadUDP)
			}
		})
	}
}
