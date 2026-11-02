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

// corpusPortProbe runs one registered probe over every TCP payload of the
// classic .pcap files in PCAP_CORPUS. On any port other than the protocol's
// hint port no payload may be Recognized, so a Modbus or ENIP capture in the
// same directory is a false-positive check. A file with payloads on the hint
// port must have some that are Recognized. Payloads on the port that are not
// are only counted: a segment that continues a long message does not start
// with a header and is Unrecognized or Incomplete on its own (the trackers
// handle those). Skipped unless PCAP_CORPUS is set.
//
//	PCAP_CORPUS=/path/to/captures go test ./lib/detect -run 'TestCorpus(S7|DNP3)' -v
func corpusPortProbe(t *testing.T, protocol string) {
	dir := os.Getenv("PCAP_CORPUS")
	if dir == "" {
		t.Skip("PCAP_CORPUS not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) == 0 {
		t.Skipf("no .pcap files in %s", dir)
	}
	proto, ok := Default().Lookup(protocol)
	if !ok {
		t.Fatalf("%s is not registered", protocol)
	}
	probe := proto.ProbeFor(TCP)
	if probe == nil {
		t.Fatalf("%s has no TCP probe", protocol)
	}
	isHint := func(src, dst uint16) bool {
		for _, h := range proto.HintPorts {
			if h.Transport&TCP != 0 && (h.Port == src || h.Port == dst) {
				return true
			}
		}
		return false
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
			var onPort, recognized, incomplete, rejected, otherChecked int
			for {
				data, _, err := r.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				l := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy).Layer(layers.LayerTypeTCP)
				if l == nil {
					continue
				}
				tc := l.(*layers.TCP)
				if len(tc.Payload) == 0 {
					continue
				}
				res := probe(tc.Payload)
				if !isHint(uint16(tc.SrcPort), uint16(tc.DstPort)) {
					otherChecked++
					if res == Recognized {
						t.Errorf("%s recognised a payload on %d -> %d: % x", protocol, tc.SrcPort, tc.DstPort, tc.Payload[:min(len(tc.Payload), 16)])
					}
					continue
				}
				onPort++
				switch res {
				case Recognized:
					recognized++
				case Incomplete:
					incomplete++
				default:
					rejected++
				}
			}
			t.Logf("%s: %d payloads on the port (recognised %d, incomplete %d, unrecognised %d), %d elsewhere", protocol, onPort, recognized, incomplete, rejected, otherChecked)
			if onPort > 0 && recognized == 0 {
				t.Errorf("%s: %d payloads on its port and none recognised", protocol, onPort)
			}
		})
	}
}

func TestCorpusS7(t *testing.T)   { corpusPortProbe(t, "S7") }
func TestCorpusDNP3(t *testing.T) { corpusPortProbe(t, "DNP3") }
