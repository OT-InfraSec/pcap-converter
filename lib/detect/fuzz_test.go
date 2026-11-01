package detect

import (
	"math/rand"
	"testing"
)

// FuzzProbes checks that no probe panics and that results stay in range.
func FuzzProbes(f *testing.F) {
	f.Add([]byte{})
	f.Add(enipHeader(ENIPListIdentity, 0, 0, 0, nil))
	f.Add(enipHeader(ENIPListInterfaces, 2, 0, 0, []byte{3, 0}))
	f.Add(cpf(2, cpfItem(0x8002, make([]byte, 8)), cpfItem(0x00B1, []byte{1, 0})))
	f.Add(dnp3Segment(dnp3ToOutstation, true, true, 0, dnp3ReadClass0))
	f.Fuzz(func(t *testing.T, b []byte) {
		decodeAllNoPanic(b)
		ParseDNP3Frame(b) // must not panic on any input
		DecodeDNP3Datagram(b)
		NewDNP3Tracker().FeedTCP("c", true, TCPSegment{Seq: 1, ACK: true, Payload: b}, true)
		for _, p := range []Probe{ProbeENIPEncapsulation, ProbeENIPImplicitIO, ProbeENIPUDP, ProbeDNP3, ProbeS7, ProbeS7Plus, ProbeModbusTCP} {
			if r := p(b); r > Recognized {
				t.Fatalf("result out of range: %d", r)
			}
		}
	})
}

// TestProbesRandomDataFalsePositives feeds random payloads to the probes. A
// strict probe should essentially never accept noise.
func TestProbesRandomDataFalsePositives(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const n = 2_000_000
	var enc, imp int
	buf := make([]byte, 64)
	for i := 0; i < n; i++ {
		rng.Read(buf)
		b := buf[:6+rng.Intn(58)]
		if ProbeENIPEncapsulation(b) == Recognized {
			enc++
		}
		if ProbeENIPImplicitIO(b) == Recognized {
			imp++
		}
	}
	t.Logf("random payloads=%d encapsulation false positives=%d implicit false positives=%d", n, enc, imp)
	if enc > n/10000 || imp > 0 {
		t.Fatalf("too many false positives: enc=%d imp=%d of %d", enc, imp, n)
	}
}

// decodeAllNoPanic runs every decoder of the package on b; the point is that
// none panics, whatever the bytes.
func decodeAllNoPanic(b []byte) {
	DecodeModbusADU(b, true)
	DecodeModbusADU(b, false)
	DecodeENIP(b)
	DecodeENIPDatagram(b)
	if f, _, ok := ParseS7Frame(b); ok {
		MessageFromFrames([]S7Frame{f})
	}
	MessageFromFrames([]S7Frame{{COTPType: cotpDT, EOT: true, Payload: b}})
	decodeDNP3App(b, true)
	decodeDNP3App(b, false)
	ParseDNP3Frame(b)
	DecodeDNP3Datagram(b)
}

// TestDecodersNeverPanicOnRandomInput feeds random and mutated bytes to every
// decoder, as lib/layers does for its gopacket decoders.
func TestDecodersNeverPanicOnRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	seeds := [][]byte{
		dnp3Segment(dnp3ToOutstation, true, true, 0, dnp3ReadClass0),
		dtFrame(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil)),
		dtFrame(s7PlusPDU(1, s7PlusOpRequest, 0x04bb, 1, 0)),
		enipHeader(ENIPListIdentity, 0, 0, 0, nil),
		{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1},
	}
	buf := make([]byte, 96)
	for i := 0; i < 300_000; i++ {
		var b []byte
		if i%2 == 0 {
			rng.Read(buf)
			b = buf[:rng.Intn(len(buf))]
		} else {
			b = append([]byte(nil), seeds[rng.Intn(len(seeds))]...)
			for k := rng.Intn(4); k >= 0; k-- {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			b = b[:rng.Intn(len(b)+1)]
		}
		decodeAllNoPanic(b)
	}
}
