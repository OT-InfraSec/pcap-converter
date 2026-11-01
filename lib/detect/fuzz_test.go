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
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range []Probe{ProbeENIPEncapsulation, ProbeENIPImplicitIO, ProbeENIPUDP} {
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
