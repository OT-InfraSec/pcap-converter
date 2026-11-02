package detect

import (
	"encoding/binary"
	"testing"
)

func nbssFrame(typ byte, body []byte) []byte {
	n := len(body)
	return append([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// nbName is the first-level encoding of a NetBIOS name (RFC 1001 14.1).
func nbName(name string, suffix byte) []byte {
	raw := make([]byte, 16)
	for i := range raw[:15] {
		raw[i] = ' '
	}
	copy(raw, name)
	raw[15] = suffix
	out := []byte{0x20}
	for _, c := range raw {
		out = append(out, 'A'+c>>4, 'A'+c&0x0f)
	}
	return append(out, 0)
}

func TestProbeSMB(t *testing.T) {
	smb2 := append([]byte{0xfe, 'S', 'M', 'B'}, make([]byte, 60)...)
	smb1 := append([]byte{0xff, 'S', 'M', 'B', 0x72}, make([]byte, 27)...)
	req := append(nbName("SRV01", 0x20), nbName("HMI02", 0x00)...)
	tests := []struct {
		name string
		in   []byte
		want Result
	}{
		{"SMB2 session message", nbssFrame(0, smb2), Recognized},
		{"SMB1 session message", nbssFrame(0, smb1), Recognized},
		{"SMB3 encrypted transform", nbssFrame(0, append([]byte{0xfd, 'S', 'M', 'B'}, make([]byte, 48)...)), Recognized},
		{"session request with two names", nbssFrame(0x81, req), Recognized},
		{"session request, names cut off", nbssFrame(0x81, req)[:30], Incomplete},
		{"session request with bad names", nbssFrame(0x81, make([]byte, 68)), Unrecognized},
		{"positive response alone", []byte{0x82, 0, 0, 0}, Incomplete},
		{"keep-alive alone", []byte{0x85, 0, 0, 0}, Incomplete},
		{"empty", nil, Incomplete},
		{"first byte of a message", []byte{0}, Incomplete},
		{"header only", []byte{0, 0, 0, 0x40}, Incomplete},
		{"header and half an id", append([]byte{0, 0, 0, 0x40}, 0xfe, 'S'), Incomplete},
		{"message that is not SMB", nbssFrame(0, []byte("GET / HTTP/1.1\r\n")), Unrecognized},
		{"HTTP", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Unrecognized},
		{"TLS record", []byte{0x16, 3, 1, 0, 0xa5, 1, 0, 0, 0xa1}, Unrecognized},
		{"reserved flag bits on a request", append([]byte{0x81, 0x04, 0, 0x44}, req...), Unrecognized},
	}
	for _, tt := range tests {
		if got := ProbeSMB(tt.in); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestProbeNBNS(t *testing.T) {
	hdr := func(flags uint16, qd, an, ar int) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[2:], flags)
		binary.BigEndian.PutUint16(b[4:], uint16(qd))
		binary.BigEndian.PutUint16(b[6:], uint16(an))
		binary.BigEndian.PutUint16(b[10:], uint16(ar))
		return b
	}
	query := append(append(hdr(0x0110, 1, 0, 0), nbName("HMI01", 0x20)...), 0, 0x20, 0, 1)
	tests := []struct {
		name string
		in   []byte
		want Result
	}{
		{"name query", query, Recognized},
		{"12 zero bytes", make([]byte, 12), Unrecognized},
		{"short", query[:8], Unrecognized},
		{"a question with a bad name", append(hdr(0x0110, 1, 0, 0), make([]byte, 40)...), Unrecognized},
		{"DNS query for a host", append(append(hdr(0x0100, 1, 0, 0), 5, 'h', 'm', 'i', '0', '1', 0), 0, 1, 0, 1), Unrecognized},
		{"unknown opcode", append(append(hdr(9<<11, 1, 0, 0), nbName("A", 0)...), 0, 0x20, 0, 1), Unrecognized},
	}
	for _, tt := range tests {
		if got := ProbeNBNS(tt.in); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}
