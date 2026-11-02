package hostid

import (
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"unicode/utf16"
)

// ---- builders, written from the specs and independent of the decoders ----

// nbEncode is the first-level encoding of RFC 1001 14.1: the name padded to 15
// characters plus the suffix, each byte as two letters 'A' + nibble.
func nbEncode(name string, suffix byte, scope string) []byte {
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
	if scope != "" {
		out = append(out, byte(len(scope)))
		out = append(out, scope...)
	}
	return append(out, 0)
}

func u16(v uint16) []byte  { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func u32(v uint32) []byte  { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le64(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func nbnsHeader(flags uint16, qd, an, ns, ar int) []byte {
	return cat(u16(0x1234), u16(flags), u16(uint16(qd)), u16(uint16(an)), u16(uint16(ns)), u16(uint16(ar)))
}

func nbRR(name []byte, typ uint16, rdata []byte) []byte {
	return cat(name, u16(typ), u16(1), u32(300), u16(uint16(len(rdata))), rdata)
}

func nbAddr(flags uint16, ip net.IP) []byte { return cat(u16(flags), ip.To4()) }

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, le16(u)...)
	}
	return out
}

// ---- NBNS ----

func TestDecodeNBNS(t *testing.T) {
	host := nbEncode("PLC-LINE3", 0x20, "")
	ip := net.IPv4(10, 20, 0, 7)

	t.Run("a registration binds a name to the sender's address", func(t *testing.T) {
		// RFC 1002 4.2.2: question plus the NB record in the additional section.
		msg := cat(nbnsHeader(5<<11|0x0010, 1, 0, 0, 1), host, u16(nbnsTypeNB), u16(1),
			nbRR([]byte{0xc0, 0x0c}, nbnsTypeNB, nbAddr(0x0000, ip)))
		m, ok := DecodeNBNS(msg)
		if !ok || len(m.Names) != 1 {
			t.Fatalf("ok=%v names=%v", ok, m.Names)
		}
		if got := m.Names[0]; got.Name != "PLC-LINE3" || got.Suffix != 0x20 || got.Group || got.IP != "10.20.0.7" {
			t.Errorf("%+v", got)
		}
	})
	t.Run("a group flag is read from the NB flags", func(t *testing.T) {
		msg := cat(nbnsHeader(5<<11, 1, 0, 0, 1), nbEncode("WORKGROUP", 0, ""), u16(nbnsTypeNB), u16(1),
			nbRR([]byte{0xc0, 0x0c}, nbnsTypeNB, nbAddr(0x8000, ip)))
		m, _ := DecodeNBNS(msg)
		if len(m.Names) != 1 || !m.Names[0].Group || m.Names[0].String() != "WORKGROUP<00> G" {
			t.Errorf("%v", m.Names)
		}
	})
	t.Run("a positive name query response carries the binding", func(t *testing.T) {
		msg := cat(nbnsHeader(0x8000|0x0400, 0, 1, 0, 0), nbRR(host, nbnsTypeNB, nbAddr(0, ip)))
		m, ok := DecodeNBNS(msg)
		if !ok || len(m.Names) != 1 || m.Names[0].IP != "10.20.0.7" {
			t.Errorf("ok=%v %v", ok, m.Names)
		}
	})
	t.Run("a query and a release bind nothing", func(t *testing.T) {
		q := cat(nbnsHeader(0x0110, 1, 0, 0, 0), host, u16(nbnsTypeNB), u16(1))
		if m, ok := DecodeNBNS(q); !ok || len(m.Names) != 0 {
			t.Errorf("query: ok=%v %v", ok, m.Names)
		}
		rel := cat(nbnsHeader(6<<11, 1, 0, 0, 1), host, u16(nbnsTypeNB), u16(1), nbRR([]byte{0xc0, 0x0c}, nbnsTypeNB, nbAddr(0, ip)))
		if m, ok := DecodeNBNS(rel); !ok || len(m.Names) != 0 {
			t.Errorf("release: ok=%v %v", ok, m.Names)
		}
	})
	t.Run("a node status response lists the names and the adapter", func(t *testing.T) {
		entry := func(name string, suffix byte, flags uint16) []byte {
			n := make([]byte, 15)
			for i := range n {
				n[i] = ' '
			}
			copy(n, name)
			return cat(n, []byte{suffix}, u16(flags))
		}
		rdata := cat([]byte{3}, entry("HMI01", 0x00, 0x0400), entry("WORKGROUP", 0x00, 0x8400), entry("HMI01", 0x20, 0x0400),
			[]byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}, make([]byte, 40))
		msg := cat(nbnsHeader(0x8400, 0, 1, 0, 0), nbRR(nbEncode("*", 0, ""), nbnsTypeNBSTAT, rdata))
		m, ok := DecodeNBNS(msg)
		if !ok || len(m.Status) != 3 || m.StatusMAC != "00:1a:2b:3c:4d:5e" {
			t.Fatalf("ok=%v status=%v mac=%q", ok, m.Status, m.StatusMAC)
		}
		if m.Status[1].String() != "WORKGROUP<00> G" || m.Status[2].String() != "HMI01<20>" {
			t.Errorf("%v", m.Status)
		}
	})
	t.Run("an all-zero unit ID is not a MAC", func(t *testing.T) {
		rdata := cat([]byte{0}, make([]byte, 46))
		msg := cat(nbnsHeader(0x8400, 0, 1, 0, 0), nbRR(nbEncode("*", 0, ""), nbnsTypeNBSTAT, rdata))
		if m, _ := DecodeNBNS(msg); m.StatusMAC != "" {
			t.Errorf("mac %q", m.StatusMAC)
		}
	})
	t.Run("addresses that are not hosts are skipped", func(t *testing.T) {
		for _, bad := range []net.IP{net.IPv4zero, net.IPv4bcast, net.IPv4(224, 0, 0, 1)} {
			msg := cat(nbnsHeader(0x8400, 0, 1, 0, 0), nbRR(host, nbnsTypeNB, nbAddr(0, bad)))
			if m, _ := DecodeNBNS(msg); len(m.Names) != 0 {
				t.Errorf("%v accepted", bad)
			}
		}
	})
	t.Run("malformed names and counts are rejected", func(t *testing.T) {
		bad := map[string][]byte{
			"short":             {1, 2, 3},
			"bad opcode":        nbnsHeader(9<<11, 0, 0, 0, 0),
			"two questions":     nbnsHeader(0, 2, 0, 0, 0),
			"too many records":  nbnsHeader(0x8000, 0, 17, 0, 0),
			"record cut off":    cat(nbnsHeader(0x8000, 0, 1, 0, 0), host),
			"letter out of A-P": cat(nbnsHeader(0x8000, 0, 1, 0, 0), append([]byte{0x20, 'Z'}, make([]byte, 40)...)),
			"pointer forward":   cat(nbnsHeader(0x8000, 0, 1, 0, 0), []byte{0xc0, 0x20}, make([]byte, 40)),
			"pointer to itself": cat(nbnsHeader(0x8000, 0, 1, 0, 0), []byte{0xc0, 0x0c}, make([]byte, 40)),
			"rdata cut off":     cat(nbnsHeader(0x8000, 0, 1, 0, 0), host, u16(nbnsTypeNB), u16(1), u32(0), u16(60), []byte{1}),
		}
		for name, b := range bad {
			if _, ok := DecodeNBNS(b); ok {
				t.Errorf("%s accepted", name)
			}
		}
	})
	t.Run("a forward pointer is rejected even where a valid name follows", func(t *testing.T) {
		// The record name points at offset 24, past itself, where a good name sits.
		msg := cat(nbnsHeader(0x8400, 0, 1, 0, 0), []byte{0xc0, 24}, u16(nbnsTypeNB), u16(1), u32(0), u16(0), nbEncode("HMI01", 0, ""))
		if _, ok := DecodeNBNS(msg); ok {
			t.Error("forward pointer accepted")
		}
	})
	t.Run("a scope id is skipped", func(t *testing.T) {
		msg := cat(nbnsHeader(0x8400, 0, 1, 0, 0), nbRR(nbEncode("HMI01", 0, "plant.example"), nbnsTypeNB, nbAddr(0, ip)))
		if m, ok := DecodeNBNS(msg); !ok || len(m.Names) != 1 || m.Names[0].Name != "HMI01" {
			t.Errorf("ok=%v %v", ok, m.Names)
		}
	})
}

// ---- NTLMSSP ----

// secField builds the (length, max length, offset) triple of MS-NLMP 2.2.2.1.
func secField(n, off int) []byte { return cat(le16(uint16(n)), le16(uint16(n)), le32(uint32(off))) }

func avPair(id uint16, v []byte) []byte { return cat(le16(id), le16(uint16(len(v))), v) }

func ntlmChallengeMsg(flags uint32, target string, avs []byte, version []byte) []byte {
	tn := utf16le(target)
	const fixed = 56
	return cat(ntlmSignature, le32(2), secField(len(tn), fixed), le32(flags), make([]byte, 8), make([]byte, 8),
		secField(len(avs), fixed+len(tn)), version, tn, avs)
}

func TestDecodeNTLMChallenge(t *testing.T) {
	avs := cat(avPair(avNbDomain, utf16le("PLANT")), avPair(avNbComputer, utf16le("HMI01")),
		avPair(avDNSDomain, utf16le("plant.example")), avPair(avDNSComputer, utf16le("hmi01.plant.example")),
		avPair(avDNSTree, utf16le("plant.example")), avPair(avTimestamp, le64(132000000000000000)), avPair(avEOL, nil))
	version := []byte{10, 0, 0x63, 0x4a, 0, 0, 0, 0x0f} // Windows 10.0 build 19043

	t.Run("names and version", func(t *testing.T) {
		m, ok := DecodeNTLMSSP(ntlmChallengeMsg(ntlmFlagUnicode|ntlmFlagVersion, "PLANT", avs, version))
		if !ok {
			t.Fatal("not decoded")
		}
		if m.NetBIOSComputer != "HMI01" || m.NetBIOSDomain != "PLANT" || m.DNSComputer != "hmi01.plant.example" ||
			m.DNSDomain != "plant.example" || m.DNSTree != "plant.example" || m.TargetName != "PLANT" {
			t.Errorf("%+v", m)
		}
		if m.Version == nil || m.Version.String() != "10.0.19043" {
			t.Errorf("version %v", m.Version)
		}
		if m.Timestamp != 132000000000000000 {
			t.Errorf("timestamp %d", m.Timestamp)
		}
	})
	t.Run("no version flag, no version", func(t *testing.T) {
		m, _ := DecodeNTLMSSP(ntlmChallengeMsg(ntlmFlagUnicode, "PLANT", avs, version))
		if m.Version != nil {
			t.Errorf("version %v without the flag", m.Version)
		}
	})
	t.Run("a version without the revision byte 0x0f is ignored", func(t *testing.T) {
		m, _ := DecodeNTLMSSP(ntlmChallengeMsg(ntlmFlagUnicode|ntlmFlagVersion, "PLANT", avs, []byte{10, 0, 1, 2, 0, 0, 0, 0}))
		if m.Version != nil {
			t.Errorf("version %v", m.Version)
		}
	})
	t.Run("an offset past the message is dropped, not read", func(t *testing.T) {
		msg := ntlmChallengeMsg(ntlmFlagUnicode, "PLANT", avs, make([]byte, 8))
		copy(msg[16:20], le32(0xffffff00)) // TargetName offset
		copy(msg[44:48], le32(0xffffff00)) // TargetInfo offset
		m, ok := DecodeNTLMSSP(msg)
		if !ok || m.TargetName != "" || m.NetBIOSComputer != "" {
			t.Errorf("ok=%v %+v", ok, m)
		}
	})
	t.Run("a control character in a name drops the name", func(t *testing.T) {
		m, _ := DecodeNTLMSSP(ntlmChallengeMsg(ntlmFlagUnicode, "PLANT", avPair(avNbComputer, utf16le("HM\x07I")), make([]byte, 8)))
		if m.NetBIOSComputer != "" {
			t.Errorf("%q", m.NetBIOSComputer)
		}
	})
	t.Run("OEM strings when Unicode was not negotiated", func(t *testing.T) {
		msg := cat(ntlmSignature, le32(2), secField(5, 56), le32(0), make([]byte, 16), secField(0, 61), make([]byte, 8), []byte("PLANT"))
		if m, _ := DecodeNTLMSSP(msg); m.TargetName != "PLANT" {
			t.Errorf("%q", m.TargetName)
		}
	})
}

func TestDecodeNTLMAuthenticate(t *testing.T) {
	dom, usr, ws := utf16le("PLANT"), utf16le("operator"), utf16le("HMI02")
	const fixed = 88
	msg := cat(ntlmSignature, le32(3), secField(0, fixed), secField(0, fixed), secField(len(dom), fixed), secField(len(usr), fixed+len(dom)),
		secField(len(ws), fixed+len(dom)+len(usr)), secField(0, fixed), le32(ntlmFlagUnicode|ntlmFlagVersion),
		[]byte{6, 1, 0xb1, 0x1d, 0, 0, 0, 0x0f}, make([]byte, 16), dom, usr, ws)
	m, ok := DecodeNTLMSSP(msg)
	if !ok || m.Domain != "PLANT" || m.User != "operator" || m.Workstation != "HMI02" {
		t.Fatalf("ok=%v %+v", ok, m)
	}
	if m.Version == nil || m.Version.String() != "6.1.7601" {
		t.Errorf("version %v", m.Version)
	}
}

func TestDecodeNTLMRejects(t *testing.T) {
	for name, b := range map[string][]byte{
		"nil":             nil,
		"signature only":  ntlmSignature,
		"negotiate":       cat(ntlmSignature, le32(1), make([]byte, 20)),
		"unknown type":    cat(ntlmSignature, le32(9), make([]byte, 60)),
		"short challenge": cat(ntlmSignature, le32(2), make([]byte, 10)),
		"bad signature":   cat([]byte("NTLMSSQ\x00"), le32(2), make([]byte, 60)),
	} {
		if _, ok := DecodeNTLMSSP(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// ---- SMB ----

func smb2Header(cmd uint16, response bool) []byte {
	flags := uint32(0)
	if response {
		flags = 1
	}
	return cat([]byte{0xfe, 'S', 'M', 'B'}, le16(64), le16(1), le32(0), le16(cmd), le16(1), le32(flags), le32(0), le64(1), le32(0), le32(0), le64(0), make([]byte, 16))
}

func TestDecodeSMB2NegotiateResponse(t *testing.T) {
	guid := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	const day = 864000000000 // one day in 100 ns
	sys := uint64(132000000000000000)
	body := cat(le16(65), le16(0x0003), le16(0x0311), le16(0), guid, le32(0x7f), le32(8388608), le32(8388608), le32(8388608),
		le64(sys), le64(sys-3*day), le16(128), le16(0), le32(0))
	info, ok := DecodeSMB(cat(smb2Header(smb2CmdNeg, true), body))
	if !ok || info.Kind != SMB2 || !info.Response {
		t.Fatalf("ok=%v %+v", ok, info)
	}
	if info.Dialect != "3.1.1" || !info.SigningEnabled || !info.SigningRequired {
		t.Errorf("%+v", info)
	}
	if info.GUID != "12345678-9abc-def0-0102-030405060708" {
		t.Errorf("guid %q", info.GUID)
	}
	if up := info.SystemTime.Sub(info.ServerStartTime); up.Hours() != 72 {
		t.Errorf("uptime %v", up)
	}
}

func TestDecodeSMB2NegotiateRequest(t *testing.T) {
	body := cat(le16(36), le16(3), le16(0x0001), le16(0), le32(0), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, le64(0),
		le16(0x0202), le16(0x0210), le16(0x0311))
	info, ok := DecodeSMB(cat(smb2Header(smb2CmdNeg, false), body))
	if !ok || info.Response || info.SigningRequired || !info.SigningEnabled {
		t.Fatalf("ok=%v %+v", ok, info)
	}
	if got := info.OfferedDialects; len(got) != 3 || got[0] != "2.0.2" || got[2] != "3.1.1" {
		t.Errorf("dialects %v", got)
	}
	if info.GUID != "04030201-0605-0807-090a-0b0c0d0e0f10" {
		t.Errorf("guid %q", info.GUID)
	}
}

func TestDecodeSMBFindsNTLMInSessionSetup(t *testing.T) {
	avs := avPair(avNbComputer, utf16le("SRV01"))
	challenge := ntlmChallengeMsg(ntlmFlagUnicode, "PLANT", avs, make([]byte, 8))
	// A SPNEGO wrapper is some ASN.1 before the message; the signature is what counts.
	blob := cat([]byte{0xa1, 0x81, 0x99, 0x30, 0x81, 0x96, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa2, 0x81, 0x90, 0x04, 0x81, 0x8d}, challenge)
	info, ok := DecodeSMB(cat(smb2Header(smb2CmdSetup, true), le16(9), le16(0), le16(72), le16(uint16(len(blob))), blob))
	if !ok || info.NTLM == nil || info.NTLM.NetBIOSComputer != "SRV01" {
		t.Fatalf("ok=%v %+v", ok, info.NTLM)
	}
}

func TestDecodeSMBOther(t *testing.T) {
	smb1 := cat([]byte{0xff, 'S', 'M', 'B', 0x72}, le32(0), []byte{0x80}, make([]byte, 22))
	if info, ok := DecodeSMB(smb1); !ok || info.Kind != SMB1 || info.Command != 0x72 || !info.Response {
		t.Errorf("smb1: %v %+v", ok, info)
	}
	enc := cat([]byte{0xfd, 'S', 'M', 'B'}, make([]byte, 48))
	if info, ok := DecodeSMB(enc); !ok || info.Kind != SMBEncrypted {
		t.Errorf("encrypted: %v %+v", ok, info)
	}
	for name, b := range map[string][]byte{
		"empty":           nil,
		"not smb":         []byte("GET / HTTP/1.1\r\n"),
		"smb2 short":      cat([]byte{0xfe, 'S', 'M', 'B'}, make([]byte, 20)),
		"smb2 wrong size": cat([]byte{0xfe, 'S', 'M', 'B'}, le16(60), make([]byte, 60)),
	} {
		if _, ok := DecodeSMB(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestNBSSAndSessionRequest(t *testing.T) {
	if h, ok := ParseNBSS([]byte{0, 0, 0, 0x40}); !ok || h.Type != NBSSMessage || h.Length != 0x40 {
		t.Errorf("%+v %v", h, ok)
	}
	if _, ok := ParseNBSS([]byte{0x81, 0x04, 0, 0}); ok { // flag bits other than the extension bit
		t.Error("reserved flag accepted")
	}
	if _, ok := ParseNBSS([]byte{0x42, 0, 0, 0}); ok {
		t.Error("unknown type accepted")
	}
	body := cat(nbEncode("SRV01", 0x20, ""), nbEncode("HMI02", 0x00, ""))
	r, ok := DecodeSessionRequest(body)
	if !ok || r.Called.String() != "SRV01<20>" || r.Calling.String() != "HMI02<00>" {
		t.Errorf("%v %+v", ok, r)
	}
	if _, ok := DecodeSessionRequest(body[:40]); ok {
		t.Error("truncated request accepted")
	}
}

// Random and truncated input must never panic.
func TestHostidNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	seeds := [][]byte{
		cat(nbnsHeader(0x8400, 0, 1, 0, 0), nbRR(nbEncode("HMI01", 0, ""), nbnsTypeNB, nbAddr(0, net.IPv4(10, 0, 0, 1)))),
		ntlmChallengeMsg(ntlmFlagUnicode|ntlmFlagVersion, "PLANT", avPair(avNbComputer, utf16le("A")), []byte{10, 0, 1, 2, 0, 0, 0, 0x0f}),
		cat(smb2Header(smb2CmdNeg, true), make([]byte, 70)),
	}
	run := func(b []byte) {
		DecodeNBNS(b)
		DecodeNTLMSSP(b)
		DecodeSMB(b)
		DecodeSessionRequest(b)
		ParseNBSS(b)
		FindNTLMSSP(b)
	}
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), seeds[rng.Intn(len(seeds))]...)
		for k := rng.Intn(6); k > 0 && len(b) > 0; k-- {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		if rng.Intn(3) == 0 && len(b) > 0 {
			b = b[:rng.Intn(len(b))]
		}
		run(b)
	}
}

func FuzzHostid(f *testing.F) {
	f.Add(cat(nbnsHeader(0x8400, 0, 1, 0, 0), nbRR(nbEncode("HMI01", 0, ""), nbnsTypeNB, nbAddr(0, net.IPv4(10, 0, 0, 1)))))
	f.Add(ntlmChallengeMsg(ntlmFlagUnicode, "PLANT", avPair(avNbComputer, utf16le("A")), make([]byte, 8)))
	f.Add(cat(smb2Header(smb2CmdNeg, false), make([]byte, 40)))
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodeNBNS(b)
		DecodeNTLMSSP(b)
		DecodeSMB(b)
		DecodeSessionRequest(b)
	})
}
