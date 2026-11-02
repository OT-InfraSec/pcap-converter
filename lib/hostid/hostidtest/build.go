// Package hostidtest builds NetBIOS name service, session service, SMB2 and
// NTLMSSP messages from the specs (RFC 1001/1002, MS-SMB2, MS-NLMP), for tests
// of code that consumes lib/hostid. It is not used outside tests.
package hostidtest

import (
	"encoding/binary"
	"net"
	"unicode/utf16"
)

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
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

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, le16(u)...)
	}
	return out
}

// NBEncode is the first-level encoding of a NetBIOS name (RFC 1001 14.1).
func NBEncode(name string, suffix byte) []byte {
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

// NBNSRegistration is a name registration request (RFC 1002 4.2.2) for name,
// held by ip. group marks a group name.
func NBNSRegistration(name string, suffix byte, group bool, ip net.IP) []byte {
	flags := uint16(0)
	if group {
		flags = 0x8000
	}
	rr := cat([]byte{0xc0, 0x0c}, be16(0x0020), be16(1), be32(300), be16(6), be16(flags), ip.To4())
	return cat(be16(0x1111), be16(5<<11|0x0010), be16(1), be16(0), be16(0), be16(1),
		NBEncode(name, suffix), be16(0x0020), be16(1), rr)
}

// NBName is a name for NBSTATResponse.
type NBName struct {
	Name   string
	Suffix byte
	Group  bool
}

// NBSTATResponse is a node status response (RFC 1002 4.2.18) listing names and
// the adapter address.
func NBSTATResponse(names []NBName, mac [6]byte) []byte {
	rdata := []byte{byte(len(names))}
	for _, n := range names {
		raw := make([]byte, 15)
		for i := range raw {
			raw[i] = ' '
		}
		copy(raw, n.Name)
		flags := uint16(0x0400)
		if n.Group {
			flags |= 0x8000
		}
		rdata = append(rdata, cat(raw, []byte{n.Suffix}, be16(flags))...)
	}
	rdata = append(rdata, mac[:]...)
	rdata = append(rdata, make([]byte, 40)...)
	rr := cat(NBEncode("*", 0), be16(0x0021), be16(1), be32(0), be16(uint16(len(rdata))), rdata)
	return cat(be16(0x2222), be16(0x8400), be16(0), be16(1), be16(0), be16(0), rr)
}

// NBSSFrame wraps a body in a session service header of the given type.
func NBSSFrame(typ byte, body []byte) []byte {
	n := len(body)
	return append([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// SessionRequest is the body of a session request (RFC 1002 4.3.2).
func SessionRequest(called string, calledSuffix byte, calling string, callingSuffix byte) []byte {
	return NBSSFrame(0x81, cat(NBEncode(called, calledSuffix), NBEncode(calling, callingSuffix)))
}

func smb2Header(cmd uint16, response bool) []byte {
	flags := uint32(0)
	if response {
		flags = 1
	}
	return cat([]byte{0xfe, 'S', 'M', 'B'}, le16(64), le16(1), le32(0), le16(cmd), le16(1), le32(flags),
		le32(0), le64(1), le32(0), le32(0), le64(0), make([]byte, 16))
}

// SMB2NegotiateRequest offers the given dialect revisions (for example 0x0311).
func SMB2NegotiateRequest(signingRequired bool, clientGUID [16]byte, dialects ...uint16) []byte {
	mode := uint16(1)
	if signingRequired {
		mode = 3
	}
	d := []byte{}
	for _, v := range dialects {
		d = append(d, le16(v)...)
	}
	body := cat(le16(36), le16(uint16(len(dialects))), le16(mode), le16(0), le32(0), clientGUID[:], le64(0), d)
	return NBSSFrame(0, cat(smb2Header(0, false), body))
}

// SMB2NegotiateResponse answers with the chosen dialect, the server GUID and
// the server's clock and start time (FILETIME values).
func SMB2NegotiateResponse(dialect uint16, signingRequired bool, serverGUID [16]byte, systemTime, startTime uint64) []byte {
	mode := uint16(1)
	if signingRequired {
		mode = 3
	}
	body := cat(le16(65), le16(mode), le16(dialect), le16(0), serverGUID[:], le32(0x7f), le32(8388608), le32(8388608), le32(8388608),
		le64(systemTime), le64(startTime), le16(128), le16(0), le32(0))
	return NBSSFrame(0, cat(smb2Header(0, true), body))
}

func secField(n, off int) []byte { return cat(le16(uint16(n)), le16(uint16(n)), le32(uint32(off))) }

func avPair(id uint16, v []byte) []byte { return cat(le16(id), le16(uint16(len(v))), v) }

// NTLMChallenge is an NTLMSSP CHALLENGE message (MS-NLMP 2.2.1.2) with the
// server's NetBIOS and DNS names and a Windows version.
func NTLMChallenge(nbComputer, nbDomain, dnsComputer, dnsDomain string, major, minor uint8, build uint16) []byte {
	avs := cat(avPair(2, utf16le(nbDomain)), avPair(1, utf16le(nbComputer)), avPair(4, utf16le(dnsDomain)),
		avPair(3, utf16le(dnsComputer)), avPair(0, nil))
	tn := utf16le(nbDomain)
	const fixed = 56
	version := cat([]byte{major, minor}, le16(build), []byte{0, 0, 0, 0x0f})
	return cat([]byte("NTLMSSP\x00"), le32(2), secField(len(tn), fixed), le32(0x02000001), make([]byte, 16),
		secField(len(avs), fixed+len(tn)), version, tn, avs)
}

// NTLMAuthenticate is an NTLMSSP AUTHENTICATE message (MS-NLMP 2.2.1.3).
func NTLMAuthenticate(domain, user, workstation string, major, minor uint8, build uint16) []byte {
	dom, usr, ws := utf16le(domain), utf16le(user), utf16le(workstation)
	const fixed = 88
	version := cat([]byte{major, minor}, le16(build), []byte{0, 0, 0, 0x0f})
	return cat([]byte("NTLMSSP\x00"), le32(3), secField(0, fixed), secField(0, fixed), secField(len(dom), fixed),
		secField(len(usr), fixed+len(dom)), secField(len(ws), fixed+len(dom)+len(usr)), secField(0, fixed),
		le32(0x02000001), version, make([]byte, 16), dom, usr, ws)
}

// SMB2SessionSetup wraps an NTLMSSP message as the security buffer of a session
// setup request or response, behind a SPNEGO-like prefix.
func SMB2SessionSetup(response bool, ntlm []byte) []byte {
	blob := spnego(ntlm, response)
	if response { // MS-SMB2 2.2.6: StructureSize 9, SessionFlags, security buffer offset and length
		return NBSSFrame(0, cat(smb2Header(1, true), le16(9), le16(0), le16(72), le16(uint16(len(blob))), blob))
	}
	// MS-SMB2 2.2.5: StructureSize 25, flags, mode, capabilities, channel, buffer offset and length, previous session id
	return NBSSFrame(0, cat(smb2Header(1, false), le16(25), []byte{0, 1}, le32(0), le32(0), le16(88), le16(uint16(len(blob))), le64(0), blob))
}

func der(tag byte, content []byte) []byte {
	n := len(content)
	var ln []byte
	switch {
	case n < 128:
		ln = []byte{byte(n)}
	case n < 256:
		ln = []byte{0x81, byte(n)}
	default:
		ln = []byte{0x82, byte(n >> 8), byte(n)}
	}
	return cat([]byte{tag}, ln, content)
}

// spnego wraps an NTLMSSP message in a SPNEGO NegTokenResp (RFC 4178 4.2.2);
// the server's reply also names the mechanism and says accept-incomplete.
func spnego(ntlm []byte, response bool) []byte {
	var inner []byte
	if response {
		oid := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // NTLMSSP
		inner = cat(der(0xa0, der(0x0a, []byte{1})), der(0xa1, der(0x06, oid)))
	}
	inner = cat(inner, der(0xa2, der(0x04, ntlm)))
	return der(0xa1, der(0x30, inner))
}
