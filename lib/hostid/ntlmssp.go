package hostid

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// NTLMSSP (MS-NLMP). SMB, HTTP, LDAP and others carry these messages inside
// their security blobs. The server's CHALLENGE message names the machine (its
// NetBIOS and DNS names, its domain) and, when it sets the version flag, its
// Windows version. The client's AUTHENTICATE names the domain, user and
// workstation.

var ntlmSignature = []byte("NTLMSSP\x00")

const (
	ntlmNegotiate    = 1
	ntlmChallenge    = 2
	ntlmAuthenticate = 3

	ntlmFlagUnicode = 0x00000001
	ntlmFlagVersion = 0x02000000

	maxNTLMString  = 255
	maxNTLMTarget  = 4096 // TargetInfo is a few hundred bytes in practice
	ntlmAVPairsMax = 32
)

// NTLMVersion is the Windows version a message reports (MS-NLMP 2.2.2.10).
type NTLMVersion struct {
	Major, Minor uint8
	Build        uint16
}

func (v NTLMVersion) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build) }

// NTLMMessage holds the identity fields of a CHALLENGE or AUTHENTICATE message.
type NTLMMessage struct {
	Type uint32 // 2 CHALLENGE, 3 AUTHENTICATE

	// CHALLENGE: the server's names (target info AV pairs).
	TargetName      string
	NetBIOSComputer string // MsvAvNbComputerName
	NetBIOSDomain   string // MsvAvNbDomainName
	DNSComputer     string // MsvAvDnsComputerName
	DNSDomain       string // MsvAvDnsDomainName
	DNSTree         string // MsvAvDnsTreeName

	// AUTHENTICATE: what the client says about itself.
	Domain      string
	User        string
	Workstation string

	Version   *NTLMVersion // nil when the message carries none
	NegFlags  uint32
	Timestamp uint64 // MsvAvTimestamp: FILETIME of the server's clock, 0 when absent
}

// FindNTLMSSP returns the offset of the first NTLMSSP message in b, or -1.
// Security blobs are ASN.1 (SPNEGO) wrapped, so the message is found by its
// signature, not by walking the wrapper.
func FindNTLMSSP(b []byte) int { return bytes.Index(b, ntlmSignature) }

// DecodeNTLMSSP decodes the NTLMSSP message that starts at b[0]. Only CHALLENGE
// and AUTHENTICATE are of interest; NEGOTIATE (type 1) and anything malformed
// return false.
func DecodeNTLMSSP(b []byte) (NTLMMessage, bool) {
	var m NTLMMessage
	if len(b) < 12 || !bytes.Equal(b[:8], ntlmSignature) {
		return m, false
	}
	m.Type = binary.LittleEndian.Uint32(b[8:12])
	switch m.Type {
	case ntlmChallenge:
		return decodeChallenge(b, m)
	case ntlmAuthenticate:
		return decodeAuthenticate(b, m)
	}
	return m, false
}

// secBuf reads a security buffer field (length, max length, offset: MS-NLMP
// 2.2.2.1) at b[at:] and returns the bytes it points to.
func secBuf(b []byte, at int, limit int) ([]byte, bool) {
	if at+8 > len(b) {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(b[at : at+2]))
	off := int(binary.LittleEndian.Uint32(b[at+4 : at+8]))
	if n == 0 {
		return nil, true
	}
	if n > limit || off < 0 || off > len(b) || off+n > len(b) {
		return nil, false
	}
	return b[off : off+n], true
}

func decodeChallenge(b []byte, m NTLMMessage) (NTLMMessage, bool) {
	// signature(8) type(4) TargetNameFields(8) flags(4) challenge(8) reserved(8)
	// TargetInfoFields(8) [version(8)]
	if len(b) < 48 {
		return m, false
	}
	m.NegFlags = binary.LittleEndian.Uint32(b[20:24])
	unicode := m.NegFlags&ntlmFlagUnicode != 0
	if tn, ok := secBuf(b, 12, 2*maxNTLMString); ok {
		m.TargetName = ntlmString(tn, unicode)
	}
	if ti, ok := secBuf(b, 40, maxNTLMTarget); ok {
		decodeAVPairs(ti, &m)
	}
	if m.NegFlags&ntlmFlagVersion != 0 && len(b) >= 56 {
		m.Version = ntlmVersion(b[48:56])
	}
	return m, true
}

func decodeAuthenticate(b []byte, m NTLMMessage) (NTLMMessage, bool) {
	// signature(8) type(4) Lm(8) Nt(8) Domain(8) User(8) Workstation(8)
	// SessionKey(8) flags(4) [version(8)] [MIC(16)]
	if len(b) < 64 {
		return m, false
	}
	m.NegFlags = binary.LittleEndian.Uint32(b[60:64])
	unicode := m.NegFlags&ntlmFlagUnicode != 0
	for _, f := range []struct {
		at  int
		dst *string
	}{{28, &m.Domain}, {36, &m.User}, {44, &m.Workstation}} {
		if s, ok := secBuf(b, f.at, 2*maxNTLMString); ok {
			*f.dst = ntlmString(s, unicode)
		}
	}
	if m.NegFlags&ntlmFlagVersion != 0 && len(b) >= 72 {
		m.Version = ntlmVersion(b[64:72])
	}
	return m, true
}

// ntlmVersion decodes the 8-byte VERSION structure. The last byte is the NTLM
// revision (always 0x0F); a message with anything else did not fill it in.
func ntlmVersion(v []byte) *NTLMVersion {
	if v[7] != 0x0f {
		return nil
	}
	return &NTLMVersion{Major: v[0], Minor: v[1], Build: binary.LittleEndian.Uint16(v[2:4])}
}

// AV pair identifiers (MS-NLMP 2.2.2.1).
const (
	avEOL         = 0
	avNbComputer  = 1
	avNbDomain    = 2
	avDNSComputer = 3
	avDNSDomain   = 4
	avDNSTree     = 5
	avTimestamp   = 7
)

func decodeAVPairs(b []byte, m *NTLMMessage) {
	for i := 0; i < ntlmAVPairsMax && len(b) >= 4; i++ {
		id := binary.LittleEndian.Uint16(b[0:2])
		n := int(binary.LittleEndian.Uint16(b[2:4]))
		if id == avEOL || 4+n > len(b) {
			return
		}
		v := b[4 : 4+n]
		switch id {
		case avNbComputer:
			m.NetBIOSComputer = ntlmString(v, true) // target info is always UTF-16LE
		case avNbDomain:
			m.NetBIOSDomain = ntlmString(v, true)
		case avDNSComputer:
			m.DNSComputer = ntlmString(v, true)
		case avDNSDomain:
			m.DNSDomain = ntlmString(v, true)
		case avDNSTree:
			m.DNSTree = ntlmString(v, true)
		case avTimestamp:
			if n == 8 {
				m.Timestamp = binary.LittleEndian.Uint64(v)
			}
		}
		b = b[4+n:]
	}
}

// ntlmString decodes a UTF-16LE string, or an OEM (ASCII) one when the message
// did not negotiate Unicode. It returns "" for anything over the length limit
// or containing control characters: a name with those is not evidence.
func ntlmString(b []byte, unicode bool) string {
	if len(b) == 0 {
		return ""
	}
	var runes []rune
	if unicode {
		if len(b)%2 != 0 || len(b)/2 > maxNTLMString {
			return ""
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		runes = utf16.Decode(u)
	} else {
		if len(b) > maxNTLMString {
			return ""
		}
		for _, c := range b {
			runes = append(runes, rune(c))
		}
	}
	for _, r := range runes {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return ""
		}
	}
	return string(runes)
}
