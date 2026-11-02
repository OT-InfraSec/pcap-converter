// Package hostid decodes the parts of Windows and NetBIOS networking that
// identify a host: the NetBIOS name service (RFC 1001/1002), NTLMSSP messages
// (MS-NLMP) and the SMB negotiation (MS-SMB2, MS-SMB, RFC 1002 session service).
//
// Everything here is pure and treats its input as hostile: every length and
// offset is checked, strings are bounded, and malformed input yields no result
// instead of an error or a panic.
package hostid

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// NBNS opcodes (RFC 1002 4.2.1.1).
const (
	nbnsOpQuery        = 0
	nbnsOpRegistration = 5
	nbnsOpRelease      = 6
	nbnsOpWACK         = 7
	nbnsOpRefresh      = 8
)

// NBNS record types.
const (
	nbnsTypeNB     = 0x0020
	nbnsTypeNBSTAT = 0x0021
)

const (
	nbnsHeaderLen = 12
	maxNBNSNames  = 64 // names kept per message; a node status holds at most 255
)

// Name suffixes (the 16th byte of a NetBIOS name) that identify a role.
const (
	SuffixWorkstation   = 0x00 // unique: the computer name; group: the workgroup or domain
	SuffixMessenger     = 0x03
	SuffixServer        = 0x20 // file server service
	SuffixDomainMaster  = 0x1B // unique: domain master browser (the PDC emulator)
	SuffixDomainControl = 0x1C // group: domain controllers
	SuffixMasterBrowser = 0x1D
	SuffixBrowserElect  = 0x1E
)

// NBName is one NetBIOS name with its suffix and group flag.
type NBName struct {
	Name   string // the 15 characters, trailing spaces removed
	Suffix byte
	Group  bool
	IP     string // the address that holds the name, when the message carries one
}

// NBNSMessage is what an NBNS packet says about hosts.
type NBNSMessage struct {
	// Names are names bound to addresses: answers to a name query,
	// registrations and refreshes (RFC 1002 4.2.2, 4.2.3, 4.2.4).
	Names []NBName
	// Node status (NBSTAT response): all names of one host and its adapter MAC.
	Status    []NBName
	StatusMAC string
}

// DecodeNBNS decodes a NetBIOS name service message (UDP 137). ok is false
// when it is not a well-formed NBNS message. Queries carry no binding and
// yield an empty message (ok stays true so the packet can still be labelled).
func DecodeNBNS(b []byte) (NBNSMessage, bool) {
	var m NBNSMessage
	if len(b) < nbnsHeaderLen {
		return m, false
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	response := flags&0x8000 != 0
	opcode := int(flags >> 11 & 0x0f)
	if opcode != nbnsOpQuery && opcode != nbnsOpRegistration && opcode != nbnsOpRelease && opcode != nbnsOpWACK && opcode != nbnsOpRefresh {
		return m, false
	}
	qd, an := int(binary.BigEndian.Uint16(b[4:6])), int(binary.BigEndian.Uint16(b[6:8]))
	ns, ar := int(binary.BigEndian.Uint16(b[8:10])), int(binary.BigEndian.Uint16(b[10:12]))
	if qd > 1 || an+ns+ar > 16 { // RFC 1002 messages carry at most one question and a few records
		return m, false
	}

	off := nbnsHeaderLen
	for i := 0; i < qd; i++ {
		_, n, ok := decodeNBName(b, off)
		if !ok || off+n+4 > len(b) {
			return m, false
		}
		off += n + 4 // type and class
	}
	for i := 0; i < an+ns+ar; i++ {
		name, n, ok := decodeNBName(b, off)
		if !ok || off+n+10 > len(b) {
			return m, false
		}
		typ := binary.BigEndian.Uint16(b[off+n : off+n+2])
		rdlen := int(binary.BigEndian.Uint16(b[off+n+8 : off+n+10]))
		start := off + n + 10
		if start+rdlen > len(b) {
			return m, false
		}
		rdata := b[start : start+rdlen]
		off = start + rdlen

		switch typ {
		case nbnsTypeNB:
			// Bindings: answers of a response, or the additional record of a
			// registration or refresh. A release names an address giving a name up.
			bindsName := (response && opcode == nbnsOpQuery) || (!response && (opcode == nbnsOpRegistration || opcode == nbnsOpRefresh))
			if !bindsName {
				continue
			}
			for p := 0; p+6 <= len(rdata) && len(m.Names) < maxNBNSNames; p += 6 {
				nf := binary.BigEndian.Uint16(rdata[p : p+2])
				ip := net.IP(rdata[p+2 : p+6])
				if ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
					continue
				}
				n := name
				n.Group, n.IP = nf&0x8000 != 0, ip.String()
				m.Names = append(m.Names, n)
			}
		case nbnsTypeNBSTAT:
			if response && opcode == nbnsOpQuery {
				m.Status, m.StatusMAC = decodeNodeStatus(rdata)
			}
		}
	}
	return m, true
}

// decodeNodeStatus decodes the RDATA of an NBSTAT answer (RFC 1002 4.2.18):
// the number of names, each 15 name bytes, a suffix and 2 flag bytes, then the
// statistics, which start with the 6-byte unit ID (the adapter's MAC).
func decodeNodeStatus(r []byte) ([]NBName, string) {
	if len(r) < 1 {
		return nil, ""
	}
	n := int(r[0])
	r = r[1:]
	var names []NBName
	for i := 0; i < n && len(r) >= 18 && len(names) < maxNBNSNames; i++ {
		name, ok := cleanNBString(r[:15])
		if ok {
			flags := binary.BigEndian.Uint16(r[16:18])
			names = append(names, NBName{Name: name, Suffix: r[15], Group: flags&0x8000 != 0})
		}
		r = r[18:]
	}
	mac := ""
	if len(r) >= 6 {
		id := r[:6]
		if !allZero(id) { // many stacks (and Samba on some platforms) report 00:00:00:00:00:00
			mac = net.HardwareAddr(id).String()
		}
	}
	return names, mac
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// decodeNBName decodes a first-level-encoded NetBIOS name at off (RFC 1001
// 14.1): a length byte 0x20, 32 characters 'A'..'P' (two per byte), then scope
// labels and a zero byte. A compression pointer (0xC0 00 pair, RFC 1002 4.2.1.4)
// to an earlier name is followed once. n is the number of bytes the name takes
// at off.
func decodeNBName(b []byte, off int) (NBName, int, bool) {
	var zero NBName
	if off >= len(b) {
		return zero, 0, false
	}
	if b[off]&0xc0 == 0xc0 {
		if off+2 > len(b) {
			return zero, 0, false
		}
		ptr := int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
		if ptr >= off { // only backward pointers: no loops
			return zero, 0, false
		}
		name, _, ok := decodeNBNameAt(b, ptr)
		return name, 2, ok
	}
	name, n, ok := decodeNBNameAt(b, off)
	return name, n, ok
}

func decodeNBNameAt(b []byte, off int) (NBName, int, bool) {
	var zero NBName
	if off+34 > len(b) || b[off] != 0x20 {
		return zero, 0, false
	}
	var raw [16]byte
	for i := 0; i < 16; i++ {
		hi, lo := b[off+1+2*i], b[off+2+2*i]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return zero, 0, false
		}
		raw[i] = (hi-'A')<<4 | (lo - 'A')
	}
	pos := off + 33
	// Scope labels (a DNS-like domain) up to the terminating zero.
	for {
		if pos >= len(b) {
			return zero, 0, false
		}
		l := int(b[pos])
		if l == 0 {
			pos++
			break
		}
		if l > 63 || pos+1+l > len(b) {
			return zero, 0, false
		}
		pos += 1 + l
	}
	name, ok := cleanNBString(raw[:15])
	if !ok {
		return zero, 0, false
	}
	return NBName{Name: name, Suffix: raw[15]}, pos - off, true
}

// cleanNBString trims the padding of a NetBIOS name and accepts printable
// ASCII only (a wildcard name "*" followed by NULs is allowed and trimmed).
func cleanNBString(b []byte) (string, bool) {
	s := strings.TrimRight(string(b), " \x00")
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return "", false
		}
	}
	return s, true
}

// String is the usual notation, NAME<xx>, with a G for group names.
func (n NBName) String() string {
	g := ""
	if n.Group {
		g = " G"
	}
	return fmt.Sprintf("%s<%02x>%s", n.Name, n.Suffix, g)
}
