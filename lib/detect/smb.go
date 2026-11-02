package detect

import "github.com/InfraSecConsult/pcap-importer-go/lib/hostid"

const (
	// SMBPort is SMB over TCP (direct hosting); SMBNetBIOSPort carries SMB
	// behind the NetBIOS session service.
	SMBPort          uint16 = 445
	SMBNetBIOSPort   uint16 = 139
	NBNSPort         uint16 = 137
	nbnsHeaderLength        = 12
)

// ProbeSMB checks a TCP payload for the start of an SMB connection: a session
// message whose payload begins with an SMB 1, SMB 2/3 or encrypted-transform
// protocol id, or a NetBIOS session request with two valid names. The other
// session service frames (positive and negative response, keep-alive) are only
// Incomplete: they carry nothing to tell them from other traffic, so on the SMB
// ports they keep the hint and elsewhere they leave no label.
func ProbeSMB(b []byte) Result {
	if len(b) == 0 {
		return Incomplete
	}
	if len(b) < 4 {
		switch b[0] {
		case hostid.NBSSMessage, hostid.NBSSRequest, hostid.NBSSPositiveResponse, hostid.NBSSNegativeResponse, hostid.NBSSRetarget, hostid.NBSSKeepAlive:
			return Incomplete
		}
		return Unrecognized
	}
	h, ok := hostid.ParseNBSS(b)
	if !ok {
		return Unrecognized
	}
	body := b[4:]
	switch h.Type {
	case hostid.NBSSMessage:
		if len(body) < 4 {
			if len(body) == 0 || body[0] == 0xff || body[0] == 0xfe || body[0] == 0xfd {
				return Incomplete
			}
			return Unrecognized
		}
		if hostid.ClassifySMB(body) == hostid.SMBNone {
			return Unrecognized
		}
		return Recognized
	case hostid.NBSSRequest:
		// Two encoded names (34 bytes each without scope): wait for them.
		if len(body) < 68 && len(body) < h.Length {
			return Incomplete
		}
		if len(body) > h.Length {
			body = body[:h.Length]
		}
		if _, ok := hostid.DecodeSessionRequest(body); ok {
			return Recognized
		}
		return Unrecognized
	}
	return Incomplete
}

// ProbeNBNS checks a UDP payload for a NetBIOS name service message (RFC 1002):
// a valid header (opcode, counts) with at least one question or record, and
// questions and records whose names are well-formed first-level encodings.
func ProbeNBNS(b []byte) Result {
	if len(b) < nbnsHeaderLength {
		return Unrecognized
	}
	if allZero(b[4:nbnsHeaderLength]) { // no question and no record
		return Unrecognized
	}
	if _, ok := hostid.DecodeNBNS(b); !ok {
		return Unrecognized
	}
	return Recognized
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
