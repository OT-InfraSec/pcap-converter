// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MDNS represents a Multicast Domain Name System packet
// mDNS is based on DNS but uses multicast addressing for service discovery
type MDNS struct {
	BaseLayer
	// DNS Header fields
	ID           uint16
	QR           bool   // Query/Response flag
	OpCode       uint8  // Operation code
	AA           bool   // Authoritative Answer
	TC           bool   // Truncated
	RD           bool   // Recursion Desired
	RA           bool   // Recursion Available
	Z            uint8  // Reserved (must be zero)
	ResponseCode uint8  // Response code
	QDCount      uint16 // Number of questions
	ANCount      uint16 // Number of answer RRs
	NSCount      uint16 // Number of authority RRs
	ARCount      uint16 // Number of additional RRs

	// mDNS specific data
	Questions   []MDNSQuestion
	Answers     []MDNSResourceRecord
	Authorities []MDNSResourceRecord
	Additionals []MDNSResourceRecord
}

// MDNSQuestion represents an mDNS query with the UNICAST-RESPONSE bit
type MDNSQuestion struct {
	Name            []byte
	Type            layers.DNSType
	Class           layers.DNSClass
	UnicastResponse bool // mDNS specific: indicates if unicast response is desired
}

// MDNSResourceRecord represents an mDNS resource record with CACHE-FLUSH bit
type MDNSResourceRecord struct {
	Name       []byte
	Type       layers.DNSType
	Class      layers.DNSClass
	CacheFlush bool // mDNS specific: indicates if cached records should be purged
	TTL        uint32
	DataLength uint16
	Data       []byte

	// Parsed data fields (similar to DNS)
	IP             net.IP
	NS, CNAME, PTR []byte
	TXT            [][]byte
	SOA            layers.DNSSOA
	SRV            layers.DNSSRV
	MX             layers.DNSMX
	OPT            []layers.DNSOPT
}

// LayerType returns the layer type for mDNS
func (m *MDNS) LayerType() gopacket.LayerType {
	return LayerTypeMDNS
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (m *MDNS) CanDecode() gopacket.LayerClass {
	return LayerTypeMDNS
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (m *MDNS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer
func (m *MDNS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	_ = df // Suppress unused parameter warning
	if len(data) < 12 {
		return errors.New("mDNS packet too short for header")
	}

	m.BaseLayer = BaseLayer{
		Contents: data,
		Payload:  nil,
	}

	// Parse DNS header
	m.ID = binary.BigEndian.Uint16(data[0:2])

	flags := binary.BigEndian.Uint16(data[2:4])
	m.QR = (flags & 0x8000) != 0
	m.OpCode = uint8((flags >> 11) & 0x0F)
	m.AA = (flags & 0x0400) != 0
	m.TC = (flags & 0x0200) != 0
	m.RD = (flags & 0x0100) != 0
	m.RA = (flags & 0x0080) != 0
	m.Z = uint8((flags >> 4) & 0x07)
	m.ResponseCode = uint8(flags & 0x0F)

	m.QDCount = binary.BigEndian.Uint16(data[4:6])
	m.ANCount = binary.BigEndian.Uint16(data[6:8])
	m.NSCount = binary.BigEndian.Uint16(data[8:10])
	m.ARCount = binary.BigEndian.Uint16(data[10:12])

	offset := 12

	// Parse questions
	m.Questions = make([]MDNSQuestion, m.QDCount)
	for i := 0; i < int(m.QDCount); i++ {
		var err error
		offset, err = m.parseQuestion(data, offset, &m.Questions[i])
		if err != nil {
			return err
		}
	}

	// Parse answers
	m.Answers = make([]MDNSResourceRecord, m.ANCount)
	for i := 0; i < int(m.ANCount); i++ {
		var err error
		offset, err = m.parseResourceRecord(data, offset, &m.Answers[i])
		if err != nil {
			return err
		}
	}

	// Parse authorities
	m.Authorities = make([]MDNSResourceRecord, m.NSCount)
	for i := 0; i < int(m.NSCount); i++ {
		var err error
		offset, err = m.parseResourceRecord(data, offset, &m.Authorities[i])
		if err != nil {
			return err
		}
	}

	// Parse additionals
	m.Additionals = make([]MDNSResourceRecord, m.ARCount)
	for i := 0; i < int(m.ARCount); i++ {
		var err error
		offset, err = m.parseResourceRecord(data, offset, &m.Additionals[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// parseQuestion parses an mDNS question from the packet data
func (m *MDNS) parseQuestion(data []byte, offset int, q *MDNSQuestion) (int, error) {
	var err error

	// Parse name
	q.Name, offset, err = m.parseName(data, offset)
	if err != nil {
		return offset, err
	}

	if len(data) < offset+4 {
		return offset, errors.New("insufficient data for question")
	}

	// Parse type
	q.Type = layers.DNSType(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Parse class with UNICAST-RESPONSE bit
	classAndFlags := binary.BigEndian.Uint16(data[offset : offset+2])
	q.UnicastResponse = (classAndFlags & 0x8000) != 0
	q.Class = layers.DNSClass(classAndFlags & 0x7FFF)
	offset += 2

	return offset, nil
}

// parseResourceRecord parses an mDNS resource record from the packet data
func (m *MDNS) parseResourceRecord(data []byte, offset int, rr *MDNSResourceRecord) (int, error) {
	var err error

	// Parse name
	rr.Name, offset, err = m.parseName(data, offset)
	if err != nil {
		return offset, err
	}

	if len(data) < offset+10 {
		return offset, errors.New("insufficient data for resource record")
	}

	// Parse type
	rr.Type = layers.DNSType(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Parse class with CACHE-FLUSH bit
	classAndFlags := binary.BigEndian.Uint16(data[offset : offset+2])
	rr.CacheFlush = (classAndFlags & 0x8000) != 0
	rr.Class = layers.DNSClass(classAndFlags & 0x7FFF)
	offset += 2

	// Parse TTL
	rr.TTL = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse data length
	rr.DataLength = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(rr.DataLength) {
		return offset, errors.New("insufficient data for resource record data")
	}

	// Parse data
	rr.Data = data[offset : offset+int(rr.DataLength)]

	// Parse specific record types
	err = m.parseRecordData(data, offset, rr)
	if err != nil {
		return offset, err
	}

	offset += int(rr.DataLength)
	return offset, nil
}

// parseRecordData parses the data section of a resource record based on its type
func (m *MDNS) parseRecordData(data []byte, offset int, rr *MDNSResourceRecord) error {
	switch rr.Type {
	case layers.DNSTypeA:
		if rr.DataLength == 4 {
			rr.IP = net.IP(rr.Data)
		}
	case layers.DNSTypeAAAA:
		if rr.DataLength == 16 {
			rr.IP = net.IP(rr.Data)
		}
	case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
		var err error
		rr.CNAME, _, err = m.parseName(data, offset)
		if err != nil {
			return err
		}
		rr.NS = rr.CNAME
		rr.PTR = rr.CNAME
	case layers.DNSTypeTXT:
		rr.TXT = m.parseTXT(rr.Data)
	case layers.DNSTypeSRV:
		if rr.DataLength >= 6 {
			rr.SRV.Priority = binary.BigEndian.Uint16(rr.Data[0:2])
			rr.SRV.Weight = binary.BigEndian.Uint16(rr.Data[2:4])
			rr.SRV.Port = binary.BigEndian.Uint16(rr.Data[4:6])
			if len(rr.Data) > 6 {
				var err error
				rr.SRV.Name, _, err = m.parseName(data, offset+6)
				if err != nil {
					return err
				}
			}
		}
	case layers.DNSTypeMX:
		if rr.DataLength >= 2 {
			rr.MX.Preference = binary.BigEndian.Uint16(rr.Data[0:2])
			if len(rr.Data) > 2 {
				var err error
				rr.MX.Name, _, err = m.parseName(data, offset+2)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// parseName parses a DNS name with compression support
func (m *MDNS) parseName(data []byte, offset int) ([]byte, int, error) {
	var name []byte
	originalOffset := offset
	jumped := false
	jumpCount := 0

	dataLen := len(data)
	for offset < dataLen {
		length := int(data[offset])

		// Check for compression pointer
		if length&0xC0 == 0xC0 {
			if !jumped {
				originalOffset = offset + 2
			}
			if dataLen < offset+2 {
				return nil, offset, errors.New("invalid compression pointer")
			}
			offset = int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			jumped = true
			jumpCount++
			if jumpCount > 10 { // Prevent infinite loops
				return nil, offset, errors.New("too many compression jumps")
			}
			continue
		}

		offset++

		if length == 0 {
			break
		}

		if dataLen < offset+length {
			return nil, offset, errors.New("name extends beyond packet")
		}

		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, data[offset:offset+length]...)
		offset += length
	}

	if jumped {
		return name, originalOffset, nil
	}
	return name, offset, nil
}

// parseTXT parses TXT record data
func (m *MDNS) parseTXT(data []byte) [][]byte {
	var txt [][]byte
	offset := 0

	dataLen := len(data)
	for offset < dataLen {
		length := int(data[offset])
		offset++

		if offset+length > dataLen {
			break
		}

		txt = append(txt, data[offset:offset+length])
		offset += length
	}

	return txt
}

// String returns a string representation of the mDNS packet
func (m *MDNS) String() string {
	if m.QR {
		return fmt.Sprintf("mDNS Response ID:%d Questions:%d Answers:%d", m.ID, m.QDCount, m.ANCount)
	}
	return fmt.Sprintf("mDNS Query ID:%d Questions:%d", m.ID, m.QDCount)
}

// IsQuery returns true if this is an mDNS query
func (m *MDNS) IsQuery() bool {
	return !m.QR
}

// IsResponse returns true if this is an mDNS response
func (m *MDNS) IsResponse() bool {
	return m.QR
}

// IsMulticast returns true if the packet is sent to mDNS multicast addresses
func (m *MDNS) IsMulticast(dstIP net.IP) bool {
	// IPv4 multicast: 224.0.0.251
	if dstIP.Equal(net.IPv4(224, 0, 0, 251)) {
		return true
	}
	// IPv6 multicast: ff02::fb
	if dstIP.Equal(net.ParseIP("ff02::fb")) {
		return true
	}
	return false
}

// GetServiceType extracts service type from PTR queries (e.g., "_http._tcp.local")
func (q *MDNSQuestion) GetServiceType() string {
	name := string(q.Name)
	if strings.HasSuffix(name, ".local") && strings.HasPrefix(name, "_") {
		return name
	}
	return ""
}

// LayerTypeMDNS is the layer type for mDNS packets
var LayerTypeMDNS = gopacket.RegisterLayerType(
	1002, // Layer type number - using a high number to avoid conflicts
	gopacket.LayerTypeMetadata{
		Name:    "MDNS",
		Decoder: gopacket.DecodeFunc(decodeMDNS),
	},
)

// decodeMDNS is the decoder function for mDNS packets
func decodeMDNS(data []byte, p gopacket.PacketBuilder) error {
	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(mdns)
	return p.NextDecoder(mdns.NextLayerType())
}

// RegisterMDNS registers the mDNS protocol with UDP port 5353
func RegisterMDNS() {
	// mDNS uses UDP port 5353
	layers.RegisterUDPPortLayerType(5353, LayerTypeMDNS)
}

// InitLayerMDNS initializes the mDNS layer for gopacket
func InitLayerMDNS() {
	RegisterMDNS()
}
