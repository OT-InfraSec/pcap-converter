// Copyright 2025 GitHub Copilot. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

// TLS record types
const (
	TLSRecordTypeChangeCipherSpec = 20
	TLSRecordTypeAlert            = 21
	TLSRecordTypeHandshake        = 22
	TLSRecordTypeApplicationData  = 23
)

// TLS handshake message types
const (
	TLSHandshakeTypeClientHello        = 1
	TLSHandshakeTypeServerHello        = 2
	TLSHandshakeTypeCertificate        = 11
	TLSHandshakeTypeServerKeyExchange  = 12
	TLSHandshakeTypeCertificateRequest = 13
	TLSHandshakeTypeServerHelloDone    = 14
	TLSHandshakeTypeCertificateVerify  = 15
	TLSHandshakeTypeClientKeyExchange  = 16
	TLSHandshakeTypeFinished           = 20
)

// TLS versions
const (
	TLSVersion10 = 0x0301
	TLSVersion11 = 0x0302
	TLSVersion12 = 0x0303
	TLSVersion13 = 0x0304
)

// TLS extension types
const (
	TLSExtensionServerName = 0
	TLSExtensionALPN       = 16
)

// TLSVersion represents TLS protocol versions
type TLSVersion uint16

func (v TLSVersion) String() string {
	switch v {
	case TLSVersion10:
		return "TLS 1.0"
	case TLSVersion11:
		return "TLS 1.1"
	case TLSVersion12:
		return "TLS 1.2"
	case TLSVersion13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown TLS Version (0x%04x)", uint16(v))
	}
}

// TLSCipherSuite represents TLS cipher suites
type TLSCipherSuite uint16

func (cs TLSCipherSuite) String() string {
	// Common cipher suites mapping
	suites := map[TLSCipherSuite]string{
		0x0004: "TLS_RSA_WITH_RC4_128_MD5",
		0x0005: "TLS_RSA_WITH_RC4_128_SHA",
		0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
		0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
		0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	}

	if name, exists := suites[cs]; exists {
		return name
	}
	return fmt.Sprintf("Unknown Cipher Suite (0x%04x)", uint16(cs))
}

// TLS represents a TLS packet
type TLS struct {
	BaseLayer

	// TLS record fields
	RecordType   uint8      // TLS record type
	Version      TLSVersion // TLS version from record header
	RecordLength uint16     // Length of the record

	// Handshake fields (if applicable)
	HandshakeType   uint8  // Handshake message type
	HandshakeLength uint32 // Length of handshake message

	// Parsed handshake data
	HandshakeVersion TLSVersion       // TLS version from handshake
	CipherSuite      TLSCipherSuite   // Chosen cipher suite (from Server Hello)
	ServerName       string           // Server name from SNI extension
	SupportedCiphers []TLSCipherSuite // Supported cipher suites (from Client Hello)

	// Additional parsed data
	Extensions    map[uint16][]byte // Raw extension data
	IsClientHello bool              // True if this is a Client Hello
	IsServerHello bool              // True if this is a Server Hello

	// Raw handshake data for further analysis
	HandshakeData []byte // Raw handshake message data
}

// LayerType returns the layer type for TLS
func (t *TLS) LayerType() gopacket.LayerType {
	return LayerTypeTLS
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (t *TLS) CanDecode() gopacket.LayerClass {
	return LayerTypeTLS
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (t *TLS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer
func (t *TLS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		return errors.New("TLS record too short")
	}

	t.BaseLayer = BaseLayer{
		Contents: data,
		Payload:  nil,
	}

	// Only parse handshake records for now (minimal, only hello messages)
	t.RecordType = data[0]
	t.Version = TLSVersion(binary.BigEndian.Uint16(data[1:3]))
	t.RecordLength = binary.BigEndian.Uint16(data[3:5])

	if t.RecordType != TLSRecordTypeHandshake {
		return nil // Only interested in handshake
	}

	if len(data) < int(5+t.RecordLength) {
		return errors.New("TLS record length exceeds available data")
	}

	handshakeData := data[5 : 5+t.RecordLength]
	if len(handshakeData) < 4 {
		return errors.New("TLS handshake message too short")
	}
	handshakeType := handshakeData[0]
	handshakeLen := int(handshakeData[1])<<16 | int(handshakeData[2])<<8 | int(handshakeData[3])
	if len(handshakeData) < 4+handshakeLen {
		return errors.New("TLS handshake message length exceeds available data")
	}

	switch handshakeType {
	case TLSHandshakeTypeClientHello:
		t.IsClientHello = true
		return t.parseClientHello(handshakeData[4 : 4+handshakeLen])
	case TLSHandshakeTypeServerHello:
		t.IsServerHello = true
		return t.parseServerHello(handshakeData[4 : 4+handshakeLen])
	case TLSHandshakeTypeFinished:
		return errors.New("TLS handshake aborted or finished before hello exchange")
	default:
		return nil // Ignore other handshake types for minimal implementation
	}
}

// parseHandshake parses TLS handshake messages
func (t *TLS) parseHandshake(data []byte) error {
	if len(data) < 4 {
		return errors.New("handshake message too short")
	}

	t.HandshakeType = data[0]
	t.HandshakeLength = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	if len(data) < int(4+t.HandshakeLength) {
		return errors.New("handshake message length exceeds available data")
	}

	t.HandshakeData = data[4 : 4+t.HandshakeLength]

	switch t.HandshakeType {
	case TLSHandshakeTypeClientHello:
		t.IsClientHello = true
		return t.parseClientHello(t.HandshakeData)
	case TLSHandshakeTypeServerHello:
		t.IsServerHello = true
		return t.parseServerHello(t.HandshakeData)
	}

	return nil
}

// parseClientHello parses Client Hello handshake message
func (t *TLS) parseClientHello(data []byte) error {
	if len(data) < 38 {
		return errors.New("Client Hello too short")
	}

	offset := 0

	// Parse version
	t.HandshakeVersion = TLSVersion(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Skip random (32 bytes)
	offset += 32

	// Parse session ID
	if offset >= len(data) {
		return errors.New("Client Hello truncated at session ID")
	}
	sessionIDLength := int(data[offset])
	offset += 1 + sessionIDLength

	// Parse cipher suites
	if offset+2 > len(data) {
		return errors.New("Client Hello truncated at cipher suites length")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLength > len(data) {
		return errors.New("Client Hello truncated at cipher suites")
	}

	// Extract cipher suites
	for i := 0; i < cipherSuitesLength; i += 2 {
		if offset+i+2 <= len(data) {
			cipher := TLSCipherSuite(binary.BigEndian.Uint16(data[offset+i : offset+i+2]))
			t.SupportedCiphers = append(t.SupportedCiphers, cipher)
		}
	}
	offset += cipherSuitesLength

	// Skip compression methods
	if offset >= len(data) {
		return nil // No extensions
	}
	compressionLength := int(data[offset])
	offset += 1 + compressionLength

	// Parse extensions
	if offset+2 <= len(data) {
		extensionsLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		t.parseExtensions(data[offset : offset+extensionsLength])
	}

	return nil
}

// parseServerHello parses Server Hello handshake message
func (t *TLS) parseServerHello(data []byte) error {
	if len(data) < 38 {
		return errors.New("Server Hello too short")
	}

	offset := 0

	// Parse version
	t.HandshakeVersion = TLSVersion(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Skip random (32 bytes)
	offset += 32

	// Parse session ID
	if offset >= len(data) {
		return errors.New("Server Hello truncated at session ID")
	}
	sessionIDLength := int(data[offset])
	offset += 1 + sessionIDLength

	// Parse chosen cipher suite
	if offset+2 > len(data) {
		return errors.New("Server Hello truncated at cipher suite")
	}
	t.CipherSuite = TLSCipherSuite(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Skip compression method
	offset += 1

	// Parse extensions
	if offset+2 <= len(data) {
		extensionsLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+extensionsLength <= len(data) {
			t.parseExtensions(data[offset : offset+extensionsLength])
		}
	}

	return nil
}

// parseExtensions parses TLS extensions
func (t *TLS) parseExtensions(data []byte) error {
	offset := 0

	for offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extLength > len(data) {
			break
		}

		extData := data[offset : offset+extLength]
		t.Extensions[extType] = extData

		// Parse specific extensions
		switch extType {
		case TLSExtensionServerName:
			t.parseServerNameExtension(extData)
		}

		offset += extLength
	}

	return nil
}

// parseServerNameExtension parses the Server Name Indication extension
func (t *TLS) parseServerNameExtension(data []byte) {
	if len(data) < 5 {
		return
	}

	offset := 0

	// Server name list length
	listLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+listLength > len(data) {
		return
	}

	// Parse server names
	for offset+3 < len(data) && offset < 2+listLength {
		nameType := data[offset]
		nameLength := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3

		if offset+nameLength > len(data) {
			break
		}

		if nameType == 0 { // hostname
			t.ServerName = string(data[offset : offset+nameLength])
			break
		}

		offset += nameLength
	}
}

// GetEffectiveTLSVersion returns the effective TLS version (handshake version takes precedence)
func (t *TLS) GetEffectiveTLSVersion() TLSVersion {
	if t.HandshakeVersion != 0 {
		return t.HandshakeVersion
	}
	return t.Version
}

// IsHandshake returns true if this is a handshake record
func (t *TLS) IsHandshake() bool {
	return t.RecordType == TLSRecordTypeHandshake
}

// IsApplicationData returns true if this is application data
func (t *TLS) IsApplicationData() bool {
	return t.RecordType == TLSRecordTypeApplicationData
}

// Register custom layer type for TLS
var LayerTypeTLS = gopacket.RegisterLayerType(2001, gopacket.LayerTypeMetadata{Name: "TLS", Decoder: gopacket.DecodeFunc(decodeTLS)})

func decodeTLS(data []byte, p gopacket.PacketBuilder) error {
	tls := &TLS{}
	err := tls.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(tls)
	return nil
}
