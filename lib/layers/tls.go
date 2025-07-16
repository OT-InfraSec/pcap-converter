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

// TLSType defines the type of data after the TLS Record
type TLSType uint8

// TLSType known values.
const (
	TLSChangeCipherSpec TLSType = 20
	TLSAlert            TLSType = 21
	TLSHandshake        TLSType = 22
	TLSApplicationData  TLSType = 23
	TLSUnknown          TLSType = 255
)

// String shows the register type nicely formatted
func (tt TLSType) String() string {
	switch tt {
	default:
		return "Unknown"
	case TLSChangeCipherSpec:
		return "Change Cipher Spec"
	case TLSAlert:
		return "Alert"
	case TLSHandshake:
		return "Handshake"
	case TLSApplicationData:
		return "Application Data"
	}
}

// TLSVersion represents the TLS version in numeric format
type TLSVersion uint16

// Strings shows the TLS version nicely formatted
func (tv TLSVersion) String() string {
	switch tv {
	default:
		return "Unknown"
	case 0x0200:
		return "SSL 2.0"
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
}

// TLS is specified in RFC 5246
//
//  TLS Record Protocol
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |     Content Type      |
//  +--+--+--+--+--+--+--+--+
//  |    Version (major)    |
//  +--+--+--+--+--+--+--+--+
//  |    Version (minor)    |
//  +--+--+--+--+--+--+--+--+
//  |        Length         |
//  +--+--+--+--+--+--+--+--+
//  |        Length         |
//  +--+--+--+--+--+--+--+--+

// TLS is actually a slide of TLSrecord structures
type TLS struct {
	BaseLayer

	// TLS Records
	ChangeCipherSpec []TLSChangeCipherSpecRecord
	Handshake        []TLSHandshakeRecord
	AppData          []TLSAppDataRecord
	Alert            []TLSAlertRecord
}

// TLSRecordHeader contains all the information that each TLS Record types should have
type TLSRecordHeader struct {
	ContentType TLSType
	Version     TLSVersion
	Length      uint16
}

// LayerType returns gopacket.LayerTypeTLS.
func (t *TLS) LayerType() gopacket.LayerType { return LayerTypeTLS }

// decodeTLS decodes the byte slice into a TLS type. It also
// setups the application Layer in PacketBuilder.
func decodeTLS(data []byte, p gopacket.PacketBuilder) error {
	t := &TLS{}
	err := t.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(t)
	p.SetApplicationLayer(t)
	return nil
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	t.BaseLayer.Contents = data
	t.BaseLayer.Payload = nil

	t.ChangeCipherSpec = t.ChangeCipherSpec[:0]
	t.Handshake = t.Handshake[:0]
	t.AppData = t.AppData[:0]
	t.Alert = t.Alert[:0]

	return t.decodeTLSRecords(data, df)
}

func (t *TLS) decodeTLSRecords(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		return errors.New("TLS record too short")
	}

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	// TODO: Consider removing this
	t.BaseLayer = BaseLayer{Contents: data[:len(data)]}

	var h TLSRecordHeader
	h.ContentType = TLSType(data[0])
	h.Version = TLSVersion(binary.BigEndian.Uint16(data[1:3]))
	h.Length = binary.BigEndian.Uint16(data[3:5])

	if h.ContentType.String() == "Unknown" {
		return errors.New("Unknown TLS record type")
	}

	hl := 5 // header length
	tl := hl + int(h.Length)
	if len(data) < tl {
		return errors.New("TLS packet length mismatch")
	}

	switch h.ContentType {
	default:
		return errors.New("Unknown TLS record type")
	case TLSChangeCipherSpec:
		var r TLSChangeCipherSpecRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.ChangeCipherSpec = append(t.ChangeCipherSpec, r)
	case TLSAlert:
		var r TLSAlertRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.Alert = append(t.Alert, r)
	case TLSHandshake:
		var r TLSHandshakeRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.Handshake = append(t.Handshake, r)
	case TLSApplicationData:
		var r TLSAppDataRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.AppData = append(t.AppData, r)
	}

	if len(data) == tl {
		return nil
	}
	return t.decodeTLSRecords(data[tl:len(data)], df)
}

// CanDecode implements gopacket.DecodingLayer.
func (t *TLS) CanDecode() gopacket.LayerClass {
	return LayerTypeTLS
}

// NextLayerType implements gopacket.DecodingLayer.
func (t *TLS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload returns nil, since TLS encrypted payload is inside TLSAppDataRecord
func (t *TLS) Payload() []byte {
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (t *TLS) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	totalLength := 0
	for _, record := range t.ChangeCipherSpec {
		if opts.FixLengths {
			record.Length = 1
		}
		totalLength += 5 + 1 // length of header + record
	}
	for range t.Handshake {
		totalLength += 5
		// TODO
	}
	for _, record := range t.AppData {
		if opts.FixLengths {
			record.Length = uint16(len(record.Payload))
		}
		totalLength += 5 + len(record.Payload)
	}
	for _, record := range t.Alert {
		if len(record.EncryptedMsg) == 0 {
			if opts.FixLengths {
				record.Length = 2
			}
			totalLength += 5 + 2
		} else {
			if opts.FixLengths {
				record.Length = uint16(len(record.EncryptedMsg))
			}
			totalLength += 5 + len(record.EncryptedMsg)
		}
	}
	data, err := b.PrependBytes(totalLength)
	if err != nil {
		return err
	}
	off := 0
	for _, record := range t.ChangeCipherSpec {
		off = encodeHeader(record.TLSRecordHeader, data, off)
		data[off] = byte(record.Message)
		off++
	}
	for _, record := range t.Handshake {
		off = encodeHeader(record.TLSRecordHeader, data, off)
		// TODO
	}
	for _, record := range t.AppData {
		off = encodeHeader(record.TLSRecordHeader, data, off)
		copy(data[off:], record.Payload)
		off += len(record.Payload)
	}
	for _, record := range t.Alert {
		off = encodeHeader(record.TLSRecordHeader, data, off)
		if len(record.EncryptedMsg) == 0 {
			data[off] = byte(record.Level)
			data[off+1] = byte(record.Description)
			off += 2
		} else {
			copy(data[off:], record.EncryptedMsg)
			off += len(record.EncryptedMsg)
		}
	}
	return nil
}

func encodeHeader(header TLSRecordHeader, data []byte, offset int) int {
	data[offset] = byte(header.ContentType)
	binary.BigEndian.PutUint16(data[offset+1:], uint16(header.Version))
	binary.BigEndian.PutUint16(data[offset+3:], header.Length)

	return offset + 5
}

// Register custom layer type for TLS
var LayerTypeTLS = gopacket.RegisterLayerType(2004, gopacket.LayerTypeMetadata{Name: "TLS", Decoder: gopacket.DecodeFunc(decodeTLS)})

// TLSchangeCipherSpec defines the message value inside ChangeCipherSpec Record
type TLSchangeCipherSpec uint8

const (
	TLSChangecipherspecMessage TLSchangeCipherSpec = 1
	TLSChangecipherspecUnknown TLSchangeCipherSpec = 255
)

//  TLS Change Cipher Spec
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |        Message        |
//  +--+--+--+--+--+--+--+--+

// TLSChangeCipherSpecRecord defines the type of data inside ChangeCipherSpec Record
type TLSChangeCipherSpecRecord struct {
	TLSRecordHeader

	Message TLSchangeCipherSpec
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSChangeCipherSpecRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) != 1 {
		return errors.New("TLS Change Cipher Spec record incorrect length")
	}

	t.Message = TLSchangeCipherSpec(data[0])
	if t.Message != TLSChangecipherspecMessage {
		t.Message = TLSChangecipherspecUnknown
	}

	return nil
}

// String shows the message value nicely formatted
func (ccs TLSchangeCipherSpec) String() string {
	switch ccs {
	default:
		return "Unknown"
	case TLSChangecipherspecMessage:
		return "Change Cipher Spec Message"
	}
}

const (
	TLSHandshakeTypeHelloRequest        uint8 = 0
	TLSHandshakeTypeClientHello         uint8 = 1
	TLSHandshakeTypeServerHello         uint8 = 2
	TLSHandshakeTypeHelloVerifyRequest  uint8 = 3
	TLSHandshakeTypeNewSessionTicket    uint8 = 4
	TLSHandshakeTypeEndOfEarlyData      uint8 = 5
	TLSHandshakeTypeHelloRetryRequest   uint8 = 6
	TLSHandshakeTypeEncryptedExtensions uint8 = 8
	TLSHandshakeTypeCertificate         uint8 = 11
	TLSHandshakeTypeServerKeyExchange   uint8 = 12
	TLSHandshakeTypeCertificateRequest  uint8 = 13
	TLSHandshakeTypeServerHelloDone     uint8 = 14
	TLSHandshakeTypeCertificateVerify   uint8 = 15
	TLSHandshakeTypeClientKeyExchange   uint8 = 16
	TLSHandshakeTypeFinished            uint8 = 20
	TLSHandshakeTypeCertificateURL      uint8 = 21
	TLSHandshakeTypeCertificateStatus   uint8 = 22
	TLSHandshakeTypeSupplementalData    uint8 = 23
)

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader

	Type   uint8
	Length int
	Body   []byte

	ClientHello *TLSClientHello
	ServerHello *TLSServerHello
}

// DecodeFromBytes decodes the slice into the TLSHandshakeRecord struct according to the TLS Handshake Protocol.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = int(h.Length)

	if len(data) < 4 {
		return errors.New("TLS Handshake record too short")
	}

	t.Type = data[0]
	t.Length = int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	t.Body = data[4:]

	// Parse ClientHello
	if t.Type == TLSHandshakeTypeClientHello {
		if len(t.Body) < 34 {
			return errors.New("TLS ClientHello too short")
		}
		ch := &TLSClientHello{}
		ch.Version = TLSVersion(binary.BigEndian.Uint16(t.Body[:2]))
		copy(ch.Random[:], t.Body[2:34])
		sidLen := int(t.Body[34])
		if len(t.Body) < 35+sidLen+2 {
			return errors.New("TLS ClientHello session id too short")
		}
		ch.SessionID = t.Body[35 : 35+sidLen]
		pos := 35 + sidLen
		csLen := int(binary.BigEndian.Uint16(t.Body[pos : pos+2]))
		pos += 2
		if len(t.Body) < pos+csLen+1 {
			return errors.New("TLS ClientHello cipher suites too short")
		}
		ch.CipherSuites = make([]uint16, csLen/2)
		for i := 0; i < csLen; i += 2 {
			ch.CipherSuites[i/2] = binary.BigEndian.Uint16(t.Body[pos+i : pos+i+2])
		}
		pos += csLen
		cmLen := int(t.Body[pos])
		pos++
		if len(t.Body) < pos+cmLen {
			return errors.New("TLS ClientHello compression methods too short")
		}
		ch.CompressionMethods = t.Body[pos : pos+cmLen]
		pos += cmLen
		if len(t.Body) > pos+1 {
			exts, sni, alpn := parseTLSExtensions(t.Body[pos:])
			ch.Extensions = exts
			ch.SNI = sni
			ch.ALPN = alpn
		}
		t.ClientHello = ch
	}
	// Parse ServerHello
	if t.Type == TLSHandshakeTypeServerHello {
		if len(t.Body) < 34 {
			return errors.New("TLS ServerHello too short")
		}
		sh := &TLSServerHello{}
		sh.Version = TLSVersion(binary.BigEndian.Uint16(t.Body[:2]))
		copy(sh.Random[:], t.Body[2:34])
		sidLen := int(t.Body[34])
		if len(t.Body) < 35+sidLen+3 {
			return errors.New("TLS ServerHello session id too short")
		}
		sh.SessionID = t.Body[35 : 35+sidLen]
		pos := 35 + sidLen
		sh.CipherSuite = binary.BigEndian.Uint16(t.Body[pos : pos+2])
		pos += 2
		sh.CompressionMethod = t.Body[pos]
		pos++
		if len(t.Body) > pos+1 {
			exts, sni, alpn := parseTLSExtensions(t.Body[pos:])
			sh.Extensions = exts
			sh.SNI = sni
			sh.ALPN = alpn
		}
		t.ServerHello = sh
	}
	return nil
}

// TLSClientHello is the structure of a Client Hello message in the TLS handshake
type TLSClientHello struct {
	Version            TLSVersion
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []TLSExtension
	SNI                *TLSExtensionSNI
	ALPN               *TLSExtensionALPN
}

// TLSServerHello is the structure of a Server Hello message in the TLS handshake
type TLSServerHello struct {
	Version           TLSVersion
	Random            [32]byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        []TLSExtension
	SNI               *TLSExtensionSNI
	ALPN              *TLSExtensionALPN
}

// TLSExtension represents a generic TLS extension
type TLSExtension struct {
	Type uint16
	Data []byte
}

// TLSExtensionSNI represents the Server Name Indication (SNI) extension
type TLSExtensionSNI struct {
	ServerNames []string
}

// TLSExtensionALPN represents the Application-Layer Protocol Negotiation (ALPN) extension
type TLSExtensionALPN struct {
	Protocols []string
}

// TLSExtensionSupportedCiphers represents a custom extension for supported ciphers
type TLSExtensionSupportedCiphers struct {
	CipherSuites []uint16
}

// --- Extension Types ---
const (
	TLSExtensionTypeServerName       uint16 = 0
	TLSExtensionTypeALPN             uint16 = 16
	TLSExtensionTypeSupportedGroups  uint16 = 10
	TLSExtensionTypeSupportedCiphers uint16 = 0x000a // not a real extension, for internal use
)

// --- Extension Parsing Helpers ---
func parseTLSExtensions(data []byte) (exts []TLSExtension, sni *TLSExtensionSNI, alpn *TLSExtensionALPN) {
	exts = []TLSExtension{}
	var sniExt *TLSExtensionSNI
	var alpnExt *TLSExtensionALPN
	if len(data) < 2 {
		return
	}
	extLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+extLen {
		return
	}
	pos := 2
	for pos+4 <= 2+extLen {
		typeVal := binary.BigEndian.Uint16(data[pos : pos+2])
		length := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if pos+4+length > 2+extLen {
			break
		}
		body := data[pos+4 : pos+4+length]
		exts = append(exts, TLSExtension{Type: typeVal, Data: body})
		// SNI
		if typeVal == TLSExtensionTypeServerName {
			if len(body) >= 5 {
				sniListLen := int(binary.BigEndian.Uint16(body[:2]))
				if len(body) >= 2+sniListLen {
					var names []string
					off := 2
					for off+3 <= 2+sniListLen {
						typeName := body[off]
						nameLen := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
						if typeName == 0 && off+3+nameLen <= 2+sniListLen {
							name := string(body[off+3 : off+3+nameLen])
							names = append(names, name)
						}
						off += 3 + nameLen
					}
					sniExt = &TLSExtensionSNI{ServerNames: names}
				}
			}
		}
		// ALPN
		if typeVal == TLSExtensionTypeALPN {
			if len(body) >= 2 {
				alpnLen := int(binary.BigEndian.Uint16(body[:2]))
				if len(body) >= 2+alpnLen {
					var protos []string
					off := 2
					for off < 2+alpnLen {
						llen := int(body[off])
						off++
						if off+llen <= 2+alpnLen {
							protos = append(protos, string(body[off:off+llen]))
						}
						off += llen
					}
					alpnExt = &TLSExtensionALPN{Protocols: protos}
				}
			}
		}
		pos += 4 + length
	}
	return exts, sniExt, alpnExt
}

// TLSAppDataRecord contains all the information that each AppData Record types should have
type TLSAppDataRecord struct {
	TLSRecordHeader
	Payload []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSAppDataRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) != int(t.Length) {
		return errors.New("TLS Application Data length mismatch")
	}

	t.Payload = data
	return nil
}

// TLSAlertLevel defines the alert level data type
type TLSAlertLevel uint8

// TLSAlertDescr defines the alert descrption data type
type TLSAlertDescr uint8

const (
	TLSAlertWarning      TLSAlertLevel = 1
	TLSAlertFatal        TLSAlertLevel = 2
	TLSAlertUnknownLevel TLSAlertLevel = 255

	TLSAlertCloseNotify               TLSAlertDescr = 0
	TLSAlertUnexpectedMessage         TLSAlertDescr = 10
	TLSAlertBadRecordMac              TLSAlertDescr = 20
	TLSAlertDecryptionFailedRESERVED  TLSAlertDescr = 21
	TLSAlertRecordOverflow            TLSAlertDescr = 22
	TLSAlertDecompressionFailure      TLSAlertDescr = 30
	TLSAlertHandshakeFailure          TLSAlertDescr = 40
	TLSAlertNoCertificateRESERVED     TLSAlertDescr = 41
	TLSAlertBadCertificate            TLSAlertDescr = 42
	TLSAlertUnsupportedCertificate    TLSAlertDescr = 43
	TLSAlertCertificateRevoked        TLSAlertDescr = 44
	TLSAlertCertificateExpired        TLSAlertDescr = 45
	TLSAlertCertificateUnknown        TLSAlertDescr = 46
	TLSAlertIllegalParameter          TLSAlertDescr = 47
	TLSAlertUnknownCa                 TLSAlertDescr = 48
	TLSAlertAccessDenied              TLSAlertDescr = 49
	TLSAlertDecodeError               TLSAlertDescr = 50
	TLSAlertDecryptError              TLSAlertDescr = 51
	TLSAlertExportRestrictionRESERVED TLSAlertDescr = 60
	TLSAlertProtocolVersion           TLSAlertDescr = 70
	TLSAlertInsufficientSecurity      TLSAlertDescr = 71
	TLSAlertInternalError             TLSAlertDescr = 80
	TLSAlertUserCanceled              TLSAlertDescr = 90
	TLSAlertNoRenegotiation           TLSAlertDescr = 100
	TLSAlertUnsupportedExtension      TLSAlertDescr = 110
	TLSAlertUnknownDescription        TLSAlertDescr = 255
)

//  TLS Alert
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |         Level         |
//  +--+--+--+--+--+--+--+--+
//  |      Description      |
//  +--+--+--+--+--+--+--+--+

// TLSAlertRecord contains all the information that each Alert Record type should have
type TLSAlertRecord struct {
	TLSRecordHeader

	Level       TLSAlertLevel
	Description TLSAlertDescr

	EncryptedMsg []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSAlertRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) < 2 {
		return errors.New("TLS Alert packet too short")
	}

	if t.Length == 2 {
		t.Level = TLSAlertLevel(data[0])
		t.Description = TLSAlertDescr(data[1])
	} else {
		t.Level = TLSAlertUnknownLevel
		t.Description = TLSAlertUnknownDescription
		t.EncryptedMsg = data
	}

	return nil
}

// Strings shows the TLS alert level nicely formatted
func (al TLSAlertLevel) String() string {
	switch al {
	default:
		return fmt.Sprintf("Unknown(%d)", al)
	case TLSAlertWarning:
		return "Warning"
	case TLSAlertFatal:
		return "Fatal"
	}
}

// Strings shows the TLS alert description nicely formatted
func (ad TLSAlertDescr) String() string {
	switch ad {
	default:
		return "Unknown"
	case TLSAlertCloseNotify:
		return "close_notify"
	case TLSAlertUnexpectedMessage:
		return "unexpected_message"
	case TLSAlertBadRecordMac:
		return "bad_record_mac"
	case TLSAlertDecryptionFailedRESERVED:
		return "decryption_failed_RESERVED"
	case TLSAlertRecordOverflow:
		return "record_overflow"
	case TLSAlertDecompressionFailure:
		return "decompression_failure"
	case TLSAlertHandshakeFailure:
		return "handshake_failure"
	case TLSAlertNoCertificateRESERVED:
		return "no_certificate_RESERVED"
	case TLSAlertBadCertificate:
		return "bad_certificate"
	case TLSAlertUnsupportedCertificate:
		return "unsupported_certificate"
	case TLSAlertCertificateRevoked:
		return "certificate_revoked"
	case TLSAlertCertificateExpired:
		return "certificate_expired"
	case TLSAlertCertificateUnknown:
		return "certificate_unknown"
	case TLSAlertIllegalParameter:
		return "illegal_parameter"
	case TLSAlertUnknownCa:
		return "unknown_ca"
	case TLSAlertAccessDenied:
		return "access_denied"
	case TLSAlertDecodeError:
		return "decode_error"
	case TLSAlertDecryptError:
		return "decrypt_error"
	case TLSAlertExportRestrictionRESERVED:
		return "export_restriction_RESERVED"
	case TLSAlertProtocolVersion:
		return "protocol_version"
	case TLSAlertInsufficientSecurity:
		return "insufficient_security"
	case TLSAlertInternalError:
		return "internal_error"
	case TLSAlertUserCanceled:
		return "user_canceled"
	case TLSAlertNoRenegotiation:
		return "no_renegotiation"
	case TLSAlertUnsupportedExtension:
		return "unsupported_extension"
	}
}
