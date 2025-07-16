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
}

// DecodeFromBytes decodes the slice into the TLSHandshakeRecord struct according to the TLS Handshake Protocol.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = int(h.Length)

	// According to the TLS Handshake Protocol, the handshake message starts with:
	// 1 byte: Handshake Type
	// 3 bytes: Length
	// The rest: Handshake message body
	if len(data) < 4 {
		return errors.New("TLS Handshake record too short")
	}

	t.Type = data[0]
	t.Length = int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	t.Body = data[4:]

	return nil
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
