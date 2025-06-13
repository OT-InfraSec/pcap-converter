// filepath: /Users/patrick/gitRepos/pcap-importer-go/lib/layers/eigrp.go
package lib_layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EIGRP protocol constants
const (
	// EIGRP Opcodes
	EIGRPOpcodeUpdate    = 1
	EIGRPOpcodeRequest   = 2
	EIGRPOpcodeQuery     = 3
	EIGRPOpcodeReply     = 4
	EIGRPOpcodeHello     = 5
	EIGRPOpcodeIPXSAPReq = 6
	EIGRPOpcodeProbe     = 7
	EIGRPOpcodeAck       = 8
	EIGRPOpcodeSIAQuery  = 10
	EIGRPOpcodeSIAReply  = 11

	// EIGRP TLV Types
	EIGRPTLVTypeParameters      = 0x0001
	EIGRPTLVTypeAuthentication  = 0x0002
	EIGRPTLVTypeSequence        = 0x0003
	EIGRPTLVTypeSoftware        = 0x0004
	EIGRPTLVTypeMulticast       = 0x05
	EIGRPTLVTypePeerInformation = 0x06
	EIGRPTLVTypePeerTermination = 0x7
	EIGRPTLVTypePeerTIDList     = 0x08
	EIGRPTLVTypeInternal        = 0x0102
	EIGRPTLVTypeExternal        = 0x0103
	EIGRPTLVTypeIPv6External    = 0x0403
	EIGRPTLVTypeIPv6Internal    = 0x0402

	// EIGRP Protocol Number
	EIGRPProtocolNumber = 88

	// EIGRP Flags
	EIGRPFlagInit = 0x01
	EIGRPFlagCR   = 0x02
	EIGRPFlagRS   = 0x04
	EIGRPFlagEOT  = 0x08

	// EIGRP Types
	EIGRPTypeGeneral       = 0
	EIGRPTypeIPv4          = 1
	EIGRPTypeIPv6          = 4
	EIGRPTypeSAF           = 5
	EIGRPTypeMultiprotocol = 6
)

var (
	// LayerTypeEIGRP is the registered layer type for EIGRP
	LayerTypeEIGRP = gopacket.RegisterLayerType(
		2001, // Using a unique number that's unlikely to conflict
		gopacket.LayerTypeMetadata{
			Name:    "EIGRP",
			Decoder: gopacket.DecodeFunc(decodeEIGRP),
		},
	)

	// Map opcodes to strings for better debugging
	eigrpOpcodeNames = map[uint8]string{
		EIGRPOpcodeUpdate:    "Update",
		EIGRPOpcodeQuery:     "Query",
		EIGRPOpcodeReply:     "Reply",
		EIGRPOpcodeHello:     "Hello",
		EIGRPOpcodeIPXSAPReq: "IPXSAPReq",
		EIGRPOpcodeSIAQuery:  "SIAQuery",
		EIGRPOpcodeSIAReply:  "SIAReply",
	}

	// Map TLV types to strings
	eigrpTLVTypeNames = map[uint16]string{
		EIGRPTLVTypeParameters:   "Parameters",
		EIGRPTLVTypeSoftware:     "Software",
		EIGRPTLVTypeMulticast:    "Multicast",
		EIGRPTLVTypeInternal:     "Internal",
		EIGRPTLVTypeExternal:     "External",
		EIGRPTLVTypeIPv6External: "IPExternal",
		EIGRPTLVTypeIPv6Internal: "IPInternal",
	}
)

// EIGRP represents an Enhanced Interior Gateway Routing Protocol packet.
type EIGRP struct {
	BaseLayer
	Version         uint8
	Opcode          uint8
	Checksum        uint16
	Flags           uint32
	Sequence        uint32
	Ack             uint32
	AS              uint32
	VirtualRouterID uint32
	Parameters      map[string]interface{}
	TLVs            []EIGRPTLV
}

// EIGRPTLV represents a Type-Length-Value structure in EIGRP
type EIGRPTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// LayerType returns LayerTypeEIGRP
func (e *EIGRP) LayerType() gopacket.LayerType { return LayerTypeEIGRP }

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (e *EIGRP) CanDecode() gopacket.LayerClass {
	return LayerTypeEIGRP
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (e *EIGRP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer
func (e *EIGRP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 { // Minimum EIGRP header size
		df.SetTruncated()
		return errors.New("EIGRP packet too short")
	}

	e.Version = data[0]
	e.Opcode = data[1]
	e.Checksum = binary.BigEndian.Uint16(data[2:4])
	e.Flags = binary.BigEndian.Uint32(data[4:8])
	e.Sequence = binary.BigEndian.Uint32(data[8:12])
	e.Ack = binary.BigEndian.Uint32(data[12:16])
	e.AS = binary.BigEndian.Uint32(data[16:20])

	headerLen := 20 // Default header size

	// Some EIGRP implementations use Virtual Router ID (extended header)
	if len(data) >= 24 && (e.Flags&0x00000001) != 0 {
		e.VirtualRouterID = binary.BigEndian.Uint32(data[20:24])
		headerLen = 24
	} else {
		e.VirtualRouterID = 0
	}

	e.BaseLayer = BaseLayer{data[:headerLen], data[headerLen:]}

	// Initialize Parameters map
	e.Parameters = make(map[string]interface{})

	// Parse TLVs from the payload
	offset := headerLen
	e.TLVs = []EIGRPTLV{}

	for offset+4 <= len(data) {
		if offset+4 > len(data) {
			break
		}

		tlvType := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvLength := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if tlvLength < 4 || offset+int(tlvLength) > len(data) {
			break // Invalid TLV or we've reached the end of the packet
		}

		tlvValue := data[offset+4 : offset+int(tlvLength)]

		tlv := EIGRPTLV{
			Type:   tlvType,
			Length: tlvLength,
			Value:  make([]byte, len(tlvValue)),
		}
		copy(tlv.Value, tlvValue)
		e.TLVs = append(e.TLVs, tlv)

		// Parse specific TLV types
		if tlvType == EIGRPTLVTypeParameters && len(tlvValue) >= 12 {
			e.Parameters["K1"] = tlvValue[0]
			e.Parameters["K2"] = tlvValue[1]
			e.Parameters["K3"] = tlvValue[2]
			e.Parameters["K4"] = tlvValue[3]
			e.Parameters["K5"] = tlvValue[4]
			// Some implementations also include K6
			if len(tlvValue) > 5 {
				e.Parameters["K6"] = tlvValue[5]
			}
			// Hold time is typically at bytes 10-11
			if len(tlvValue) >= 12 {
				e.Parameters["holdTime"] = binary.BigEndian.Uint16(tlvValue[10:12])
			}
		}

		// Move to the next TLV
		offset += int(tlvLength)
	}

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer
func (e *EIGRP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	headerLength := 20
	if e.VirtualRouterID != 0 {
		headerLength = 24
		// Set the VR flag if using Virtual Router ID
		e.Flags |= 0x00000001
	}

	bytes, err := b.PrependBytes(headerLength)
	if err != nil {
		return err
	}

	bytes[0] = e.Version
	bytes[1] = e.Opcode
	binary.BigEndian.PutUint16(bytes[2:4], e.Checksum)
	binary.BigEndian.PutUint32(bytes[4:8], e.Flags)
	binary.BigEndian.PutUint32(bytes[8:12], e.Sequence)
	binary.BigEndian.PutUint32(bytes[12:16], e.Ack)
	binary.BigEndian.PutUint32(bytes[16:20], e.AS)

	if e.VirtualRouterID != 0 {
		binary.BigEndian.PutUint32(bytes[20:24], e.VirtualRouterID)
	}

	// Serialize TLVs
	for _, tlv := range e.TLVs {
		tlvBytes, err := b.AppendBytes(int(tlv.Length))
		if err != nil {
			return err
		}

		binary.BigEndian.PutUint16(tlvBytes[0:2], tlv.Type)
		binary.BigEndian.PutUint16(tlvBytes[2:4], tlv.Length)
		copy(tlvBytes[4:], tlv.Value)
	}

	if opts.ComputeChecksums {
		// Clear checksum bytes first
		bytes[2] = 0
		bytes[3] = 0

		// Compute checksum over the entire packet
		e.Checksum = tcpipChecksum(b.Bytes(), 0)
		binary.BigEndian.PutUint16(bytes[2:4], e.Checksum)
	}

	return nil
}

// OpcodeString returns a string representation of the EIGRP opcode
func (e *EIGRP) OpcodeString() string {
	if name, ok := eigrpOpcodeNames[e.Opcode]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02x)", e.Opcode)
}

// String returns a string representation of the EIGRP packet
func (e *EIGRP) String() string {
	return fmt.Sprintf("EIGRP v%d %s AS:%d Seq:%d Ack:%d Flags:0x%08x",
		e.Version, e.OpcodeString(), e.AS, e.Sequence, e.Ack, e.Flags)
}

// decodeEIGRP decodes the EIGRP layer
func decodeEIGRP(data []byte, p gopacket.PacketBuilder) error {
	e := &EIGRP{}
	return decodingLayerDecoder(e, data, p)
}

// Register EIGRP for appropriate port and protocol
func init() {
	// EIGRP uses IP protocol 88
	RegisterIPProtocol(EIGRPProtocolNumber, layers.EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeEIGRP),
		Name:       "EIGRP",
		LayerType:  LayerTypeEIGRP,
	})
}

// tcpipChecksum is a helper function for calculating checksums
func tcpipChecksum(data []byte, initial uint32) uint16 {
	// Calculate the checksum
	sum := initial
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i]) << 8
		sum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// Take care of any overflow
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	// Get the ones complement
	return ^uint16(sum)
}
