// Copyright 2025 Patrick InfraSec Consult. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

// LayerTypeNetBIOS is the layer type for NetBIOS Datagram Service protocol
var LayerTypeNetBIOS gopacket.LayerType

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// NetBIOS command types as defined in RFC 1002
type NetBIOSCommand uint8

const (
	NB_ADD_GROUP           NetBIOSCommand = 0x00
	NB_ADD_NAME            NetBIOSCommand = 0x01
	NB_NAME_IN_CONFLICT    NetBIOSCommand = 0x02
	NB_STATUS_QUERY        NetBIOSCommand = 0x03
	NB_TERMINATE_TRACE_R   NetBIOSCommand = 0x07
	NB_DATAGRAM            NetBIOSCommand = 0x08
	NB_DATAGRAM_BCAST      NetBIOSCommand = 0x09
	NB_NAME_QUERY          NetBIOSCommand = 0x0A
	NB_ADD_NAME_RESP       NetBIOSCommand = 0x0D
	NB_NAME_RESP           NetBIOSCommand = 0x0E
	NB_STATUS_RESP         NetBIOSCommand = 0x0F
	NB_TERMINATE_TRACE_LR  NetBIOSCommand = 0x13
	NB_DATA_ACK            NetBIOSCommand = 0x14
	NB_DATA_FIRST_MIDDLE   NetBIOSCommand = 0x15
	NB_DATA_ONLY_LAST      NetBIOSCommand = 0x16
	NB_SESSION_CONFIRM     NetBIOSCommand = 0x17
	NB_SESSION_END         NetBIOSCommand = 0x18
	NB_SESSION_INIT        NetBIOSCommand = 0x19
	NB_NO_RECEIVE          NetBIOSCommand = 0x1A
	NB_RECEIVE_OUTSTANDING NetBIOSCommand = 0x1B
	NB_RECEIVE_CONTINUE    NetBIOSCommand = 0x1C
	NB_KEEP_ALIVE          NetBIOSCommand = 0x1F
)

// String returns the string representation of the NetBIOS command type
func (c NetBIOSCommand) String() string {
	switch c {
	case NB_ADD_GROUP:
		return "Add Group Name"
	case NB_ADD_NAME:
		return "Add Name"
	case NB_NAME_IN_CONFLICT:
		return "Name In Conflict"
	case NB_STATUS_QUERY:
		return "Status Query"
	case NB_TERMINATE_TRACE_R:
		return "Terminate Trace (Remote)"
	case NB_DATAGRAM:
		return "Datagram"
	case NB_DATAGRAM_BCAST:
		return "Datagram Broadcast"
	case NB_NAME_QUERY:
		return "Name Query"
	case NB_ADD_NAME_RESP:
		return "Add Name Response"
	case NB_NAME_RESP:
		return "Name Response"
	case NB_STATUS_RESP:
		return "Status Response"
	case NB_TERMINATE_TRACE_LR:
		return "Terminate Trace (Local/Remote)"
	case NB_DATA_ACK:
		return "Data Acknowledgment"
	case NB_DATA_FIRST_MIDDLE:
		return "Data First Middle"
	case NB_DATA_ONLY_LAST:
		return "Data Only Last"
	case NB_SESSION_CONFIRM:
		return "Session Confirm"
	case NB_SESSION_END:
		return "Session End"
	case NB_SESSION_INIT:
		return "Session Initialize"
	case NB_NO_RECEIVE:
		return "No Receive"
	case NB_RECEIVE_OUTSTANDING:
		return "Receive Outstanding"
	case NB_RECEIVE_CONTINUE:
		return "Receive Continue"
	case NB_KEEP_ALIVE:
		return "Keep Alive"
	default:
		return fmt.Sprintf("Unknown (0x%02x)", uint8(c))
	}
}

// NetBIOS datagram header field offsets (RFC 1002 Section 4.4)
const (
	NB_DGM_MSG_TYPE      = 0
	NB_DGM_FLAGS         = 1
	NB_DGM_ID            = 2
	NB_DGM_SOURCE_IP     = 4
	NB_DGM_SOURCE_PORT   = 8
	NB_DGM_LENGTH        = 10
	NB_DGM_PACKET_OFFSET = 12
	NB_DGM_SOURCE_NAME   = 14
)

// NetBIOS represents a NetBIOS Datagram Service packet (RFC 1002)
type NetBIOS struct {
	layers.BaseLayer

	// Header fields (RFC 1002 datagram format)
	MessageType    NetBIOSCommand // MSG_TYPE
	Flags          uint8          // FLAGS
	DatagramID     uint16         // DGM_ID
	SourceIP       [4]byte        // SOURCE_IP
	SourcePort     uint16         // SOURCE_PORT
	DatagramLength uint16         // DGM_LENGTH
	PacketOffset   uint16         // PACKET_OFFSET (for fragmentation)

	// Names (decoded from RFC 1001 encoding)
	SourceName      string // SOURCE_NAME (34 bytes encoded)
	DestinationName string // DESTINATION_NAME (34 bytes encoded)
}

// LayerType returns the layer type for NetBIOS
func (n *NetBIOS) LayerType() gopacket.LayerType {
	return LayerTypeNetBIOS
}

// CanDecode returns the set of layer types that this layer can decode
func (n *NetBIOS) CanDecode() gopacket.LayerClass {
	return LayerTypeNetBIOS
}

// NextLayerType returns the next layer type
func (n *NetBIOS) NextLayerType() gopacket.LayerType {
	// For RFC 1002 datagram packets, the payload is typically SMB
	// Datagram message types: 0x10, 0x11, 0x12, 0x13
	switch n.MessageType {
	case 0x10, 0x11, 0x12, 0x13:
		// Check if payload looks like SMB
		if len(n.Payload) >= 4 {
			if n.Payload[0] == 0xFF && n.Payload[1] == 'S' && n.Payload[2] == 'M' && n.Payload[3] == 'B' {
				return LayerTypeSMBProtocol
			}
		}
	}
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the NetBIOS datagram packet from bytes (RFC 1002 format)
func (n *NetBIOS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Minimum NetBIOS datagram header is 14 bytes
	if len(data) < 14 {
		log.Warn().Int("length", len(data)).Msg("NetBIOS datagram packet too short")
		return errors.New("NetBIOS datagram packet too short")
	}

	// Parse RFC 1002 datagram header (first 14 bytes)
	n.MessageType = NetBIOSCommand(data[NB_DGM_MSG_TYPE])
	n.Flags = data[NB_DGM_FLAGS]
	n.DatagramID = binary.BigEndian.Uint16(data[NB_DGM_ID:])
	copy(n.SourceIP[:], data[NB_DGM_SOURCE_IP:NB_DGM_SOURCE_IP+4])
	n.SourcePort = binary.BigEndian.Uint16(data[NB_DGM_SOURCE_PORT:])
	n.DatagramLength = binary.BigEndian.Uint16(data[NB_DGM_LENGTH:])
	n.PacketOffset = binary.BigEndian.Uint16(data[NB_DGM_PACKET_OFFSET:])

	offset := NB_DGM_SOURCE_NAME // offset = 14

	// Parse based on message type
	switch n.MessageType {
	case 0x10, 0x11, 0x12, 0x13: // RFC 1002 datagram message types
		// 0x10 = Direct Unique Datagram
		// 0x11 = Direct Group Datagram
		// 0x12 = Broadcast Datagram
		// 0x13 = Datagram Error

		// Names in datagram format: first byte is length (0x20 = 32), then 32 encoded bytes
		// Total: 34 bytes per name

		// Check if we have enough for both names
		if len(data) < offset+68 {
			// Not enough for both names, try to extract what we can
			log.Warn().
				Int("offset", offset).
				Int("have", len(data)).
				Msg("Not enough data for both names in NetBIOS datagram")
		}

		// Source name (34 bytes)
		if len(data) >= offset+34 {
			// First byte should be 0x20 (32 decimal)
			if data[offset] == 0x20 {
				sourceName, err := DecodeNetBIOSName(data[offset+1 : offset+33])
				if err != nil {
					log.Warn().Err(err).Msg("Failed to decode NetBIOS source name")
					n.SourceName = ""
				} else {
					n.SourceName = sourceName
				}
			} else {
				log.Warn().Uint8("lengthByte", data[offset]).Msg("Unexpected length byte for source name")
				n.SourceName = ""
			}
			offset += 34
		} else {
			n.SourceName = ""
		}

		// Destination name (34 bytes)
		if len(data) >= offset+34 {
			if data[offset] == 0x20 {
				destName, err := DecodeNetBIOSName(data[offset+1 : offset+33])
				if err != nil {
					log.Warn().Err(err).Msg("Failed to decode NetBIOS destination name")
					n.DestinationName = ""
				} else {
					n.DestinationName = destName
				}
			} else {
				log.Warn().Uint8("lengthByte", data[offset]).Msg("Unexpected length byte for destination name")
				n.DestinationName = ""
			}
			offset += 34
		} else {
			n.DestinationName = ""
		}

		// Remaining data is the payload (SMB data)
		n.Contents = data[:offset]
		if len(data) > offset {
			n.Payload = data[offset:]
		} else {
			n.Payload = nil
			log.Debug().
				Str("srcName", n.SourceName).
				Str("destName", n.DestinationName).
				Msg("NetBIOS datagram parsed (no payload)")
		}

	default:
		// For non-datagram message types, just mark everything as payload
		n.Contents = data[:14]
		if len(data) > 14 {
			n.Payload = data[14:]
		} else {
			n.Payload = nil
		}
	}

	return nil
}

// DecodeNetBIOSName decodes a NetBIOS name from RFC 1001 first-level encoding
// RFC 1001 encoding: each byte is split into two 4-bit nibbles, each nibble + 'A' (0x41)
// Input: 32 bytes (encoded), Output: 16 bytes (decoded) as string
func DecodeNetBIOSName(encoded []byte) (string, error) {
	if len(encoded) != 32 {
		return "", fmt.Errorf("invalid encoded NetBIOS name length: %d (expected 32)", len(encoded))
	}

	decoded := make([]byte, 16)

	for i := 0; i < 16; i++ {
		// Each decoded byte comes from two encoded bytes
		highNibble := encoded[i*2] - 'A'
		lowNibble := encoded[i*2+1] - 'A'

		// Validate nibbles are in range 0-15
		if highNibble > 15 || lowNibble > 15 {
			return "", fmt.Errorf("invalid NetBIOS name encoding at position %d", i)
		}

		decoded[i] = (highNibble << 4) | lowNibble
	}

	// The last byte is the name type/suffix
	// The first 15 bytes are the name, often space-padded
	// Convert to string and trim spaces and nulls
	nameStr := string(decoded[:15])
	nameStr = strings.TrimRight(nameStr, " \x00")

	// Return name with type suffix if needed
	nameSuffix := decoded[15]
	if nameSuffix != 0x00 && nameSuffix != 0x20 {
		// Include the suffix in hex format
		nameStr = fmt.Sprintf("%s<%02X>", nameStr, nameSuffix)
	}

	return nameStr, nil
}

// IsDatagramCommand returns true if the command is a datagram type
func IsDatagramCommand(cmd NetBIOSCommand) bool {
	return cmd == NB_DATAGRAM || cmd == NB_DATAGRAM_BCAST
}

// GetNetBIOSCommandName returns the string representation of a NetBIOS command
func GetNetBIOSCommandName(cmd NetBIOSCommand) string {
	return cmd.String()
}

// ValidateNetBIOSHeader performs basic validation on NetBIOS datagram header
func ValidateNetBIOSHeader(data []byte) bool {
	if len(data) < 14 {
		return false
	}

	// Check if message type is valid datagram type
	// According to RFC 1002, message types 0x10-0x11 are Direct/Broadcast datagrams
	msgType := data[NB_DGM_MSG_TYPE]
	if msgType >= 0x10 && msgType <= 0x11 {
		return true
	}

	// Also accept legacy command values
	nbCmd := NetBIOSCommand(msgType)
	if nbCmd == NB_DATAGRAM || nbCmd == NB_DATAGRAM_BCAST {
		return true
	}

	log.Debug().Uint8("msgType", msgType).Msg("Unrecognized NetBIOS message type")
	return false
}

// DecodeNetBIOS decodes NetBIOS protocol data
func DecodeNetBIOS(data []byte, p gopacket.PacketBuilder) error {
	netbios := &NetBIOS{}
	err := netbios.DecodeFromBytes(data, p)
	if err != nil {
		log.Warn().Err(err).Msg("NetBIOS DecodeFromBytes failed")
		return err
	}

	p.AddLayer(netbios)
	next := netbios.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}

// SerializeBuffer is a gopacket.SerializeBuffer implementation
type netbiosLayerFactory struct{}

func (f *netbiosLayerFactory) Create() gopacket.Layer {
	return &NetBIOS{}
}

var netbiosLayerFactoryInstance = &netbiosLayerFactory{}

func init() {
	// Register the NetBIOS layer type
	LayerTypeNetBIOS = gopacket.RegisterLayerType(
		2100, // Layer type number (high number to avoid conflicts)
		gopacket.LayerTypeMetadata{
			Name:    "NetBIOS",
			Decoder: gopacket.DecodeFunc(DecodeNetBIOS),
		},
	)

	// Register UDP port 138 for NetBIOS Datagram Service
	layers.RegisterUDPPortLayerType(layers.UDPPort(138), LayerTypeNetBIOS)
}
