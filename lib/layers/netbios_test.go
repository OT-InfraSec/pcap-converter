// Copyright 2025 Patrick InfraSec Consult. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
)

// TestDecodeNetBIOSName tests RFC 1001 name decoding
func TestDecodeNetBIOSName(t *testing.T) {
	tests := []struct {
		name     string
		encoded  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "Simple workstation name",
			encoded:  encodeNetBIOSNameForTest("WORKSTATION"),
			expected: "WORKSTATION",
			wantErr:  false,
		},
		{
			name:     "Short name",
			encoded:  encodeNetBIOSNameForTest("PC01"),
			expected: "PC01",
			wantErr:  false,
		},
		{
			name:     "Invalid length",
			encoded:  []byte{0x41, 0x41, 0x41},
			expected: "",
			wantErr:  true,
		},
		{
			name: "Invalid encoding - out of range",
			encoded: []byte{
				'Z', 'Z', // Invalid - would decode to nibbles > 15
				'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
				'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
				'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
				'A', 'A', 'A', 'A', 'A', 'A',
			},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeNetBIOSName(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeNetBIOSName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("DecodeNetBIOSName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// buildNetBIOSDatagramPacket builds an RFC 1002 datagram packet for testing
func buildNetBIOSDatagramPacket(msgType NetBIOSCommand, sourceIP [4]byte, sourceName, destName string, payload []byte) []byte {
	data := make([]byte, 0, 200)

	// Byte 0: MESSAGE_TYPE (0x10 = Direct Datagram, 0x11 = Broadcast Datagram)
	data = append(data, byte(msgType))

	// Byte 1: FLAGS
	data = append(data, 0x00)

	// Bytes 2-3: DATAGRAM_ID (big-endian)
	data = append(data, 0xA5, 0x81)

	// Bytes 4-7: SOURCE_IP
	data = append(data, sourceIP[:]...)

	// Bytes 8-9: SOURCE_PORT (big-endian) - port 138
	data = append(data, 0x00, 0x8A)

	// Bytes 10-11: DATAGRAM_LENGTH (will be set later)
	lengthPos := len(data)
	data = append(data, 0x00, 0x00)

	// Bytes 12-13: PACKET_OFFSET
	data = append(data, 0x00, 0x00)

	// Bytes 14-47: SOURCE_NAME (34 bytes)
	sourceBits := encodeNetBIOSNameForTest(sourceName)
	data = append(data, 0x20) // Length byte
	data = append(data, sourceBits...)
	data = append(data, 0x00) // Terminator

	// Bytes 48-81: DESTINATION_NAME (34 bytes)
	destBits := encodeNetBIOSNameForTest(destName)
	data = append(data, 0x20) // Length byte
	data = append(data, destBits...)
	data = append(data, 0x00) // Terminator

	// Bytes 82+: USER_DATA (payload)
	data = append(data, payload...)

	// Set the datagram length (from byte 14 onward = everything after SOURCE_PORT)
	dgramLen := uint16(len(data) - 10) // Length excludes first 10 bytes
	binary.BigEndian.PutUint16(data[lengthPos:], dgramLen)

	return data
}

// TestNetBIOSDatagramParsing tests parsing of NetBIOS datagram packets (RFC 1002)
func TestNetBIOSDatagramParsing(t *testing.T) {
	// Create a NetBIOS datagram packet
	sourceIP := [4]byte{192, 168, 1, 100}
	payload := []byte{0xFF, 'S', 'M', 'B', 0x00, 0x01, 0x02, 0x03}
	
	data := buildNetBIOSDatagramPacket(NB_DATAGRAM, sourceIP, "SOURCE", "DESTINATION", payload)

	// Decode the packet
	packet := gopacket.NewPacket(data, LayerTypeNetBIOS, gopacket.Default)
	netbiosLayer := packet.Layer(LayerTypeNetBIOS)

	if netbiosLayer == nil {
		t.Fatal("Failed to decode NetBIOS layer")
	}

	netbios := netbiosLayer.(*NetBIOS)

	// Verify header fields
	if netbios.MessageType != NB_DATAGRAM {
		t.Errorf("MessageType = %v, want %v", netbios.MessageType, NB_DATAGRAM)
	}

	// Verify source IP
	expectedIP := [4]byte{192, 168, 1, 100}
	if netbios.SourceIP != expectedIP {
		t.Errorf("SourceIP = %v, want %v", netbios.SourceIP, expectedIP)
	}

	// Verify source port
	if netbios.SourcePort != 138 {
		t.Errorf("SourcePort = %d, want 138", netbios.SourcePort)
	}

	// Verify names
	if netbios.SourceName != "SOURCE" {
		t.Errorf("SourceName = %q, want %q", netbios.SourceName, "SOURCE")
	}

	if netbios.DestinationName != "DESTINATION" {
		t.Errorf("DestinationName = %q, want %q", netbios.DestinationName, "DESTINATION")
	}

	// Verify payload
	if len(netbios.Payload) != len(payload) {
		t.Errorf("Payload length = %d, want %d", len(netbios.Payload), len(payload))
	}

	// Verify next layer type
	if netbios.NextLayerType() != LayerTypeSMBProtocol {
		t.Errorf("NextLayerType = %v, want LayerTypeSMBProtocol", netbios.NextLayerType())
	}
}

// TestNetBIOSBroadcastDatagram tests broadcast datagram parsing
func TestNetBIOSBroadcastDatagram(t *testing.T) {
	sourceIP := [4]byte{192, 168, 1, 255}
	payload := []byte{0xFF, 'S', 'M', 'B'}
	
	data := buildNetBIOSDatagramPacket(NB_DATAGRAM_BCAST, sourceIP, "BROADCAST", "*", payload)

	// Decode
	netbios := &NetBIOS{}
	err := netbios.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	if err != nil {
		t.Fatalf("Failed to decode broadcast datagram: %v", err)
	}

	if netbios.MessageType != NB_DATAGRAM_BCAST {
		t.Errorf("MessageType = %v, want NB_DATAGRAM_BCAST", netbios.MessageType)
	}

	if netbios.SourceName != "BROADCAST" {
		t.Errorf("SourceName = %q, want %q", netbios.SourceName, "BROADCAST")
	}
}

// TestNetBIOSTooShort tests handling of truncated packets
func TestNetBIOSTooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty packet",
			data: []byte{},
		},
		{
			name: "Only 4 bytes",
			data: []byte{0x10, 0x00, 0x00, 0xFF},
		},
		{
			name: "Incomplete header",
			data: []byte{0x10, 0x00, 0x00, 0xFF, 0x00, 0x8A},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netbios := &NetBIOS{}
			err := netbios.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback)
			if err == nil {
				t.Error("Expected error for truncated packet, got nil")
			}
		})
	}
}

// TestNetBIOSCommandType tests command type identification
func TestNetBIOSCommandType(t *testing.T) {
	tests := []struct {
		cmd      NetBIOSCommand
		expected string
	}{
		{NB_ADD_GROUP, "Add Group Name"},
		{NB_ADD_NAME, "Add Name"},
		{NB_DATAGRAM, "Datagram"},
		{NB_DATAGRAM_BCAST, "Datagram Broadcast"},
		{NB_NAME_QUERY, "Name Query"},
		{NB_SESSION_INIT, "Session Initialize"},
		{NetBIOSCommand(0xFF), "Unknown (0xff)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.cmd.String()
			if result != tt.expected {
				t.Errorf("Command.String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestIsDatagramCommand tests the datagram command checker
func TestIsDatagramCommand(t *testing.T) {
	tests := []struct {
		cmd      NetBIOSCommand
		expected bool
	}{
		{NB_DATAGRAM, true},
		{NB_DATAGRAM_BCAST, true},
		{NB_ADD_NAME, false},
		{NB_SESSION_INIT, false},
		{NB_NAME_QUERY, false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd.String(), func(t *testing.T) {
			result := IsDatagramCommand(tt.cmd)
			if result != tt.expected {
				t.Errorf("IsDatagramCommand(%v) = %v, want %v", tt.cmd, result, tt.expected)
			}
		})
	}
}

// TestValidateNetBIOSHeader tests header validation
func TestValidateNetBIOSHeader(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid Direct Datagram header",
			data:     []byte{0x10, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x64, 0x00, 0x8A, 0x00, 0x20, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "Valid Broadcast Datagram header",
			data:     []byte{0x11, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0xFF, 0x00, 0x8A, 0x00, 0x20, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x10, 0x00},
			expected: false,
		},
		{
			name:     "Invalid message type",
			data:     []byte{0xAA, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x64, 0x00, 0x8A, 0x00, 0x20, 0x00, 0x00},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNetBIOSHeader(tt.data)
			if result != tt.expected {
				t.Errorf("ValidateNetBIOSHeader() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestNetBIOSNextLayerType tests next layer determination
func TestNetBIOSNextLayerType(t *testing.T) {
	tests := []struct {
		name     string
		msgType  NetBIOSCommand
		payload  []byte
		expected gopacket.LayerType
	}{
		{
			name:     "Datagram with SMB payload",
			msgType:  NB_DATAGRAM,
			payload:  []byte{0xFF, 'S', 'M', 'B', 0x25},
			expected: LayerTypeSMBProtocol,
		},
		{
			name:     "Datagram with non-SMB payload",
			msgType:  NB_DATAGRAM,
			payload:  []byte{0x00, 0x01, 0x02, 0x03},
			expected: gopacket.LayerTypePayload,
		},
		{
			name:     "Broadcast Datagram with SMB payload",
			msgType:  NB_DATAGRAM_BCAST,
			payload:  []byte{0xFF, 'S', 'M', 'B'},
			expected: LayerTypeSMBProtocol,
		},
		{
			name:     "Non-datagram command",
			msgType:  NB_SESSION_INIT,
			payload:  []byte{0xFF, 'S', 'M', 'B'},
			expected: gopacket.LayerTypePayload,
		},
		{
			name:     "Empty payload",
			msgType:  NB_DATAGRAM,
			payload:  []byte{},
			expected: gopacket.LayerTypePayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netbios := &NetBIOS{
				MessageType: tt.msgType,
			}
			netbios.Payload = tt.payload

			result := netbios.NextLayerType()
			if result != tt.expected {
				t.Errorf("NextLayerType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper function to encode a NetBIOS name for testing
// This is a simplified encoder for test purposes
func encodeNetBIOSNameForTest(name string) []byte {
	// Pad to 15 characters
	padded := name
	for len(padded) < 15 {
		padded += " "
	}
	if len(padded) > 15 {
		padded = padded[:15]
	}

	// Add suffix byte (0x00 for workstation)
	padded += "\x00"

	// Encode each byte (32 bytes total = 16 bytes * 2 nibbles each)
	encoded := make([]byte, 32)
	for i := 0; i < 16; i++ {
		b := padded[i]
		encoded[i*2] = 'A' + (b >> 4)
		encoded[i*2+1] = 'A' + (b & 0x0F)
	}

	return encoded
}
