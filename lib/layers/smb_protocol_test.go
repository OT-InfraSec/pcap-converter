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

// TestSMBMagicDetection tests SMB magic byte detection
func TestSMBMagicDetection(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid SMB v1 magic",
			data:     []byte{0xFF, 'S', 'M', 'B'},
			expected: true,
		},
		{
			name:     "Invalid magic",
			data:     []byte{0x00, 0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "Too short",
			data:     []byte{0xFF, 'S'},
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSMBPacket(tt.data)
			if result != tt.expected {
				t.Errorf("IsSMBPacket() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSMBCommandString tests command string representation
func TestSMBCommandString(t *testing.T) {
	tests := []struct {
		cmd      SMBCommand
		expected string
	}{
		{SMB_COM_NEGOTIATE, "Negotiate Protocol"},
		{SMB_COM_SESSION_SETUP_ANDX, "Session Setup AndX"},
		{SMB_COM_TREE_CONNECT_ANDX, "Tree Connect AndX"},
		{SMB_COM_TRANSACTION, "Transaction"},
		{SMB_COM_TRANSACTION2, "Transaction2"},
		{SMB_COM_NT_TRANSACT, "NT Transact"},
		{SMB_COM_CLOSE, "Close"},
		{SMBCommand(0xFF), "Unknown (0xff)"},
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

// TestIsTransactionCommand tests transaction command detection
func TestIsTransactionCommand(t *testing.T) {
	tests := []struct {
		cmd      SMBCommand
		expected bool
	}{
		{SMB_COM_TRANSACTION, true},
		{SMB_COM_TRANSACTION2, true},
		{SMB_COM_NT_TRANSACT, true},
		{SMB_COM_NEGOTIATE, false},
		{SMB_COM_CLOSE, false},
		{SMB_COM_READ, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.cmd.String(), func(t *testing.T) {
			result := IsTransactionCommand(tt.cmd)
			if result != tt.expected {
				t.Errorf("IsTransactionCommand(%v) = %v, want %v", tt.cmd, result, tt.expected)
			}
		})
	}
}

// TestSMBHeaderParsing tests basic SMB header parsing
func TestSMBHeaderParsing(t *testing.T) {
	// Create a minimal SMB packet
	data := make([]byte, 37) // 32 byte header + 1 WordCount + 2 ByteCount + 2 padding
	
	// Magic bytes
	data[0] = 0xFF
	data[1] = 'S'
	data[2] = 'M'
	data[3] = 'B'
	
	// Command
	data[4] = byte(SMB_COM_NEGOTIATE)
	
	// NTStatus (4 bytes) - success
	binary.LittleEndian.PutUint32(data[5:9], 0x00000000)
	
	// Flags
	data[9] = 0x00
	
	// Flags2
	binary.LittleEndian.PutUint16(data[10:12], SMB_FLAGS2_LONG_NAMES)
	
	// PIDHigh
	binary.LittleEndian.PutUint16(data[12:14], 0x0000)
	
	// Signature (8 bytes) - zeros
	// Reserved (2 bytes) - zeros
	
	// TID
	binary.LittleEndian.PutUint16(data[24:26], 0x0001)
	
	// PID
	binary.LittleEndian.PutUint16(data[26:28], 0x1234)
	
	// UID
	binary.LittleEndian.PutUint16(data[28:30], 0x5678)
	
	// MID
	binary.LittleEndian.PutUint16(data[30:32], 0x0001)
	
	// WordCount
	data[32] = 0x00
	
	// ByteCount
	binary.LittleEndian.PutUint16(data[33:35], 0x0000)
	
	// Decode
	smb := &SMBProtocol{}
	err := smb.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	
	if err != nil {
		t.Fatalf("Failed to decode SMB header: %v", err)
	}
	
	// Verify fields
	if smb.Command != SMB_COM_NEGOTIATE {
		t.Errorf("Command = %v, want %v", smb.Command, SMB_COM_NEGOTIATE)
	}
	
	if smb.TID != 0x0001 {
		t.Errorf("TID = 0x%04X, want 0x0001", smb.TID)
	}
	
	if smb.PID != 0x1234 {
		t.Errorf("PID = 0x%04X, want 0x1234", smb.PID)
	}
	
	if smb.UID != 0x5678 {
		t.Errorf("UID = 0x%04X, want 0x5678", smb.UID)
	}
	
	if smb.Flags2 != SMB_FLAGS2_LONG_NAMES {
		t.Errorf("Flags2 = 0x%04X, want 0x%04X", smb.Flags2, SMB_FLAGS2_LONG_NAMES)
	}
}

// TestSMBResponseFlag tests response flag detection
func TestSMBResponseFlag(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint8
		expected bool
	}{
		{
			name:     "Response packet",
			flags:    SMB_FLAGS_REPLY,
			expected: true,
		},
		{
			name:     "Request packet",
			flags:    0x00,
			expected: false,
		},
		{
			name:     "Response with other flags",
			flags:    SMB_FLAGS_REPLY | SMB_FLAGS_OPLOCK,
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smb := &SMBProtocol{Flags: tt.flags}
			result := smb.IsResponse()
			if result != tt.expected {
				t.Errorf("IsResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSMBTransactionParsing tests transaction command parsing
func TestSMBTransactionParsing(t *testing.T) {
	// Create an SMB TRANSACTION packet with mailslot name
	data := make([]byte, 0, 200)
	
	// SMB Header
	data = append(data, 0xFF, 'S', 'M', 'B')
	data = append(data, byte(SMB_COM_TRANSACTION))
	
	// NTStatus
	data = append(data, 0x00, 0x00, 0x00, 0x00)
	
	// Flags
	data = append(data, 0x00)
	
	// Flags2
	data = append(data, 0x00, 0x00)
	
	// PIDHigh
	data = append(data, 0x00, 0x00)
	
	// Signature (8 bytes)
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	
	// Reserved
	data = append(data, 0x00, 0x00)
	
	// TID, PID, UID, MID
	data = append(data, 0x01, 0x00) // TID
	data = append(data, 0x34, 0x12) // PID
	data = append(data, 0x78, 0x56) // UID
	data = append(data, 0x01, 0x00) // MID
	
	// WordCount - 17 words for transaction (34 bytes)
	data = append(data, 17)
	
	// Transaction parameters (17 words = 34 bytes)
	params := make([]byte, 34)
	binary.LittleEndian.PutUint16(params[0:2], 0)     // TotalParameterCount
	binary.LittleEndian.PutUint16(params[2:4], 100)   // TotalDataCount
	binary.LittleEndian.PutUint16(params[4:6], 0)     // MaxParameterCount
	binary.LittleEndian.PutUint16(params[6:8], 1024)  // MaxDataCount
	params[8] = 0                                      // MaxSetupCount
	params[9] = 0                                      // Reserved
	binary.LittleEndian.PutUint16(params[10:12], 0)   // Flags
	binary.LittleEndian.PutUint32(params[12:16], 0)   // Timeout
	binary.LittleEndian.PutUint16(params[16:18], 0)   // Reserved2
	binary.LittleEndian.PutUint16(params[18:20], 0)   // ParameterCount
	binary.LittleEndian.PutUint16(params[20:22], 0)   // ParameterOffset
	binary.LittleEndian.PutUint16(params[24:26], 50)  // DataCount
	binary.LittleEndian.PutUint16(params[26:28], 90)  // DataOffset (relative to SMB header start)
	params[28] = 3                                     // SetupCount
	params[29] = 0                                     // Reserved3
	// Setup words (3 words = 6 bytes) - OpCode, Priority, Class
	binary.LittleEndian.PutUint16(params[30:32], 1)   // OpCode: Write
	binary.LittleEndian.PutUint16(params[32:34], 1)   // Priority
	
	data = append(data, params...)
	
	// ByteCount
	mailslotName := "\\MAILSLOT\\BROWSE\x00"
	byteDataSize := len(mailslotName) + 50 // name + data
	binary.LittleEndian.PutUint16(params[0:2], uint16(byteDataSize))
	data = append(data, byte(byteDataSize&0xFF), byte((byteDataSize>>8)&0xFF))
	
	// ByteData: Transaction name
	data = append(data, []byte(mailslotName)...)
	
	// Padding to align data
	padding := 90 - (len(data) + 50)
	if padding > 0 {
		for i := 0; i < padding; i++ {
			data = append(data, 0x00)
		}
	}
	
	// Transaction data (50 bytes)
	transData := make([]byte, 50)
	for i := range transData {
		transData[i] = byte(i)
	}
	data = append(data, transData...)
	
	// Decode
	smb := &SMBProtocol{}
	err := smb.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	
	if err != nil {
		t.Fatalf("Failed to decode SMB transaction: %v", err)
	}
	
	// Verify command
	if smb.Command != SMB_COM_TRANSACTION {
		t.Errorf("Command = %v, want SMB_COM_TRANSACTION", smb.Command)
	}
	
	// Verify transaction name was extracted
	if smb.TransactionName != "\\MAILSLOT\\BROWSE" {
		t.Errorf("TransactionName = %q, want %q", smb.TransactionName, "\\MAILSLOT\\BROWSE")
	}
}

// TestSMBTooShort tests handling of truncated packets
func TestSMBTooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty",
			data: []byte{},
		},
		{
			name: "Only magic",
			data: []byte{0xFF, 'S', 'M', 'B'},
		},
		{
			name: "Incomplete header",
			data: []byte{
				0xFF, 'S', 'M', 'B',
				byte(SMB_COM_NEGOTIATE),
				0x00, 0x00, 0x00, 0x00,
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smb := &SMBProtocol{}
			err := smb.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback)
			if err == nil {
				t.Error("Expected error for truncated packet, got nil")
			}
		})
	}
}

// TestSMBInvalidMagic tests handling of invalid magic bytes
func TestSMBInvalidMagic(t *testing.T) {
	data := make([]byte, 32)
	// Invalid magic
	data[0] = 0x00
	data[1] = 0x01
	data[2] = 0x02
	data[3] = 0x03
	
	smb := &SMBProtocol{}
	err := smb.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	
	if err == nil {
		t.Error("Expected error for invalid magic bytes, got nil")
	}
}

// TestSMBNextLayerType tests next layer type determination
func TestSMBNextLayerType(t *testing.T) {
	tests := []struct {
		name            string
		command         SMBCommand
		transactionName string
		expected        gopacket.LayerType
	}{
		{
			name:            "Transaction with mailslot",
			command:         SMB_COM_TRANSACTION,
			transactionName: "\\MAILSLOT\\BROWSE",
			expected:        LayerTypeSMBMailSlot,
		},
		{
			name:            "Transaction2 with mailslot",
			command:         SMB_COM_TRANSACTION2,
			transactionName: "\\MAILSLOT\\LANMAN",
			expected:        LayerTypeSMBMailSlot,
		},
		{
			name:            "Transaction without mailslot",
			command:         SMB_COM_TRANSACTION,
			transactionName: "",
			expected:        gopacket.LayerTypePayload,
		},
		{
			name:            "Non-transaction command",
			command:         SMB_COM_NEGOTIATE,
			transactionName: "",
			expected:        gopacket.LayerTypePayload,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smb := &SMBProtocol{
				Command:         tt.command,
				TransactionName: tt.transactionName,
			}
			
			result := smb.NextLayerType()
			if result != tt.expected {
				t.Errorf("NextLayerType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSMBLayerType tests layer type
func TestSMBLayerType(t *testing.T) {
	smb := &SMBProtocol{}
	if smb.LayerType() != LayerTypeSMBProtocol {
		t.Errorf("LayerType() = %v, want LayerTypeSMBProtocol", smb.LayerType())
	}
}

// TestSMBWithParameters tests parsing with parameter words
func TestSMBWithParameters(t *testing.T) {
	data := make([]byte, 0, 100)
	
	// SMB Header
	data = append(data, 0xFF, 'S', 'M', 'B')
	data = append(data, byte(SMB_COM_NEGOTIATE))
	data = append(data, 0x00, 0x00, 0x00, 0x00) // NTStatus
	data = append(data, 0x00)                    // Flags
	data = append(data, 0x00, 0x00)              // Flags2
	data = append(data, 0x00, 0x00)              // PIDHigh
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // Signature
	data = append(data, 0x00, 0x00)              // Reserved
	data = append(data, 0x00, 0x00)              // TID
	data = append(data, 0x00, 0x00)              // PID
	data = append(data, 0x00, 0x00)              // UID
	data = append(data, 0x00, 0x00)              // MID
	
	// WordCount = 2 (4 bytes of parameters)
	data = append(data, 0x02)
	
	// Parameter words (2 words = 4 bytes)
	data = append(data, 0x01, 0x00, 0x02, 0x00)
	
	// ByteCount = 10
	data = append(data, 0x0A, 0x00)
	
	// ByteData (10 bytes)
	for i := 0; i < 10; i++ {
		data = append(data, byte(i))
	}
	
	// Decode
	smb := &SMBProtocol{}
	err := smb.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	
	if err != nil {
		t.Fatalf("Failed to decode SMB with parameters: %v", err)
	}
	
	if smb.WordCount != 2 {
		t.Errorf("WordCount = %d, want 2", smb.WordCount)
	}
	
	if len(smb.ParameterWords) != 4 {
		t.Errorf("len(ParameterWords) = %d, want 4", len(smb.ParameterWords))
	}
	
	if smb.ByteCount != 10 {
		t.Errorf("ByteCount = %d, want 10", smb.ByteCount)
	}
	
	if len(smb.ByteData) != 10 {
		t.Errorf("len(ByteData) = %d, want 10", len(smb.ByteData))
	}
}
