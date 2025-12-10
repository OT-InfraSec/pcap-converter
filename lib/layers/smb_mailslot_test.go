// Copyright 2025 Patrick InfraSec Consult. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"testing"

	"github.com/google/gopacket"
)

// TestGetMailSlotType tests mailslot type detection from name
func TestGetMailSlotType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Browse mailslot",
			input:    "\\MAILSLOT\\BROWSE",
			expected: MAILSLOT_BROWSE,
		},
		{
			name:     "Browse mailslot lowercase",
			input:    "\\mailslot\\browse",
			expected: MAILSLOT_BROWSE,
		},
		{
			name:     "Lanman mailslot",
			input:    "\\MAILSLOT\\LANMAN",
			expected: MAILSLOT_LANMAN,
		},
		{
			name:     "Netlogon mailslot",
			input:    "\\MAILSLOT\\NET\\NETLOGON",
			expected: MAILSLOT_NETLOGON,
		},
		{
			name:     "MSSP mailslot",
			input:    "\\MAILSLOT\\MSSP",
			expected: MAILSLOT_MSSP,
		},
		{
			name:     "Unknown mailslot",
			input:    "\\MAILSLOT\\UNKNOWN",
			expected: MAILSLOT_UNKNOWN,
		},
		{
			name:     "Empty name",
			input:    "",
			expected: MAILSLOT_UNKNOWN,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMailSlotType(tt.input)
			if result != tt.expected {
				t.Errorf("GetMailSlotType(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsBrowseMailSlot tests browse mailslot detection
func TestIsBrowseMailSlot(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Browse mailslot",
			input:    "\\MAILSLOT\\BROWSE",
			expected: true,
		},
		{
			name:     "Lanman mailslot",
			input:    "\\MAILSLOT\\LANMAN",
			expected: false,
		},
		{
			name:     "Empty",
			input:    "",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBrowseMailSlot(tt.input)
			if result != tt.expected {
				t.Errorf("IsBrowseMailSlot(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsLanmanMailSlot tests lanman mailslot detection
func TestIsLanmanMailSlot(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Lanman mailslot",
			input:    "\\MAILSLOT\\LANMAN",
			expected: true,
		},
		{
			name:     "Browse mailslot",
			input:    "\\MAILSLOT\\BROWSE",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLanmanMailSlot(tt.input)
			if result != tt.expected {
				t.Errorf("IsLanmanMailSlot(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsNetlogonMailSlot tests netlogon mailslot detection
func TestIsNetlogonMailSlot(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Netlogon mailslot",
			input:    "\\MAILSLOT\\NET\\NETLOGON",
			expected: true,
		},
		{
			name:     "Browse mailslot",
			input:    "\\MAILSLOT\\BROWSE",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNetlogonMailSlot(tt.input)
			if result != tt.expected {
				t.Errorf("IsNetlogonMailSlot(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestGetMailSlotTypeName tests mailslot type name retrieval
func TestGetMailSlotTypeName(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{
			name:     "Browse",
			input:    MAILSLOT_BROWSE,
			expected: "BROWSE",
		},
		{
			name:     "Lanman",
			input:    MAILSLOT_LANMAN,
			expected: "LANMAN",
		},
		{
			name:     "Netlogon",
			input:    MAILSLOT_NETLOGON,
			expected: "NETLOGON",
		},
		{
			name:     "MSSP",
			input:    MAILSLOT_MSSP,
			expected: "MSSP",
		},
		{
			name:     "Unknown",
			input:    MAILSLOT_UNKNOWN,
			expected: "UNKNOWN",
		},
		{
			name:     "Invalid",
			input:    999,
			expected: "UNKNOWN",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMailSlotTypeName(tt.input)
			if result != tt.expected {
				t.Errorf("GetMailSlotTypeName(%d) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestMailSlotOpcodeString tests opcode string representation
func TestMailSlotOpcodeString(t *testing.T) {
	tests := []struct {
		name     string
		opcode   MailSlotOpcode
		expected string
	}{
		{
			name:     "Write",
			opcode:   MAILSLOT_WRITE,
			expected: "Write",
		},
		{
			name:     "Read",
			opcode:   MAILSLOT_READ,
			expected: "Read",
		},
		{
			name:     "Unknown",
			opcode:   MailSlotOpcode(0xFF),
			expected: "Unknown (0x00ff)",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.opcode.String()
			if result != tt.expected {
				t.Errorf("MailSlotOpcode.String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestExtractMailSlotNameFromSMB tests mailslot name extraction
func TestExtractMailSlotNameFromSMB(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expected  string
		expectErr bool
	}{
		{
			name:      "Valid browse mailslot",
			data:      []byte("\\MAILSLOT\\BROWSE\x00additional data"),
			expected:  "\\MAILSLOT\\BROWSE",
			expectErr: false,
		},
		{
			name:      "Valid lanman mailslot",
			data:      []byte("\\MAILSLOT\\LANMAN\x00more data"),
			expected:  "\\MAILSLOT\\LANMAN",
			expectErr: false,
		},
		{
			name:      "Forward slash",
			data:      []byte("/MAILSLOT/BROWSE\x00data"),
			expected:  "/MAILSLOT/BROWSE",
			expectErr: false,
		},
		{
			name:      "Empty data",
			data:      []byte{},
			expected:  "",
			expectErr: true,
		},
		{
			name:      "No null terminator",
			data:      []byte("\\MAILSLOT\\BROWSE"),
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Invalid format - no backslash",
			data:      []byte("MAILSLOT\\BROWSE\x00"),
			expected:  "",
			expectErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractMailSlotNameFromSMB(tt.data)
			if (err != nil) != tt.expectErr {
				t.Errorf("ExtractMailSlotNameFromSMB() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if !tt.expectErr && result != tt.expected {
				t.Errorf("ExtractMailSlotNameFromSMB() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestSMBMailSlotNextLayerType tests next layer determination
func TestSMBMailSlotNextLayerType(t *testing.T) {
	tests := []struct {
		name         string
		mailslotType int
		expected     gopacket.LayerType
	}{
		{
			name:         "Browse mailslot",
			mailslotType: MAILSLOT_BROWSE,
			expected:     LayerTypeCIFSBrowser,
		},
		{
			name:         "Lanman mailslot",
			mailslotType: MAILSLOT_LANMAN,
			expected:     gopacket.LayerTypePayload,
		},
		{
			name:         "Netlogon mailslot",
			mailslotType: MAILSLOT_NETLOGON,
			expected:     gopacket.LayerTypePayload,
		},
		{
			name:         "Unknown mailslot",
			mailslotType: MAILSLOT_UNKNOWN,
			expected:     gopacket.LayerTypePayload,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mailslot := &SMBMailSlot{
				MailSlotType: tt.mailslotType,
			}
			
			result := mailslot.NextLayerType()
			if result != tt.expected {
				t.Errorf("NextLayerType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSMBMailSlotDecodeFromSMBTransaction tests decoding with SMB context
func TestSMBMailSlotDecodeFromSMBTransaction(t *testing.T) {
	// Create a mock SMB transaction
	smb := &SMBProtocol{
		Command:         SMB_COM_TRANSACTION,
		TransactionName: "\\MAILSLOT\\BROWSE",
		TransactionData: []byte{0x01, 0x02, 0x03, 0x04},
	}
	
	// Create parameter words with setup words
	// Setup: Opcode=1 (Write), Priority=1, Class=2 (Unreliable)
	smb.ParameterWords = make([]byte, 36)
	// Words 0-14 are transaction params (30 bytes)
	// Word 15 is setup count and reserved (2 bytes)
	smb.ParameterWords[28] = 3 // SetupCount = 3
	// Setup words start at byte 30
	smb.ParameterWords[30] = 0x01 // Opcode low byte
	smb.ParameterWords[31] = 0x00 // Opcode high byte
	smb.ParameterWords[32] = 0x01 // Priority low byte
	smb.ParameterWords[33] = 0x00 // Priority high byte
	smb.ParameterWords[34] = 0x02 // Class low byte
	smb.ParameterWords[35] = 0x00 // Class high byte
	
	mailslot := &SMBMailSlot{}
	err := mailslot.DecodeFromSMBTransaction(smb, nil, gopacket.NilDecodeFeedback)
	
	if err != nil {
		t.Fatalf("Failed to decode mailslot: %v", err)
	}
	
	// Verify fields
	if mailslot.MailSlotName != "\\MAILSLOT\\BROWSE" {
		t.Errorf("MailSlotName = %q, want %q", mailslot.MailSlotName, "\\MAILSLOT\\BROWSE")
	}
	
	if mailslot.MailSlotType != MAILSLOT_BROWSE {
		t.Errorf("MailSlotType = %d, want %d", mailslot.MailSlotType, MAILSLOT_BROWSE)
	}
	
	if mailslot.Opcode != MAILSLOT_WRITE {
		t.Errorf("Opcode = %v, want %v", mailslot.Opcode, MAILSLOT_WRITE)
	}
	
	if mailslot.Priority != 1 {
		t.Errorf("Priority = %d, want 1", mailslot.Priority)
	}
	
	if mailslot.Class != 2 {
		t.Errorf("Class = %d, want 2", mailslot.Class)
	}
	
	if len(mailslot.Payload) != 4 {
		t.Errorf("Payload length = %d, want 4", len(mailslot.Payload))
	}
}

// TestSMBMailSlotLayerType tests layer type
func TestSMBMailSlotLayerType(t *testing.T) {
	mailslot := &SMBMailSlot{}
	if mailslot.LayerType() != LayerTypeSMBMailSlot {
		t.Errorf("LayerType() = %v, want LayerTypeSMBMailSlot", mailslot.LayerType())
	}
}

// TestSMBMailSlotDecodeWithoutSMBContext tests decoding without SMB layer
func TestSMBMailSlotDecodeWithoutSMBContext(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	
	mailslot := &SMBMailSlot{}
	err := mailslot.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	
	if err != nil {
		t.Fatalf("Failed to decode mailslot: %v", err)
	}
	
	// Should have data as payload
	if len(mailslot.Payload) != len(data) {
		t.Errorf("Payload length = %d, want %d", len(mailslot.Payload), len(data))
	}
}
