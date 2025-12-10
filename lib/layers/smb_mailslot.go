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
)

// LayerTypeSMBMailSlot is the layer type for SMB MailSlot protocol
var LayerTypeSMBMailSlot gopacket.LayerType

// MailSlot opcodes
type MailSlotOpcode uint16

const (
	MAILSLOT_WRITE      MailSlotOpcode = 0x0001
	MAILSLOT_READ       MailSlotOpcode = 0x0002  // Not commonly used
)

// MailSlot types based on name
const (
	MAILSLOT_UNKNOWN     = 0
	MAILSLOT_BROWSE      = 1
	MAILSLOT_LANMAN      = 2
	MAILSLOT_NETLOGON    = 3
	MAILSLOT_MSSP        = 4
)

// MailSlot class values
const (
	MAILSLOT_CLASS_RELIABLE   = 1
	MAILSLOT_CLASS_UNRELIABLE = 2
)

// Common mailslot names
const (
	MAILSLOT_NAME_BROWSE   = "\\MAILSLOT\\BROWSE"
	MAILSLOT_NAME_LANMAN   = "\\MAILSLOT\\LANMAN"
	MAILSLOT_NAME_NETLOGON = "\\MAILSLOT\\NET\\NETLOGON"
	MAILSLOT_NAME_MSSP     = "\\MAILSLOT\\MSSP"
)

// SMBMailSlot represents an SMB MailSlot message
type SMBMailSlot struct {
	layers.BaseLayer
	
	// MailSlot header fields (from transaction setup)
	Opcode      MailSlotOpcode
	Priority    uint16
	Class       uint16
	
	// MailSlot identification
	MailSlotName string
	MailSlotType int
	
	// From parent SMB transaction
	SMBCommand SMBCommand
}

// LayerType returns the layer type
func (m *SMBMailSlot) LayerType() gopacket.LayerType {
	return LayerTypeSMBMailSlot
}

// CanDecode returns the layer class
func (m *SMBMailSlot) CanDecode() gopacket.LayerClass {
	return LayerTypeSMBMailSlot
}

// NextLayerType returns the next layer type based on mailslot type
func (m *SMBMailSlot) NextLayerType() gopacket.LayerType {
	// If this is a BROWSE mailslot, next layer is CIFS Browser
	if m.MailSlotType == MAILSLOT_BROWSE {
		return LayerTypeCIFSBrowser
	}
	
	// For other mailslot types, we don't have specific decoders yet
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes SMB MailSlot data
func (m *SMBMailSlot) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// The data we receive here should be from the parent SMB layer
	// We need to extract mailslot information from the SMB transaction
	
	// For now, we'll parse what we can from the data directly
	// The parent SMB layer should have already parsed the transaction structure
	
	// Minimum mailslot data would just be the payload
	// Setup words from SMB transaction contain: Opcode, Priority, Class
	
	// Since we're called as the next decoder after SMB, we should have access
	// to the transaction data. However, we need the setup words which are in
	// the SMB layer. We'll work with what we have.
	
	// Mark all data as contents for now, and let the next layer (CIFS Browser)
	// parse the actual payload
	m.Contents = nil
	m.Payload = data
	
	return nil
}

// DecodeFromSMBTransaction decodes mailslot from an SMB transaction
// This is a helper that should be called with the full SMB context
func (m *SMBMailSlot) DecodeFromSMBTransaction(smb *SMBProtocol, data []byte, df gopacket.DecodeFeedback) error {
	// Extract mailslot information from SMB transaction
	m.SMBCommand = smb.Command
	m.MailSlotName = smb.TransactionName
	m.MailSlotType = GetMailSlotType(m.MailSlotName)
	
	// Parse setup words if available
	// Setup words for mailslot: [0]=Opcode, [1]=Priority, [2]=Class
	if len(smb.ParameterWords) >= 30 {
		// Extract setup words (after word 15)
		setupStart := 30
		if len(smb.ParameterWords) >= setupStart+6 {
			m.Opcode = MailSlotOpcode(binary.LittleEndian.Uint16(smb.ParameterWords[setupStart:]))
			m.Priority = binary.LittleEndian.Uint16(smb.ParameterWords[setupStart+2:])
			m.Class = binary.LittleEndian.Uint16(smb.ParameterWords[setupStart+4:])
		}
	}
	
	// The transaction data is the mailslot payload
	m.Contents = nil
	if len(smb.TransactionData) > 0 {
		m.Payload = smb.TransactionData
	} else {
		m.Payload = data
	}
	
	return nil
}

// GetMailSlotType returns the mailslot type based on name
func GetMailSlotType(name string) int {
	nameUpper := strings.ToUpper(name)
	
	if strings.Contains(nameUpper, "BROWSE") {
		return MAILSLOT_BROWSE
	} else if strings.Contains(nameUpper, "LANMAN") {
		return MAILSLOT_LANMAN
	} else if strings.Contains(nameUpper, "NETLOGON") {
		return MAILSLOT_NETLOGON
	} else if strings.Contains(nameUpper, "MSSP") {
		return MAILSLOT_MSSP
	}
	
	return MAILSLOT_UNKNOWN
}

// IsBrowseMailSlot returns true if the name is a browse mailslot
func IsBrowseMailSlot(name string) bool {
	return GetMailSlotType(name) == MAILSLOT_BROWSE
}

// IsLanmanMailSlot returns true if the name is a lanman mailslot
func IsLanmanMailSlot(name string) bool {
	return GetMailSlotType(name) == MAILSLOT_LANMAN
}

// IsNetlogonMailSlot returns true if the name is a netlogon mailslot
func IsNetlogonMailSlot(name string) bool {
	return GetMailSlotType(name) == MAILSLOT_NETLOGON
}

// GetMailSlotTypeName returns the string name of a mailslot type
func GetMailSlotTypeName(mailslotType int) string {
	switch mailslotType {
	case MAILSLOT_BROWSE:
		return "BROWSE"
	case MAILSLOT_LANMAN:
		return "LANMAN"
	case MAILSLOT_NETLOGON:
		return "NETLOGON"
	case MAILSLOT_MSSP:
		return "MSSP"
	default:
		return "UNKNOWN"
	}
}

// String returns a string representation of the opcode
func (o MailSlotOpcode) String() string {
	switch o {
	case MAILSLOT_WRITE:
		return "Write"
	case MAILSLOT_READ:
		return "Read"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", uint16(o))
	}
}

// DecodeSMBMailSlot decodes SMB MailSlot protocol data
// This decoder is called from the SMB layer when a transaction with a mailslot is detected
func DecodeSMBMailSlot(data []byte, p gopacket.PacketBuilder) error {
	mailslot := &SMBMailSlot{}
	
	// PacketBuilder doesn't have a Layers() method, so we'll work with the data we have
	// The SMB layer should have already set up the context we need via TransactionData
	// For now, we'll decode with the data we have
	err := mailslot.DecodeFromBytes(data, p)
	
	if err != nil {
		return err
	}
	
	p.AddLayer(mailslot)
	next := mailslot.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	
	// If the next layer is CIFS Browser, decode it here
	if next == LayerTypeCIFSBrowser && len(data) > 0 {
		// Decode CIFS Browser message
		msg, err := DecodeCIFSBrowserMessage(data)
		if err != nil {
			// Log but don't fail - return the mailslot layer we have
			return nil
		}
		
		// Add the decoded CIFS Browser layer
		// The message types already implement gopacket.Layer interface
		if layer, ok := msg.(gopacket.Layer); ok {
			p.AddLayer(layer)
		}
		
		return nil
	}
	
	return p.NextDecoder(next)
}

// ExtractMailSlotNameFromSMB extracts the mailslot name from SMB transaction data
func ExtractMailSlotNameFromSMB(smbData []byte) (string, error) {
	// This should be called on the ByteData portion of an SMB transaction
	// The transaction name is null-terminated at the start of ByteData
	
	if len(smbData) == 0 {
		return "", errors.New("empty SMB data")
	}
	
	// Find null terminator
	nameEnd := 0
	for i, b := range smbData {
		if b == 0 {
			nameEnd = i
			break
		}
	}
	
	if nameEnd == 0 {
		return "", errors.New("no null terminator found in transaction name")
	}
	
	name := string(smbData[:nameEnd])
	
	// Validate mailslot name format (should start with backslash)
	if len(name) > 0 && (name[0] == '\\' || name[0] == '/') {
		return name, nil
	}
	
	return "", fmt.Errorf("invalid mailslot name format: %q", name)
}

func init() {
	// Register SMB MailSlot layer type
	LayerTypeSMBMailSlot = gopacket.RegisterLayerType(
		2102,
		gopacket.LayerTypeMetadata{
			Name:    "SMBMailSlot",
			Decoder: gopacket.DecodeFunc(DecodeSMBMailSlot),
		},
	)
}
