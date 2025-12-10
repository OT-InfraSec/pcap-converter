// Copyright 2025 Patrick InfraSec Consult. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

// LayerTypeSMBProtocol is the layer type for SMB v1 protocol
var LayerTypeSMBProtocol gopacket.LayerType

// SMB v1 Command types
type SMBCommand uint8

const (
	SMB_COM_CREATE_DIRECTORY      SMBCommand = 0x00
	SMB_COM_DELETE_DIRECTORY      SMBCommand = 0x01
	SMB_COM_OPEN                  SMBCommand = 0x02
	SMB_COM_CREATE                SMBCommand = 0x03
	SMB_COM_CLOSE                 SMBCommand = 0x04
	SMB_COM_FLUSH                 SMBCommand = 0x05
	SMB_COM_DELETE                SMBCommand = 0x06
	SMB_COM_RENAME                SMBCommand = 0x07
	SMB_COM_QUERY_INFORMATION     SMBCommand = 0x08
	SMB_COM_SET_INFORMATION       SMBCommand = 0x09
	SMB_COM_READ                  SMBCommand = 0x0A
	SMB_COM_WRITE                 SMBCommand = 0x0B
	SMB_COM_LOCK_BYTE_RANGE       SMBCommand = 0x0C
	SMB_COM_UNLOCK_BYTE_RANGE     SMBCommand = 0x0D
	SMB_COM_CREATE_TEMPORARY      SMBCommand = 0x0E
	SMB_COM_CREATE_NEW            SMBCommand = 0x0F
	SMB_COM_CHECK_DIRECTORY       SMBCommand = 0x10
	SMB_COM_PROCESS_EXIT          SMBCommand = 0x11
	SMB_COM_SEEK                  SMBCommand = 0x12
	SMB_COM_LOCK_AND_READ         SMBCommand = 0x13
	SMB_COM_WRITE_AND_UNLOCK      SMBCommand = 0x14
	SMB_COM_READ_RAW              SMBCommand = 0x1A
	SMB_COM_READ_MPX              SMBCommand = 0x1B
	SMB_COM_READ_MPX_SECONDARY    SMBCommand = 0x1C
	SMB_COM_WRITE_RAW             SMBCommand = 0x1D
	SMB_COM_WRITE_MPX             SMBCommand = 0x1E
	SMB_COM_WRITE_MPX_SECONDARY   SMBCommand = 0x1F
	SMB_COM_WRITE_COMPLETE        SMBCommand = 0x20
	SMB_COM_QUERY_SERVER          SMBCommand = 0x21
	SMB_COM_SET_INFORMATION2      SMBCommand = 0x22
	SMB_COM_QUERY_INFORMATION2    SMBCommand = 0x23
	SMB_COM_LOCKING_ANDX          SMBCommand = 0x24
	SMB_COM_TRANSACTION           SMBCommand = 0x25
	SMB_COM_TRANSACTION_SECONDARY SMBCommand = 0x26
	SMB_COM_IOCTL                 SMBCommand = 0x27
	SMB_COM_IOCTL_SECONDARY       SMBCommand = 0x28
	SMB_COM_COPY                  SMBCommand = 0x29
	SMB_COM_MOVE                  SMBCommand = 0x2A
	SMB_COM_ECHO                  SMBCommand = 0x2B
	SMB_COM_WRITE_AND_CLOSE       SMBCommand = 0x2C
	SMB_COM_OPEN_ANDX             SMBCommand = 0x2D
	SMB_COM_READ_ANDX             SMBCommand = 0x2E
	SMB_COM_WRITE_ANDX            SMBCommand = 0x2F
	SMB_COM_NEW_FILE_SIZE         SMBCommand = 0x30
	SMB_COM_CLOSE_AND_TREE_DISC   SMBCommand = 0x31
	SMB_COM_TRANSACTION2          SMBCommand = 0x32
	SMB_COM_TRANSACTION2_SECONDARY SMBCommand = 0x33
	SMB_COM_FIND_CLOSE2           SMBCommand = 0x34
	SMB_COM_FIND_NOTIFY_CLOSE     SMBCommand = 0x35
	SMB_COM_TREE_CONNECT          SMBCommand = 0x70
	SMB_COM_TREE_DISCONNECT       SMBCommand = 0x71
	SMB_COM_NEGOTIATE             SMBCommand = 0x72
	SMB_COM_SESSION_SETUP_ANDX    SMBCommand = 0x73
	SMB_COM_LOGOFF_ANDX           SMBCommand = 0x74
	SMB_COM_TREE_CONNECT_ANDX     SMBCommand = 0x75
	SMB_COM_QUERY_INFORMATION_DISK SMBCommand = 0x80
	SMB_COM_SEARCH                SMBCommand = 0x81
	SMB_COM_FIND                  SMBCommand = 0x82
	SMB_COM_FIND_UNIQUE           SMBCommand = 0x83
	SMB_COM_FIND_CLOSE            SMBCommand = 0x84
	SMB_COM_NT_TRANSACT           SMBCommand = 0xA0
	SMB_COM_NT_TRANSACT_SECONDARY SMBCommand = 0xA1
	SMB_COM_NT_CREATE_ANDX        SMBCommand = 0xA2
	SMB_COM_NT_CANCEL             SMBCommand = 0xA4
	SMB_COM_NT_RENAME             SMBCommand = 0xA5
	SMB_COM_OPEN_PRINT_FILE       SMBCommand = 0xC0
	SMB_COM_WRITE_PRINT_FILE      SMBCommand = 0xC1
	SMB_COM_CLOSE_PRINT_FILE      SMBCommand = 0xC2
	SMB_COM_GET_PRINT_QUEUE       SMBCommand = 0xC3
	SMB_COM_READ_BULK             SMBCommand = 0xD8
	SMB_COM_WRITE_BULK            SMBCommand = 0xD9
	SMB_COM_WRITE_BULK_DATA       SMBCommand = 0xDA
)

// String returns the command name
func (c SMBCommand) String() string {
	switch c {
	case SMB_COM_CREATE_DIRECTORY:
		return "Create Directory"
	case SMB_COM_DELETE_DIRECTORY:
		return "Delete Directory"
	case SMB_COM_OPEN:
		return "Open"
	case SMB_COM_CREATE:
		return "Create"
	case SMB_COM_CLOSE:
		return "Close"
	case SMB_COM_FLUSH:
		return "Flush"
	case SMB_COM_DELETE:
		return "Delete"
	case SMB_COM_RENAME:
		return "Rename"
	case SMB_COM_QUERY_INFORMATION:
		return "Query Information"
	case SMB_COM_SET_INFORMATION:
		return "Set Information"
	case SMB_COM_READ:
		return "Read"
	case SMB_COM_WRITE:
		return "Write"
	case SMB_COM_LOCK_BYTE_RANGE:
		return "Lock Byte Range"
	case SMB_COM_UNLOCK_BYTE_RANGE:
		return "Unlock Byte Range"
	case SMB_COM_CREATE_TEMPORARY:
		return "Create Temporary"
	case SMB_COM_CREATE_NEW:
		return "Create New"
	case SMB_COM_CHECK_DIRECTORY:
		return "Check Directory"
	case SMB_COM_PROCESS_EXIT:
		return "Process Exit"
	case SMB_COM_SEEK:
		return "Seek"
	case SMB_COM_LOCK_AND_READ:
		return "Lock And Read"
	case SMB_COM_WRITE_AND_UNLOCK:
		return "Write And Unlock"
	case SMB_COM_READ_RAW:
		return "Read Raw"
	case SMB_COM_READ_MPX:
		return "Read Mpx"
	case SMB_COM_READ_MPX_SECONDARY:
		return "Read Mpx Secondary"
	case SMB_COM_WRITE_RAW:
		return "Write Raw"
	case SMB_COM_WRITE_MPX:
		return "Write Mpx"
	case SMB_COM_WRITE_MPX_SECONDARY:
		return "Write Mpx Secondary"
	case SMB_COM_WRITE_COMPLETE:
		return "Write Complete"
	case SMB_COM_QUERY_SERVER:
		return "Query Server"
	case SMB_COM_SET_INFORMATION2:
		return "Set Information2"
	case SMB_COM_QUERY_INFORMATION2:
		return "Query Information2"
	case SMB_COM_LOCKING_ANDX:
		return "Locking AndX"
	case SMB_COM_TRANSACTION:
		return "Transaction"
	case SMB_COM_TRANSACTION_SECONDARY:
		return "Transaction Secondary"
	case SMB_COM_IOCTL:
		return "Ioctl"
	case SMB_COM_IOCTL_SECONDARY:
		return "Ioctl Secondary"
	case SMB_COM_COPY:
		return "Copy"
	case SMB_COM_MOVE:
		return "Move"
	case SMB_COM_ECHO:
		return "Echo"
	case SMB_COM_WRITE_AND_CLOSE:
		return "Write And Close"
	case SMB_COM_OPEN_ANDX:
		return "Open AndX"
	case SMB_COM_READ_ANDX:
		return "Read AndX"
	case SMB_COM_WRITE_ANDX:
		return "Write AndX"
	case SMB_COM_NEW_FILE_SIZE:
		return "New File Size"
	case SMB_COM_CLOSE_AND_TREE_DISC:
		return "Close And Tree Disconnect"
	case SMB_COM_TRANSACTION2:
		return "Transaction2"
	case SMB_COM_TRANSACTION2_SECONDARY:
		return "Transaction2 Secondary"
	case SMB_COM_FIND_CLOSE2:
		return "Find Close2"
	case SMB_COM_FIND_NOTIFY_CLOSE:
		return "Find Notify Close"
	case SMB_COM_TREE_CONNECT:
		return "Tree Connect"
	case SMB_COM_TREE_DISCONNECT:
		return "Tree Disconnect"
	case SMB_COM_NEGOTIATE:
		return "Negotiate Protocol"
	case SMB_COM_SESSION_SETUP_ANDX:
		return "Session Setup AndX"
	case SMB_COM_LOGOFF_ANDX:
		return "Logoff AndX"
	case SMB_COM_TREE_CONNECT_ANDX:
		return "Tree Connect AndX"
	case SMB_COM_QUERY_INFORMATION_DISK:
		return "Query Information Disk"
	case SMB_COM_SEARCH:
		return "Search"
	case SMB_COM_FIND:
		return "Find"
	case SMB_COM_FIND_UNIQUE:
		return "Find Unique"
	case SMB_COM_FIND_CLOSE:
		return "Find Close"
	case SMB_COM_NT_TRANSACT:
		return "NT Transact"
	case SMB_COM_NT_TRANSACT_SECONDARY:
		return "NT Transact Secondary"
	case SMB_COM_NT_CREATE_ANDX:
		return "NT Create AndX"
	case SMB_COM_NT_CANCEL:
		return "NT Cancel"
	case SMB_COM_NT_RENAME:
		return "NT Rename"
	case SMB_COM_OPEN_PRINT_FILE:
		return "Open Print File"
	case SMB_COM_WRITE_PRINT_FILE:
		return "Write Print File"
	case SMB_COM_CLOSE_PRINT_FILE:
		return "Close Print File"
	case SMB_COM_GET_PRINT_QUEUE:
		return "Get Print Queue"
	case SMB_COM_READ_BULK:
		return "Read Bulk"
	case SMB_COM_WRITE_BULK:
		return "Write Bulk"
	case SMB_COM_WRITE_BULK_DATA:
		return "Write Bulk Data"
	default:
		return fmt.Sprintf("Unknown (0x%02x)", uint8(c))
	}
}

// SMB Flags
const (
	SMB_FLAGS_LOCK_AND_READ_OK     = 0x01
	SMB_FLAGS_BUF_AVAIL            = 0x02
	SMB_FLAGS_CASE_INSENSITIVE     = 0x08
	SMB_FLAGS_CANONICALIZED_PATHS  = 0x10
	SMB_FLAGS_OPLOCK               = 0x20
	SMB_FLAGS_OPBATCH              = 0x40
	SMB_FLAGS_REPLY                = 0x80
)

// SMB Flags2
const (
	SMB_FLAGS2_LONG_NAMES          = 0x0001
	SMB_FLAGS2_EAS                 = 0x0002
	SMB_FLAGS2_SECURITY_SIGNATURE  = 0x0004
	SMB_FLAGS2_IS_LONG_NAME        = 0x0040
	SMB_FLAGS2_DFS                 = 0x1000
	SMB_FLAGS2_PAGING_IO           = 0x2000
	SMB_FLAGS2_NT_STATUS           = 0x4000
	SMB_FLAGS2_UNICODE             = 0x8000
)

// SMBProtocol represents an SMB v1 protocol packet
type SMBProtocol struct {
	layers.BaseLayer
	
	// SMB v1 Header (32 bytes + variable)
	Protocol        [4]byte // Should be 0xFF,'S','M','B'
	Command         SMBCommand
	NTStatus        uint32  // or Error Class/Code in older dialects
	Flags           uint8
	Flags2          uint16
	PIDHigh         uint16
	Signature       [8]byte // Security signature
	Reserved        uint16
	TID             uint16  // Tree ID
	PID             uint16  // Process ID
	UID             uint16  // User ID
	MID             uint16  // Multiplex ID
	
	// Variable part
	WordCount       uint8
	ParameterWords  []byte  // WordCount * 2 bytes
	ByteCount       uint16
	ByteData        []byte  // ByteCount bytes
	
	// Parsed transaction data (for TRANSACTION commands)
	TransactionName string
	TransactionData []byte
}

// LayerType returns the layer type
func (s *SMBProtocol) LayerType() gopacket.LayerType {
	return LayerTypeSMBProtocol
}

// CanDecode returns the layer class
func (s *SMBProtocol) CanDecode() gopacket.LayerClass {
	return LayerTypeSMBProtocol
}

// NextLayerType returns the next layer type
func (s *SMBProtocol) NextLayerType() gopacket.LayerType {
	// Check if this is a TRANSACTION command with a mailslot
	if s.Command == SMB_COM_TRANSACTION || s.Command == SMB_COM_TRANSACTION2 {
		// Check if transaction name indicates a mailslot
		if len(s.TransactionName) > 0 && 
		   (s.TransactionName[0] == '\\' || s.TransactionName[0] == '/') {
			return LayerTypeSMBMailSlot
		}
	}
	
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes SMB protocol data
func (s *SMBProtocol) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Minimum SMB header is 32 bytes
	if len(data) < 32 {
		log.Warn().Int("length", len(data)).Msg("SMB packet too short")
		return errors.New("SMB packet too short")
	}
	
	// Check magic bytes
	copy(s.Protocol[:], data[0:4])
	if s.Protocol[0] != 0xFF || s.Protocol[1] != 'S' || s.Protocol[2] != 'M' || s.Protocol[3] != 'B' {
		log.Warn().
			Bytes("magic", s.Protocol[:]).
			Msg("Invalid SMB magic bytes")
		return errors.New("invalid SMB magic bytes")
	}
	
	// Parse header
	s.Command = SMBCommand(data[4])
	s.NTStatus = binary.LittleEndian.Uint32(data[5:9])
	s.Flags = data[9]
	s.Flags2 = binary.LittleEndian.Uint16(data[10:12])
	s.PIDHigh = binary.LittleEndian.Uint16(data[12:14])
	copy(s.Signature[:], data[14:22])
	s.Reserved = binary.LittleEndian.Uint16(data[22:24])
	s.TID = binary.LittleEndian.Uint16(data[24:26])
	s.PID = binary.LittleEndian.Uint16(data[26:28])
	s.UID = binary.LittleEndian.Uint16(data[28:30])
	s.MID = binary.LittleEndian.Uint16(data[30:32])
	
	offset := 32
	
	// Check if we have enough data for WordCount
	if len(data) < offset+1 {
		s.Contents = data
		s.Payload = nil
		return nil
	}
	
	// Parse WordCount and parameters
	s.WordCount = data[offset]
	offset++
	
	paramSize := int(s.WordCount) * 2
	if len(data) < offset+paramSize {
		log.Warn().
			Int("expected", paramSize).
			Int("available", len(data)-offset).
			Msg("SMB packet too short for parameters")
		s.Contents = data
		s.Payload = nil
		return nil
	}
	
	s.ParameterWords = data[offset : offset+paramSize]
	offset += paramSize
	
	// Check if we have ByteCount
	if len(data) < offset+2 {
		s.Contents = data[:offset]
		s.Payload = nil
		return nil
	}
	
	// Parse ByteCount and data
	s.ByteCount = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	
	if len(data) < offset+int(s.ByteCount) {
		log.Warn().
			Int("expected", int(s.ByteCount)).
			Int("available", len(data)-offset).
			Msg("SMB packet too short for byte data")
		s.ByteData = data[offset:]
		s.Contents = data
		s.Payload = nil
		return nil
	}
	
	s.ByteData = data[offset : offset+int(s.ByteCount)]
	offset += int(s.ByteCount)
	
	// Parse transaction-specific data
	if s.Command == SMB_COM_TRANSACTION || s.Command == SMB_COM_TRANSACTION2 {
		s.parseTransaction()
	}
	
	s.Contents = data[:offset]
	if len(data) > offset {
		s.Payload = data[offset:]
	} else {
		s.Payload = nil
	}
	
	return nil
}

// parseTransaction parses transaction-specific fields
func (s *SMBProtocol) parseTransaction() {
	// Transaction structure:
	// Parameters (WordCount words):
	//   Word 0: TotalParameterCount
	//   Word 1: TotalDataCount
	//   Word 2: MaxParameterCount
	//   Word 3: MaxDataCount
	//   Word 4: MaxSetupCount
	//   Word 5: Reserved
	//   Word 6: Flags
	//   Word 7-8: Timeout
	//   Word 9: Reserved2
	//   Word 10: ParameterCount
	//   Word 11: ParameterOffset
	//   Word 12: DataCount
	//   Word 13: DataOffset
	//   Word 14: SetupCount
	//   Word 15: Reserved3
	//   Words 16+: Setup words
	
	if len(s.ParameterWords) < 30 { // Need at least 15 words
		return
	}
	
	// Extract setup count and setup words
	setupCount := s.ParameterWords[28] // Word 14 low byte
	setupStart := 30                    // After word 15
	
	if setupCount > 0 && len(s.ParameterWords) >= setupStart+int(setupCount)*2 {
		// Setup words are present - not needed for basic parsing
	}
	
	// Extract transaction name from ByteData
	// ByteData contains: Name (null-terminated string) + padding + params + data
	if len(s.ByteData) > 0 {
		// Find null terminator
		nameEnd := 0
		for i, b := range s.ByteData {
			if b == 0 {
				nameEnd = i
				break
			}
		}
		if nameEnd > 0 {
			s.TransactionName = string(s.ByteData[:nameEnd])
		}
	}
	
	// Extract data portion (for mailslot payload)
	if len(s.ParameterWords) >= 26 {
		dataCount := binary.LittleEndian.Uint16(s.ParameterWords[24:26])  // Word 12
		dataOffset := binary.LittleEndian.Uint16(s.ParameterWords[26:28]) // Word 13
		
		// DataOffset is relative to start of SMB header
		// We need to calculate where that is in ByteData
		if dataOffset >= 32 { // Must be after SMB header
			relativeOffset := int(dataOffset) - 32 - 1 - len(s.ParameterWords) - 2
			if relativeOffset >= 0 && relativeOffset < len(s.ByteData) {
				endOffset := relativeOffset + int(dataCount)
				if endOffset <= len(s.ByteData) {
					s.TransactionData = s.ByteData[relativeOffset:endOffset]
				}
			}
		}
	}
}

// IsResponse returns true if this is a response packet
func (s *SMBProtocol) IsResponse() bool {
	return (s.Flags & SMB_FLAGS_REPLY) != 0
}

// IsTransactionCommand returns true if the command is a transaction type
func IsTransactionCommand(cmd SMBCommand) bool {
	return cmd == SMB_COM_TRANSACTION || 
	       cmd == SMB_COM_TRANSACTION2 || 
	       cmd == SMB_COM_NT_TRANSACT
}

// GetCommandName returns the command name
func GetCommandName(cmd SMBCommand) string {
	return cmd.String()
}

// IsSMBPacket checks if data starts with SMB magic bytes
func IsSMBPacket(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B'
}

// DecodeSMBProtocol decodes SMB protocol data
func DecodeSMBProtocol(data []byte, p gopacket.PacketBuilder) error {
	smb := &SMBProtocol{}
	err := smb.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(smb)
	next := smb.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	
	// For mailslot layer, we need to create a custom packet builder that will
	// decode the transaction data (which contains the actual mailslot payload)
	// The MailSlot decoder will then extract the CIFS Browser data
	// Since we need to pass SMB context, we'll rely on the MailSlot decoder
	// to look back and find the SMB layer
	
	// The transaction data contains the mailslot payload which should be
	// passed to the next decoder (MailSlot, then CIFS Browser)
	if next == LayerTypeSMBMailSlot && len(smb.TransactionData) > 0 {
		// Decode the mailslot with the transaction data
		mailslot := &SMBMailSlot{}
		err := mailslot.DecodeFromSMBTransaction(smb, smb.TransactionData, p)
		if err != nil {
			return err
		}
		p.AddLayer(mailslot)
		
		// Now continue with the next layer (CIFS Browser)
		nextNext := mailslot.NextLayerType()
		if nextNext == gopacket.LayerTypeZero {
			return nil
		}
		return p.NextDecoder(nextNext)
	}
	
	return p.NextDecoder(next)
}

func init() {
	// Register SMB Protocol layer type
	LayerTypeSMBProtocol = gopacket.RegisterLayerType(
		2101,
		gopacket.LayerTypeMetadata{
			Name:    "SMBProtocol",
			Decoder: gopacket.DecodeFunc(DecodeSMBProtocol),
		},
	)
}
