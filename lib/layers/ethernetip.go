// Copyright 2025 InfraSecConsult. All rights reserved.
//
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

// EtherNet/IP Command codes
const (
	EtherNetIPCommandNOP               uint16 = 0x0000
	EtherNetIPCommandListServices      uint16 = 0x0004
	EtherNetIPCommandListIdentity      uint16 = 0x0063
	EtherNetIPCommandListInterfaces    uint16 = 0x0064
	EtherNetIPCommandRegisterSession   uint16 = 0x0065
	EtherNetIPCommandUnregisterSession uint16 = 0x0066
	EtherNetIPCommandSendRRData        uint16 = 0x006F
	EtherNetIPCommandSendUnitData      uint16 = 0x0070
	EtherNetIPCommandIndicateStatus    uint16 = 0x0072
	EtherNetIPCommandCancel            uint16 = 0x0073
)

// EtherNet/IP Status codes
const (
	EtherNetIPStatusSuccess              uint32 = 0x0000
	EtherNetIPStatusInvalidCommand       uint32 = 0x0001
	EtherNetIPStatusInsufficientMemory   uint32 = 0x0002
	EtherNetIPStatusIncorrectData        uint32 = 0x0003
	EtherNetIPStatusInvalidSessionHandle uint32 = 0x0064
	EtherNetIPStatusInvalidLength        uint32 = 0x0065
	EtherNetIPStatusUnsupportedProtocol  uint32 = 0x0069
)

// CIP Service codes
const (
	CIPServiceGetAttributesAll   uint8 = 0x01
	CIPServiceSetAttributesAll   uint8 = 0x02
	CIPServiceGetAttributeSingle uint8 = 0x0E
	CIPServiceSetAttributeSingle uint8 = 0x10
	CIPServiceReset              uint8 = 0x05
	CIPServiceStart              uint8 = 0x06
	CIPServiceStop               uint8 = 0x07
	CIPServiceCreate             uint8 = 0x08
	CIPServiceDelete             uint8 = 0x09
	CIPServiceMultipleServiceReq uint8 = 0x0A
	CIPServiceApplyAttributes    uint8 = 0x0D
	CIPServiceGetAttributeList   uint8 = 0x03
	CIPServiceSetAttributeList   uint8 = 0x04
)

// EtherNet/IP represents an EtherNet/IP packet following the CIP specification
// EtherNet/IP Header Format:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|            Command            |            Length             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        Session Handle                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                            Status                             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        Sender Context                         |
//	|                            (8 bytes)                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           Options                             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type EtherNetIP struct {
	BaseLayer

	// EtherNet/IP Header fields
	Command       uint16 // Command code
	Length        uint16 // Length of data portion
	SessionHandle uint32 // Session handle
	Status        uint32 // Status code
	SenderContext []byte // Sender context (8 bytes)
	Options       uint32 // Options field

	// CIP-specific fields (parsed from data portion)
	Service     uint8  // CIP Service code
	ClassID     uint16 // CIP Class ID
	InstanceID  uint16 // CIP Instance ID
	AttributeID uint16 // CIP Attribute ID

	// Additional parsed data
	DeviceType        string                 // Device type from identity
	VendorID          uint16                 // Vendor ID
	ProductCode       uint16                 // Product code
	SerialNumber      uint32                 // Device serial number
	ProductName       string                 // Product name
	DeviceState       uint8                  // Device state
	ConfigurationData map[string]interface{} // Additional configuration data
	IsImplicitMsg     bool                   // True if this is implicit I/O messaging
	IsExplicitMsg     bool                   // True if this is explicit messaging
}

// LayerType returns the layer type for EtherNet/IP
func (e *EtherNetIP) LayerType() gopacket.LayerType {
	return LayerTypeEtherNetIP
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (e *EtherNetIP) CanDecode() gopacket.LayerClass {
	return LayerTypeEtherNetIP
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (e *EtherNetIP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer
func (e *EtherNetIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 24 {
		return errors.New("EtherNet/IP packet too short (minimum 24 bytes required)")
	}

	e.BaseLayer = BaseLayer{
		Contents: data,
		Payload:  nil,
	}

	// Initialize maps
	e.ConfigurationData = make(map[string]interface{})

	// Parse EtherNet/IP header (24 bytes)
	e.Command = binary.LittleEndian.Uint16(data[0:2])
	e.Length = binary.LittleEndian.Uint16(data[2:4])
	e.SessionHandle = binary.LittleEndian.Uint32(data[4:8])
	e.Status = binary.LittleEndian.Uint32(data[8:12])
	e.SenderContext = make([]byte, 8)
	copy(e.SenderContext, data[12:20])
	e.Options = binary.LittleEndian.Uint32(data[20:24])

	// Validate length field
	if int(e.Length) > len(data)-24 {
		return fmt.Errorf("EtherNet/IP length field (%d) exceeds available data (%d)", e.Length, len(data)-24)
	}

	// Parse data portion if present
	if e.Length > 0 && len(data) > 24 {
		dataPayload := data[24 : 24+e.Length]
		if err := e.parseCIPData(dataPayload); err != nil {
			// Don't fail completely on CIP parsing errors, just log and continue
			// This allows basic EtherNet/IP detection even with malformed CIP data
			e.ConfigurationData["cip_parse_error"] = err.Error()
		}
	}

	// Determine message type based on command
	e.classifyMessageType()

	return nil
}

// parseCIPData parses the CIP (Common Industrial Protocol) data portion
func (e *EtherNetIP) parseCIPData(data []byte) error {
	if len(data) < 2 {
		return errors.New("CIP data too short")
	}

	// Parse based on command type
	switch e.Command {
	case EtherNetIPCommandListIdentity:
		return e.parseListIdentityResponse(data)
	case EtherNetIPCommandSendRRData:
		return e.parseExplicitMessaging(data)
	case EtherNetIPCommandSendUnitData:
		return e.parseImplicitMessaging(data)
	default:
		// For other commands, try to extract basic CIP service info
		if len(data) >= 1 {
			e.Service = data[0]
		}
	}

	return nil
}

// parseListIdentityResponse parses the List Identity response to extract device information
func (e *EtherNetIP) parseListIdentityResponse(data []byte) error {
	if len(data) < 12 {
		return errors.New("List Identity response too short")
	}

	// Skip item count and item type (4 bytes)
	offset := 4
	if len(data) < offset+8 {
		return errors.New("List Identity response missing identity data")
	}

	// Parse identity object
	e.VendorID = binary.LittleEndian.Uint16(data[offset : offset+2])
	e.ProductCode = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
	e.SerialNumber = binary.LittleEndian.Uint32(data[offset+4 : offset+8])
	offset += 8

	// Parse device state and additional info if available
	if len(data) > offset {
		e.DeviceState = data[offset]
		offset++
	}

	// Try to parse product name if present
	if len(data) > offset+1 {
		nameLength := int(data[offset])
		offset++
		if len(data) >= offset+nameLength {
			e.ProductName = string(data[offset : offset+nameLength])
		}
	}

	// Set device type based on vendor/product information
	e.inferDeviceType()

	return nil
}

// parseExplicitMessaging parses explicit messaging data (request/response)
func (e *EtherNetIP) parseExplicitMessaging(data []byte) error {
	if len(data) < 6 {
		return errors.New("Explicit messaging data too short")
	}

	// Skip interface handle and timeout (6 bytes)
	offset := 6
	if len(data) < offset+2 {
		return errors.New("Explicit messaging missing CIP data")
	}

	// Parse CIP request/response
	e.Service = data[offset]
	offset++

	// Parse path if present (simplified parsing)
	if len(data) > offset {
		pathSize := data[offset]
		offset++
		if pathSize > 0 && len(data) >= offset+int(pathSize)*2 {
			// Parse class, instance, attribute from path
			if pathSize >= 1 && len(data) >= offset+2 {
				e.ClassID = binary.LittleEndian.Uint16(data[offset : offset+2])
			}
			if pathSize >= 2 && len(data) >= offset+4 {
				e.InstanceID = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
			}
			if pathSize >= 3 && len(data) >= offset+6 {
				e.AttributeID = binary.LittleEndian.Uint16(data[offset+4 : offset+6])
			}
		}
	}

	e.IsExplicitMsg = true
	return nil
}

// parseImplicitMessaging parses implicit I/O messaging data
func (e *EtherNetIP) parseImplicitMessaging(data []byte) error {
	// Implicit messaging is typically just I/O data
	// The structure varies by device, so we do basic parsing
	e.IsImplicitMsg = true

	// Store raw I/O data size for analysis
	e.ConfigurationData["io_data_size"] = len(data)

	return nil
}

// classifyMessageType determines the type of EtherNet/IP message
func (e *EtherNetIP) classifyMessageType() {
	// Ensure ConfigurationData is initialized
	if e.ConfigurationData == nil {
		e.ConfigurationData = make(map[string]interface{})
	}

	switch e.Command {
	case EtherNetIPCommandSendRRData:
		e.IsExplicitMsg = true
	case EtherNetIPCommandSendUnitData:
		e.IsImplicitMsg = true
	case EtherNetIPCommandListIdentity, EtherNetIPCommandListServices:
		// Discovery messages
		e.ConfigurationData["message_type"] = "discovery"
	case EtherNetIPCommandRegisterSession, EtherNetIPCommandUnregisterSession:
		// Session management
		e.ConfigurationData["message_type"] = "session_management"
	}
}

// inferDeviceType attempts to determine device type from vendor/product information
func (e *EtherNetIP) inferDeviceType() {
	// Common vendor IDs and their typical device types
	switch e.VendorID {
	case 1: // Allen-Bradley/Rockwell
		if e.ProductCode >= 100 && e.ProductCode < 200 {
			e.DeviceType = "PLC"
		} else if e.ProductCode >= 200 && e.ProductCode < 300 {
			e.DeviceType = "HMI"
		} else {
			e.DeviceType = "Industrial_Controller"
		}
	case 42: // Schneider Electric
		e.DeviceType = "PLC"
	case 283: // Siemens
		e.DeviceType = "Industrial_Controller"
	default:
		// Generic classification based on product name or code
		if e.ProductName != "" {
			if contains(e.ProductName, "plc") || contains(e.ProductName, "controller") {
				e.DeviceType = "PLC"
			} else if contains(e.ProductName, "hmi") || contains(e.ProductName, "panel") {
				e.DeviceType = "HMI"
			} else if contains(e.ProductName, "drive") || contains(e.ProductName, "motor") {
				e.DeviceType = "Drive"
			} else {
				e.DeviceType = "Industrial_Device"
			}
		} else {
			e.DeviceType = "Unknown"
		}
	}
}

// Helper function to check if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	// Convert both strings to lowercase for case-insensitive comparison
	sLower := toLower(s)
	substrLower := toLower(substr)

	return findSubstring(sLower, substrLower)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Simple toLower function to avoid importing strings package
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			result[i] = s[i] + 32
		} else {
			result[i] = s[i]
		}
	}
	return string(result)
}

// String returns a string representation of the EtherNet/IP packet
func (e *EtherNetIP) String() string {
	cmdName := e.getCommandName()
	statusName := e.getStatusName()

	if e.DeviceType != "" && e.DeviceType != "Unknown" {
		return fmt.Sprintf("EtherNet/IP %s (Status: %s, Device: %s)", cmdName, statusName, e.DeviceType)
	}
	return fmt.Sprintf("EtherNet/IP %s (Status: %s)", cmdName, statusName)
}

// getCommandName returns a human-readable command name
func (e *EtherNetIP) getCommandName() string {
	switch e.Command {
	case EtherNetIPCommandNOP:
		return "NOP"
	case EtherNetIPCommandListServices:
		return "List Services"
	case EtherNetIPCommandListIdentity:
		return "List Identity"
	case EtherNetIPCommandListInterfaces:
		return "List Interfaces"
	case EtherNetIPCommandRegisterSession:
		return "Register Session"
	case EtherNetIPCommandUnregisterSession:
		return "Unregister Session"
	case EtherNetIPCommandSendRRData:
		return "Send RR Data"
	case EtherNetIPCommandSendUnitData:
		return "Send Unit Data"
	case EtherNetIPCommandIndicateStatus:
		return "Indicate Status"
	case EtherNetIPCommandCancel:
		return "Cancel"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", e.Command)
	}
}

// getStatusName returns a human-readable status name
func (e *EtherNetIP) getStatusName() string {
	switch e.Status {
	case EtherNetIPStatusSuccess:
		return "Success"
	case EtherNetIPStatusInvalidCommand:
		return "Invalid Command"
	case EtherNetIPStatusInsufficientMemory:
		return "Insufficient Memory"
	case EtherNetIPStatusIncorrectData:
		return "Incorrect Data"
	case EtherNetIPStatusInvalidSessionHandle:
		return "Invalid Session Handle"
	case EtherNetIPStatusInvalidLength:
		return "Invalid Length"
	case EtherNetIPStatusUnsupportedProtocol:
		return "Unsupported Protocol"
	default:
		return fmt.Sprintf("Unknown(0x%08X)", e.Status)
	}
}

// GetDeviceIdentity returns device identity information extracted from the packet
func (e *EtherNetIP) GetDeviceIdentity() map[string]interface{} {
	identity := make(map[string]interface{})

	if e.VendorID != 0 {
		identity["vendor_id"] = e.VendorID
	}
	if e.ProductCode != 0 {
		identity["product_code"] = e.ProductCode
	}
	if e.SerialNumber != 0 {
		identity["serial_number"] = e.SerialNumber
	}
	if e.ProductName != "" {
		identity["product_name"] = e.ProductName
	}
	if e.DeviceType != "" {
		identity["device_type"] = e.DeviceType
	}
	if e.DeviceState != 0 {
		identity["device_state"] = e.DeviceState
	}

	return identity
}

// GetCIPInfo returns CIP-specific information
func (e *EtherNetIP) GetCIPInfo() map[string]interface{} {
	cip := make(map[string]interface{})

	if e.Service != 0 {
		cip["service"] = e.Service
		cip["service_name"] = e.getCIPServiceName()
	}
	if e.ClassID != 0 {
		cip["class_id"] = e.ClassID
	}
	if e.InstanceID != 0 {
		cip["instance_id"] = e.InstanceID
	}
	if e.AttributeID != 0 {
		cip["attribute_id"] = e.AttributeID
	}

	cip["is_explicit"] = e.IsExplicitMsg
	cip["is_implicit"] = e.IsImplicitMsg

	return cip
}

// getCIPServiceName returns a human-readable CIP service name
func (e *EtherNetIP) getCIPServiceName() string {
	switch e.Service {
	case CIPServiceGetAttributesAll:
		return "Get Attributes All"
	case CIPServiceSetAttributesAll:
		return "Set Attributes All"
	case CIPServiceGetAttributeSingle:
		return "Get Attribute Single"
	case CIPServiceSetAttributeSingle:
		return "Set Attribute Single"
	case CIPServiceReset:
		return "Reset"
	case CIPServiceStart:
		return "Start"
	case CIPServiceStop:
		return "Stop"
	case CIPServiceCreate:
		return "Create"
	case CIPServiceDelete:
		return "Delete"
	case CIPServiceMultipleServiceReq:
		return "Multiple Service Request"
	case CIPServiceApplyAttributes:
		return "Apply Attributes"
	case CIPServiceGetAttributeList:
		return "Get Attribute List"
	case CIPServiceSetAttributeList:
		return "Set Attribute List"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", e.Service)
	}
}

// IsDiscoveryMessage returns true if this is a discovery-related message
func (e *EtherNetIP) IsDiscoveryMessage() bool {
	return e.Command == EtherNetIPCommandListIdentity ||
		e.Command == EtherNetIPCommandListServices ||
		e.Command == EtherNetIPCommandListInterfaces
}

// IsSessionManagement returns true if this is a session management message
func (e *EtherNetIP) IsSessionManagement() bool {
	return e.Command == EtherNetIPCommandRegisterSession ||
		e.Command == EtherNetIPCommandUnregisterSession
}

// IsDataTransfer returns true if this is a data transfer message
func (e *EtherNetIP) IsDataTransfer() bool {
	return e.Command == EtherNetIPCommandSendRRData ||
		e.Command == EtherNetIPCommandSendUnitData
}

// LayerTypeEtherNetIP is the layer type for EtherNet/IP packets
var LayerTypeEtherNetIP = gopacket.RegisterLayerType(
	1004, // Layer type number - using a high number to avoid conflicts
	gopacket.LayerTypeMetadata{
		Name:    "EtherNetIP",
		Decoder: gopacket.DecodeFunc(decodeEtherNetIP),
	},
)

// decodeEtherNetIP is the decoder function for EtherNet/IP packets
func decodeEtherNetIP(data []byte, p gopacket.PacketBuilder) error {
	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(ethernetip)
	return p.NextDecoder(ethernetip.NextLayerType())
}

// RegisterEtherNetIP registers the EtherNet/IP protocol with common TCP/UDP ports
func RegisterEtherNetIP() {
	// Register EtherNet/IP on standard ports
	layers.RegisterTCPPortLayerType(44818, LayerTypeEtherNetIP) // TCP port 44818
	layers.RegisterUDPPortLayerType(2222, LayerTypeEtherNetIP)  // UDP port 2222
}

// InitLayerEtherNetIP initializes the EtherNet/IP layer for gopacket
func InitLayerEtherNetIP() {
	RegisterEtherNetIP()
}

// Validate performs comprehensive validation of the EtherNet/IP packet
func (e *EtherNetIP) Validate() error {
	if err := e.validateHeader(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}

	if err := e.validateCIPData(); err != nil {
		return fmt.Errorf("CIP data validation failed: %w", err)
	}

	if err := e.validateDeviceIdentity(); err != nil {
		return fmt.Errorf("device identity validation failed: %w", err)
	}

	return nil
}

// validateHeader validates the EtherNet/IP header fields
func (e *EtherNetIP) validateHeader() error {
	// Validate command field
	validCommands := map[uint16]bool{
		EtherNetIPCommandNOP:               true,
		EtherNetIPCommandListServices:      true,
		EtherNetIPCommandListIdentity:      true,
		EtherNetIPCommandListInterfaces:    true,
		EtherNetIPCommandRegisterSession:   true,
		EtherNetIPCommandUnregisterSession: true,
		EtherNetIPCommandSendRRData:        true,
		EtherNetIPCommandSendUnitData:      true,
		EtherNetIPCommandIndicateStatus:    true,
		EtherNetIPCommandCancel:            true,
	}

	if !validCommands[e.Command] {
		return fmt.Errorf("invalid command code: 0x%04X", e.Command)
	}

	// Validate length field (should not exceed reasonable limits)
	const maxReasonableLength = 65535
	if e.Length > maxReasonableLength {
		return fmt.Errorf("length field too large: %d", e.Length)
	}

	// Validate status field for known status codes
	if e.Status != EtherNetIPStatusSuccess {
		validStatuses := map[uint32]bool{
			EtherNetIPStatusInvalidCommand:       true,
			EtherNetIPStatusInsufficientMemory:   true,
			EtherNetIPStatusIncorrectData:        true,
			EtherNetIPStatusInvalidSessionHandle: true,
			EtherNetIPStatusInvalidLength:        true,
			EtherNetIPStatusUnsupportedProtocol:  true,
		}
		if !validStatuses[e.Status] {
			// Not a fatal error, but worth noting
			if e.ConfigurationData == nil {
				e.ConfigurationData = make(map[string]interface{})
			}
			e.ConfigurationData["unknown_status"] = fmt.Sprintf("0x%08X", e.Status)
		}
	}

	// Validate sender context length
	if len(e.SenderContext) != 8 {
		return fmt.Errorf("sender context must be 8 bytes, got %d", len(e.SenderContext))
	}

	return nil
}

// validateCIPData validates the Common Industrial Protocol data
func (e *EtherNetIP) validateCIPData() error {
	// Validate service code if present
	if e.Service != 0 {
		validServices := map[uint8]bool{
			CIPServiceGetAttributesAll:   true,
			CIPServiceSetAttributesAll:   true,
			CIPServiceGetAttributeSingle: true,
			CIPServiceSetAttributeSingle: true,
			CIPServiceReset:              true,
			CIPServiceStart:              true,
			CIPServiceStop:               true,
			CIPServiceCreate:             true,
			CIPServiceDelete:             true,
			CIPServiceMultipleServiceReq: true,
			CIPServiceApplyAttributes:    true,
			CIPServiceGetAttributeList:   true,
			CIPServiceSetAttributeList:   true,
		}
		if !validServices[e.Service] {
			// Not necessarily an error, might be a vendor-specific service
			if e.ConfigurationData == nil {
				e.ConfigurationData = make(map[string]interface{})
			}
			e.ConfigurationData["unknown_service"] = fmt.Sprintf("0x%02X", e.Service)
		}
	}

	// CIP IDs are uint16, so they're automatically within valid range

	return nil
}

// validateDeviceIdentity validates device identity information extracted from packets
func (e *EtherNetIP) validateDeviceIdentity() error {
	// Validate vendor ID
	if e.VendorID > 0 {
		// Vendor IDs are typically well-defined ranges
		const maxVendorID = 0xFFFF
		if e.VendorID > maxVendorID {
			return fmt.Errorf("vendor ID out of range: %d", e.VendorID)
		}
	}

	// Validate product name length and content
	if e.ProductName != "" {
		const maxProductNameLength = 256
		if len(e.ProductName) > maxProductNameLength {
			return fmt.Errorf("product name too long: %d characters", len(e.ProductName))
		}

		// Check for reasonable ASCII content
		for i, r := range e.ProductName {
			if r < 0x20 || r > 0x7E {
				return fmt.Errorf("invalid character in product name at position %d: 0x%02X", i, r)
			}
		}
	}

	// DeviceState is uint8, so it's automatically within valid range

	return nil
}

// IsValidForClassification returns true if the packet contains sufficient information for device classification
func (e *EtherNetIP) IsValidForClassification() bool {
	// Must have valid command
	if e.Command == 0 {
		return false
	}

	// Must have successful status or be a request
	if e.Status != EtherNetIPStatusSuccess && e.Command != EtherNetIPCommandListIdentity {
		return false
	}

	// For classification, we need either device identity or service information
	hasDeviceIdentity := e.VendorID > 0 || e.ProductName != "" || e.SerialNumber > 0
	hasServiceInfo := e.Service > 0 || e.ClassID > 0

	return hasDeviceIdentity || hasServiceInfo
}

// ExtractDeviceIdentityInfo safely extracts device identity information
func (e *EtherNetIP) ExtractDeviceIdentityInfo() map[string]interface{} {
	identity := make(map[string]interface{})

	// Only include fields that have been validated and are present
	if e.VendorID > 0 {
		identity["vendor_id"] = e.VendorID
	}

	if e.ProductCode > 0 {
		identity["product_code"] = e.ProductCode
	}

	if e.SerialNumber > 0 {
		identity["serial_number"] = e.SerialNumber
	}

	if e.ProductName != "" {
		identity["product_name"] = e.ProductName
	}

	if e.DeviceType != "" {
		identity["device_type"] = e.DeviceType
	}

	if e.DeviceState > 0 {
		identity["device_state"] = e.DeviceState
	}

	// Add any additional configuration data that passed validation
	if e.ConfigurationData != nil {
		for k, v := range e.ConfigurationData {
			identity[k] = v
		}
	}

	return identity
}

// ExtractSecurityInfo safely extracts security-related information
func (e *EtherNetIP) ExtractSecurityInfo() map[string]interface{} {
	security := make(map[string]interface{})

	// EtherNet/IP doesn't have built-in security, but we can infer some information
	// Check if this appears to be encrypted or secured communication
	if e.SessionHandle > 0 {
		security["has_session"] = true
		security["session_handle"] = e.SessionHandle
	}

	// Check for any security-related configuration data
	if e.ConfigurationData != nil {
		for k, v := range e.ConfigurationData {
			if strings.Contains(strings.ToLower(k), "security") ||
				strings.Contains(strings.ToLower(k), "auth") ||
				strings.Contains(strings.ToLower(k), "encrypt") {
				security[k] = v
			}
		}
	}

	// Infer security level based on protocol usage
	security["security_level"] = "none" // EtherNet/IP typically has no security
	if e.SessionHandle > 0 {
		security["security_level"] = "basic" // At least has session management
	}

	return security
}
