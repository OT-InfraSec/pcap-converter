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

// OPC UA Message Types
const (
	OPCUAMessageTypeHello        = "HEL"
	OPCUAMessageTypeAcknowledge  = "ACK"
	OPCUAMessageTypeError        = "ERR"
	OPCUAMessageTypeReverseHello = "RHE"
	OPCUAMessageTypeOpenChannel  = "OPN"
	OPCUAMessageTypeCloseChannel = "CLO"
	OPCUAMessageTypeMessage      = "MSG"
)

// OPC UA Chunk Types
const (
	OPCUAChunkTypeFinal        = "F"
	OPCUAChunkTypeIntermediate = "C"
	OPCUAChunkTypeAbort        = "A"
)

// OPC UA Security Policy URIs
const (
	SecurityPolicyNone           = "http://opcfoundation.org/UA/SecurityPolicy#None"
	SecurityPolicyBasic128Rsa15  = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
	SecurityPolicyBasic256       = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
	SecurityPolicyBasic256Sha256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	SecurityPolicyAes128Sha256   = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
	SecurityPolicyAes256Sha256   = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
)

// OPC UA Security Modes
const (
	SecurityModeNone           = "None"
	SecurityModeSign           = "Sign"
	SecurityModeSignAndEncrypt = "SignAndEncrypt"
)

// OPC UA Service Types (Node IDs)
const (
	ServiceTypeCreateSession        uint32 = 461
	ServiceTypeActivateSession      uint32 = 467
	ServiceTypeCloseSession         uint32 = 473
	ServiceTypeCancel               uint32 = 479
	ServiceTypeBrowse               uint32 = 527
	ServiceTypeBrowseNext           uint32 = 533
	ServiceTypeTranslateBrowsePaths uint32 = 554
	ServiceTypeRegisterNodes        uint32 = 560
	ServiceTypeUnregisterNodes      uint32 = 566
	ServiceTypeRead                 uint32 = 631
	ServiceTypeHistoryRead          uint32 = 664
	ServiceTypeWrite                uint32 = 673
	ServiceTypeHistoryUpdate        uint32 = 679
	ServiceTypeCall                 uint32 = 712
	ServiceTypeCreateMonitoredItems uint32 = 751
	ServiceTypeModifyMonitoredItems uint32 = 763
	ServiceTypeSetMonitoringMode    uint32 = 769
	ServiceTypeSetTriggering        uint32 = 775
	ServiceTypeDeleteMonitoredItems uint32 = 781
	ServiceTypeCreateSubscription   uint32 = 787
	ServiceTypeModifySubscription   uint32 = 793
	ServiceTypeSetPublishingMode    uint32 = 799
	ServiceTypePublish              uint32 = 826
	ServiceTypeRepublish            uint32 = 829
	ServiceTypeTransferSubscription uint32 = 841
	ServiceTypeDeleteSubscription   uint32 = 847
)

// OPCUA represents an OPC UA packet following the OPC UA specification
// OPC UA Message Header Format:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    Message Type (3 bytes)     |C|         Message Size         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        Secure Channel ID                      |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type OPCUA struct {
	BaseLayer

	// OPC UA Header fields
	MessageType     string // Message type (HEL, ACK, OPN, MSG, etc.)
	ChunkType       string // Chunk type (F, C, A)
	MessageSize     uint32 // Total message size
	SecureChannelID uint32 // Secure channel identifier

	// Security and service-specific fields
	SecurityPolicy string // Security policy URI
	SecurityMode   string // Security mode (None, Sign, SignAndEncrypt)
	ServiceType    string // Service type name
	ServiceNodeID  uint32 // Service node ID

	// Client/Server identification
	ClientCertificate []byte   // Client certificate (if present)
	ServerCertificate []byte   // Server certificate (if present)
	ApplicationURI    string   // Application URI
	ProductURI        string   // Product URI
	ApplicationName   string   // Application name
	ApplicationType   string   // Application type (Server, Client, ClientAndServer, DiscoveryServer)
	GatewayServerURI  string   // Gateway server URI
	DiscoveryURLs     []string // Discovery profile URLs

	// Session and subscription information
	SessionID           []byte // Session identifier
	AuthenticationToken []byte // Authentication token
	SubscriptionID      uint32 // Subscription ID (for subscription services)
	PublishingEnabled   bool   // Publishing enabled flag
	RequestHandle       uint32 // Request handle

	// Communication patterns
	IsHandshake        bool // True if this is a handshake message (HEL/ACK)
	IsSessionMgmt      bool // True if this is session management
	IsSubscription     bool // True if this is subscription-related
	IsDataAccess       bool // True if this is data access (read/write)
	IsMethodCall       bool // True if this is method call
	IsBrowse           bool // True if this is browse operation
	IsSecurityExchange bool // True if this involves security token exchange

	// Additional parsed data
	EndpointURL       string                 // Endpoint URL
	RequestedLifetime uint32                 // Requested lifetime
	MaxMessageSize    uint32                 // Maximum message size
	MaxChunkCount     uint32                 // Maximum chunk count
	ConfigurationData map[string]interface{} // Additional configuration data
}

// LayerType returns the layer type for OPC UA
func (o *OPCUA) LayerType() gopacket.LayerType {
	return LayerTypeOPCUA
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (o *OPCUA) CanDecode() gopacket.LayerClass {
	return LayerTypeOPCUA
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (o *OPCUA) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer
func (o *OPCUA) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		return errors.New("OPC UA packet too short (minimum 8 bytes required)")
	}

	o.BaseLayer = BaseLayer{
		Contents: data,
		Payload:  nil,
	}

	// Initialize maps
	o.ConfigurationData = make(map[string]interface{})
	o.DiscoveryURLs = make([]string, 0)

	// Parse OPC UA header (8 bytes minimum)
	if len(data) >= 3 {
		o.MessageType = string(data[0:3])
	}
	if len(data) >= 4 {
		o.ChunkType = string(data[3:4])
	}
	if len(data) >= 8 {
		o.MessageSize = binary.LittleEndian.Uint32(data[4:8])
	}

	// Validate message size
	if int(o.MessageSize) > len(data) {
		return fmt.Errorf("OPC UA message size (%d) exceeds available data (%d)", o.MessageSize, len(data))
	}

	// Parse secure channel ID for most message types
	if len(data) >= 12 && o.MessageType != OPCUAMessageTypeHello && o.MessageType != OPCUAMessageTypeAcknowledge {
		o.SecureChannelID = binary.LittleEndian.Uint32(data[8:12])
	}

	// Parse message-specific data
	if err := o.parseMessageData(data); err != nil {
		// Don't fail completely on parsing errors, just log and continue
		o.ConfigurationData["parse_error"] = err.Error()
	}

	// Classify message type
	o.classifyMessage()

	return nil
}

// parseMessageData parses message-specific data based on message type
func (o *OPCUA) parseMessageData(data []byte) error {
	switch o.MessageType {
	case OPCUAMessageTypeHello:
		return o.parseHelloMessage(data)
	case OPCUAMessageTypeAcknowledge:
		return o.parseAcknowledgeMessage(data)
	case OPCUAMessageTypeOpenChannel:
		return o.parseOpenChannelMessage(data)
	case OPCUAMessageTypeMessage:
		return o.parseServiceMessage(data)
	case OPCUAMessageTypeError:
		return o.parseErrorMessage(data)
	default:
		// Unknown message type, store raw info
		o.ConfigurationData["raw_message_type"] = o.MessageType
	}
	return nil
}

// parseHelloMessage parses Hello message (client to server handshake)
func (o *OPCUA) parseHelloMessage(data []byte) error {
	if len(data) < 32 {
		return errors.New("Hello message too short")
	}

	offset := 8 // Skip header

	// Parse protocol version (4 bytes)
	protocolVersion := binary.LittleEndian.Uint32(data[offset : offset+4])
	o.ConfigurationData["protocol_version"] = protocolVersion
	offset += 4

	// Parse receive buffer size (4 bytes)
	receiveBufferSize := binary.LittleEndian.Uint32(data[offset : offset+4])
	o.ConfigurationData["receive_buffer_size"] = receiveBufferSize
	offset += 4

	// Parse send buffer size (4 bytes)
	sendBufferSize := binary.LittleEndian.Uint32(data[offset : offset+4])
	o.ConfigurationData["send_buffer_size"] = sendBufferSize
	offset += 4

	// Parse max message size (4 bytes)
	if len(data) >= offset+4 {
		o.MaxMessageSize = binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	// Parse max chunk count (4 bytes)
	if len(data) >= offset+4 {
		o.MaxChunkCount = binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	// Parse endpoint URL (string)
	if len(data) > offset+4 {
		urlLength := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		if len(data) >= offset+int(urlLength) && urlLength > 0 {
			o.EndpointURL = string(data[offset : offset+int(urlLength)])
		}
	}

	o.IsHandshake = true
	return nil
}

// parseAcknowledgeMessage parses Acknowledge message (server to client handshake response)
func (o *OPCUA) parseAcknowledgeMessage(data []byte) error {
	if len(data) < 28 {
		return errors.New("Acknowledge message too short")
	}

	offset := 8 // Skip header

	// Parse protocol version (4 bytes)
	protocolVersion := binary.LittleEndian.Uint32(data[offset : offset+4])
	o.ConfigurationData["protocol_version"] = protocolVersion
	offset += 4

	// Parse receive buffer size (4 bytes)
	receiveBufferSize := binary.LittleEndian.Uint32(data[offset : offset+4])
	o.ConfigurationData["receive_buffer_size"] = receiveBufferSize
	offset += 4

	// Parse send buffer size (4 bytes)
	sendBufferSize := binary.LittleEndian.Uint32(data[offset : offset+4])
	o.ConfigurationData["send_buffer_size"] = sendBufferSize
	offset += 4

	// Parse max message size (4 bytes)
	if len(data) >= offset+4 {
		o.MaxMessageSize = binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	// Parse max chunk count (4 bytes)
	if len(data) >= offset+4 {
		o.MaxChunkCount = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	o.IsHandshake = true
	return nil
}

// parseOpenChannelMessage parses OpenSecureChannel message
func (o *OPCUA) parseOpenChannelMessage(data []byte) error {
	if len(data) < 12 {
		return errors.New("OpenChannel message too short")
	}

	offset := 12 // Skip header + secure channel ID

	// Parse security policy URI
	if len(data) > offset+4 {
		policyLength := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		if len(data) >= offset+int(policyLength) && policyLength > 0 {
			o.SecurityPolicy = string(data[offset : offset+int(policyLength)])
			offset += int(policyLength)
		}
	}

	// Parse client certificate
	if len(data) > offset+4 {
		certLength := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		if len(data) >= offset+int(certLength) && certLength > 0 {
			o.ClientCertificate = make([]byte, certLength)
			copy(o.ClientCertificate, data[offset:offset+int(certLength)])
			offset += int(certLength)
		}
	}

	// Parse requested lifetime
	if len(data) >= offset+4 {
		o.RequestedLifetime = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	// Determine security mode from policy
	o.determineSecurityMode()
	o.IsSecurityExchange = true
	return nil
}

// parseServiceMessage parses service request/response messages
func (o *OPCUA) parseServiceMessage(data []byte) error {
	if len(data) < 16 {
		return errors.New("Service message too short")
	}

	offset := 12 // Skip header + secure channel ID

	// Parse service node ID (simplified - assumes numeric node ID)
	if len(data) >= offset+4 {
		o.ServiceNodeID = binary.LittleEndian.Uint32(data[offset : offset+4])
		o.ServiceType = o.getServiceTypeName(o.ServiceNodeID)
		offset += 4
	}

	// Parse request handle
	if len(data) >= offset+4 {
		o.RequestHandle = binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	// Parse service-specific data based on service type
	o.parseServiceSpecificData(data[offset:])
	o.classifyServiceType()

	return nil
}

// parseErrorMessage parses error messages
func (o *OPCUA) parseErrorMessage(data []byte) error {
	if len(data) < 12 {
		return errors.New("Error message too short")
	}

	offset := 8 // Skip header

	// Parse error code
	if len(data) >= offset+4 {
		errorCode := binary.LittleEndian.Uint32(data[offset : offset+4])
		o.ConfigurationData["error_code"] = errorCode
		offset += 4
	}

	// Parse reason string
	if len(data) > offset+4 {
		reasonLength := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		if len(data) >= offset+int(reasonLength) && reasonLength > 0 {
			reason := string(data[offset : offset+int(reasonLength)])
			o.ConfigurationData["error_reason"] = reason
		}
	}

	return nil
}

// parseServiceSpecificData parses data specific to different service types
func (o *OPCUA) parseServiceSpecificData(data []byte) {
	switch o.ServiceNodeID {
	case ServiceTypeCreateSubscription, ServiceTypeModifySubscription:
		o.parseSubscriptionData(data)
	case ServiceTypePublish:
		o.parsePublishData(data)
	case ServiceTypeRead, ServiceTypeWrite:
		o.parseDataAccessData(data)
	case ServiceTypeCall:
		o.parseMethodCallData(data)
	case ServiceTypeBrowse, ServiceTypeBrowseNext:
		o.parseBrowseData(data)
	case ServiceTypeCreateSession, ServiceTypeActivateSession, ServiceTypeCloseSession:
		o.parseSessionData(data)
	}
}

// parseSubscriptionData parses subscription-related service data
func (o *OPCUA) parseSubscriptionData(data []byte) {
	if len(data) >= 4 {
		o.SubscriptionID = binary.LittleEndian.Uint32(data[0:4])
	}
	if len(data) >= 8 {
		publishingInterval := binary.LittleEndian.Uint32(data[4:8])
		o.ConfigurationData["publishing_interval"] = publishingInterval
	}
	if len(data) >= 9 {
		o.PublishingEnabled = data[8] != 0
	}
}

// parsePublishData parses publish service data
func (o *OPCUA) parsePublishData(data []byte) {
	if len(data) >= 4 {
		subscriptionAckCount := binary.LittleEndian.Uint32(data[0:4])
		o.ConfigurationData["subscription_ack_count"] = subscriptionAckCount
	}
}

// parseDataAccessData parses read/write service data
func (o *OPCUA) parseDataAccessData(data []byte) {
	if len(data) >= 4 {
		nodeCount := binary.LittleEndian.Uint32(data[0:4])
		o.ConfigurationData["node_count"] = nodeCount
	}
}

// parseMethodCallData parses method call service data
func (o *OPCUA) parseMethodCallData(data []byte) {
	if len(data) >= 4 {
		methodCount := binary.LittleEndian.Uint32(data[0:4])
		o.ConfigurationData["method_count"] = methodCount
	}
}

// parseBrowseData parses browse service data
func (o *OPCUA) parseBrowseData(data []byte) {
	if len(data) >= 4 {
		maxReferencesPerNode := binary.LittleEndian.Uint32(data[0:4])
		o.ConfigurationData["max_references_per_node"] = maxReferencesPerNode
	}
}

// parseSessionData parses session management data
func (o *OPCUA) parseSessionData(data []byte) {
	// Parse session ID if present (simplified)
	if len(data) >= 16 {
		o.SessionID = make([]byte, 16)
		copy(o.SessionID, data[0:16])
	}
}

// classifyMessage classifies the message type and sets appropriate flags
func (o *OPCUA) classifyMessage() {
	switch o.MessageType {
	case OPCUAMessageTypeHello, OPCUAMessageTypeAcknowledge:
		o.IsHandshake = true
	case OPCUAMessageTypeOpenChannel, OPCUAMessageTypeCloseChannel:
		o.IsSecurityExchange = true
	case OPCUAMessageTypeMessage:
		// Further classification based on service type
		o.classifyServiceType()
	}
}

// classifyServiceType classifies service messages into categories
func (o *OPCUA) classifyServiceType() {
	switch o.ServiceNodeID {
	case ServiceTypeCreateSession, ServiceTypeActivateSession, ServiceTypeCloseSession:
		o.IsSessionMgmt = true
	case ServiceTypeCreateSubscription, ServiceTypeModifySubscription, ServiceTypeDeleteSubscription,
		ServiceTypePublish, ServiceTypeRepublish, ServiceTypeSetPublishingMode:
		o.IsSubscription = true
	case ServiceTypeRead, ServiceTypeWrite, ServiceTypeHistoryRead, ServiceTypeHistoryUpdate:
		o.IsDataAccess = true
	case ServiceTypeCall:
		o.IsMethodCall = true
	case ServiceTypeBrowse, ServiceTypeBrowseNext, ServiceTypeTranslateBrowsePaths:
		o.IsBrowse = true
	}
}

// determineSecurityMode determines security mode from security policy
func (o *OPCUA) determineSecurityMode() {
	switch o.SecurityPolicy {
	case SecurityPolicyNone:
		o.SecurityMode = SecurityModeNone
	case SecurityPolicyBasic128Rsa15, SecurityPolicyBasic256:
		// These policies typically use Sign mode
		o.SecurityMode = SecurityModeSign
	case SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256, SecurityPolicyAes256Sha256:
		// These policies typically use SignAndEncrypt mode
		o.SecurityMode = SecurityModeSignAndEncrypt
	default:
		if o.SecurityPolicy != "" {
			o.SecurityMode = SecurityModeSign // Default assumption for unknown policies
		} else {
			o.SecurityMode = SecurityModeNone
		}
	}
}

// getServiceTypeName returns a human-readable service type name
func (o *OPCUA) getServiceTypeName(nodeID uint32) string {
	switch nodeID {
	case ServiceTypeCreateSession:
		return "CreateSession"
	case ServiceTypeActivateSession:
		return "ActivateSession"
	case ServiceTypeCloseSession:
		return "CloseSession"
	case ServiceTypeCancel:
		return "Cancel"
	case ServiceTypeBrowse:
		return "Browse"
	case ServiceTypeBrowseNext:
		return "BrowseNext"
	case ServiceTypeTranslateBrowsePaths:
		return "TranslateBrowsePaths"
	case ServiceTypeRegisterNodes:
		return "RegisterNodes"
	case ServiceTypeUnregisterNodes:
		return "UnregisterNodes"
	case ServiceTypeRead:
		return "Read"
	case ServiceTypeHistoryRead:
		return "HistoryRead"
	case ServiceTypeWrite:
		return "Write"
	case ServiceTypeHistoryUpdate:
		return "HistoryUpdate"
	case ServiceTypeCall:
		return "Call"
	case ServiceTypeCreateMonitoredItems:
		return "CreateMonitoredItems"
	case ServiceTypeModifyMonitoredItems:
		return "ModifyMonitoredItems"
	case ServiceTypeSetMonitoringMode:
		return "SetMonitoringMode"
	case ServiceTypeSetTriggering:
		return "SetTriggering"
	case ServiceTypeDeleteMonitoredItems:
		return "DeleteMonitoredItems"
	case ServiceTypeCreateSubscription:
		return "CreateSubscription"
	case ServiceTypeModifySubscription:
		return "ModifySubscription"
	case ServiceTypeSetPublishingMode:
		return "SetPublishingMode"
	case ServiceTypePublish:
		return "Publish"
	case ServiceTypeRepublish:
		return "Republish"
	case ServiceTypeTransferSubscription:
		return "TransferSubscription"
	case ServiceTypeDeleteSubscription:
		return "DeleteSubscription"
	default:
		return fmt.Sprintf("Unknown(%d)", nodeID)
	}
}

// String returns a string representation of the OPC UA packet
func (o *OPCUA) String() string {
	if o.ServiceType != "" && o.ServiceType != "Unknown" {
		return fmt.Sprintf("OPC UA %s %s (Service: %s)", o.MessageType, o.ChunkType, o.ServiceType)
	}
	return fmt.Sprintf("OPC UA %s %s", o.MessageType, o.ChunkType)
}

// GetSecurityInfo returns security-related information
func (o *OPCUA) GetSecurityInfo() map[string]interface{} {
	security := make(map[string]interface{})

	if o.SecurityPolicy != "" {
		security["policy"] = o.SecurityPolicy
		security["policy_name"] = o.getSecurityPolicyName()
	}
	if o.SecurityMode != "" {
		security["mode"] = o.SecurityMode
	}
	if len(o.ClientCertificate) > 0 {
		security["has_client_cert"] = true
		security["client_cert_size"] = len(o.ClientCertificate)
	}
	if len(o.ServerCertificate) > 0 {
		security["has_server_cert"] = true
		security["server_cert_size"] = len(o.ServerCertificate)
	}
	if o.RequestedLifetime > 0 {
		security["requested_lifetime"] = o.RequestedLifetime
	}

	return security
}

// getSecurityPolicyName returns a human-readable security policy name
func (o *OPCUA) getSecurityPolicyName() string {
	switch o.SecurityPolicy {
	case SecurityPolicyNone:
		return "None"
	case SecurityPolicyBasic128Rsa15:
		return "Basic128Rsa15"
	case SecurityPolicyBasic256:
		return "Basic256"
	case SecurityPolicyBasic256Sha256:
		return "Basic256Sha256"
	case SecurityPolicyAes128Sha256:
		return "Aes128Sha256"
	case SecurityPolicyAes256Sha256:
		return "Aes256Sha256"
	default:
		return "Custom"
	}
}

// GetServiceInfo returns service call information
func (o *OPCUA) GetServiceInfo() map[string]interface{} {
	service := make(map[string]interface{})

	if o.ServiceType != "" {
		service["type"] = o.ServiceType
		service["node_id"] = o.ServiceNodeID
	}
	if o.RequestHandle > 0 {
		service["request_handle"] = o.RequestHandle
	}
	if o.SubscriptionID > 0 {
		service["subscription_id"] = o.SubscriptionID
	}
	if len(o.SessionID) > 0 {
		service["has_session_id"] = true
	}

	service["is_session_mgmt"] = o.IsSessionMgmt
	service["is_subscription"] = o.IsSubscription
	service["is_data_access"] = o.IsDataAccess
	service["is_method_call"] = o.IsMethodCall
	service["is_browse"] = o.IsBrowse

	return service
}

// IsClientConnection returns true if this appears to be a client-initiated connection
func (o *OPCUA) IsClientConnection() bool {
	return o.MessageType == OPCUAMessageTypeHello ||
		(o.IsSessionMgmt && o.ServiceType == "CreateSession") ||
		(o.IsSubscription && o.ServiceType == "CreateSubscription")
}

// IsServerResponse returns true if this appears to be a server response
func (o *OPCUA) IsServerResponse() bool {
	return o.MessageType == OPCUAMessageTypeAcknowledge ||
		(o.IsDataAccess && o.ServiceType == "Read") ||
		(o.IsSubscription && o.ServiceType == "Publish")
}

// IsRealTimeData returns true if this is real-time data exchange
func (o *OPCUA) IsRealTimeData() bool {
	return o.IsSubscription && (o.ServiceType == "Publish" || o.ServiceType == "CreateMonitoredItems")
}

// IsSecure returns true if the connection uses security
func (o *OPCUA) IsSecure() bool {
	return o.SecurityMode != SecurityModeNone && o.SecurityPolicy != SecurityPolicyNone
}

// LayerTypeOPCUA is the layer type for OPC UA packets
var LayerTypeOPCUA = gopacket.RegisterLayerType(
	1005, // Layer type number - using a high number to avoid conflicts
	gopacket.LayerTypeMetadata{
		Name:    "OPCUA",
		Decoder: gopacket.DecodeFunc(decodeOPCUA),
	},
)

// decodeOPCUA is the decoder function for OPC UA packets
func decodeOPCUA(data []byte, p gopacket.PacketBuilder) error {
	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(opcua)
	return p.NextDecoder(opcua.NextLayerType())
}

// RegisterOPCUA registers the OPC UA protocol with common TCP ports
func RegisterOPCUA() {
	// Register OPC UA on standard port
	layers.RegisterTCPPortLayerType(4840, LayerTypeOPCUA) // TCP port 4840
}

// InitLayerOPCUA initializes the OPC UA layer for gopacket
func InitLayerOPCUA() {
	RegisterOPCUA()
}

// Validate performs comprehensive validation of the OPC UA packet
func (o *OPCUA) Validate() error {
	if err := o.validateHeader(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}

	if err := o.validateSecurityInfo(); err != nil {
		return fmt.Errorf("security info validation failed: %w", err)
	}

	if err := o.validateServiceInfo(); err != nil {
		return fmt.Errorf("service info validation failed: %w", err)
	}

	return nil
}

// validateHeader validates the OPC UA message header
func (o *OPCUA) validateHeader() error {
	// Validate message type
	validMessageTypes := map[string]bool{
		OPCUAMessageTypeHello:        true,
		OPCUAMessageTypeAcknowledge:  true,
		OPCUAMessageTypeError:        true,
		OPCUAMessageTypeReverseHello: true,
		OPCUAMessageTypeOpenChannel:  true,
		OPCUAMessageTypeCloseChannel: true,
		OPCUAMessageTypeMessage:      true,
	}

	if !validMessageTypes[o.MessageType] {
		return fmt.Errorf("invalid message type: %s", o.MessageType)
	}

	// Validate chunk type
	validChunkTypes := map[string]bool{
		OPCUAChunkTypeFinal:        true,
		OPCUAChunkTypeIntermediate: true,
		OPCUAChunkTypeAbort:        true,
	}

	if o.ChunkType != "" && !validChunkTypes[o.ChunkType] {
		return fmt.Errorf("invalid chunk type: %s", o.ChunkType)
	}

	// Validate message size (should be reasonable)
	const maxReasonableSize = 16 * 1024 * 1024 // 16MB max
	if o.MessageSize > maxReasonableSize {
		return fmt.Errorf("message size too large: %d", o.MessageSize)
	}

	// Message size should not be zero for valid messages
	if o.MessageSize == 0 {
		return fmt.Errorf("message size cannot be zero")
	}

	return nil
}

// validateSecurityInfo validates OPC UA security information
func (o *OPCUA) validateSecurityInfo() error {
	// Validate security policy if present
	if o.SecurityPolicy != "" {
		validPolicies := map[string]bool{
			SecurityPolicyNone:           true,
			SecurityPolicyBasic128Rsa15:  true,
			SecurityPolicyBasic256:       true,
			SecurityPolicyBasic256Sha256: true,
			SecurityPolicyAes128Sha256:   true,
			SecurityPolicyAes256Sha256:   true,
		}

		if !validPolicies[o.SecurityPolicy] {
			// Not necessarily an error, might be a custom policy
			if o.ConfigurationData == nil {
				o.ConfigurationData = make(map[string]interface{})
			}
			o.ConfigurationData["unknown_security_policy"] = o.SecurityPolicy
		}
	}

	// Validate security mode if present
	if o.SecurityMode != "" {
		validModes := map[string]bool{
			SecurityModeNone:           true,
			SecurityModeSign:           true,
			SecurityModeSignAndEncrypt: true,
		}

		if !validModes[o.SecurityMode] {
			return fmt.Errorf("invalid security mode: %s", o.SecurityMode)
		}
	}

	return nil
}

// validateServiceInfo validates OPC UA service information
func (o *OPCUA) validateServiceInfo() error {
	// Validate service type if present
	if o.ServiceType != "" {
		// Common OPC UA service types - not exhaustive, but covers main ones
		knownServices := map[string]bool{
			"CreateSession":         true,
			"ActivateSession":       true,
			"CloseSession":          true,
			"CreateSubscription":    true,
			"DeleteSubscription":    true,
			"CreateMonitoredItems":  true,
			"DeleteMonitoredItems":  true,
			"ModifyMonitoredItems":  true,
			"SetMonitoringMode":     true,
			"Publish":               true,
			"Republish":             true,
			"TransferSubscriptions": true,
			"Browse":                true,
			"BrowseNext":            true,
			"Read":                  true,
			"Write":                 true,
			"Call":                  true,
			"GetEndpoints":          true,
			"FindServers":           true,
			"RegisterServer":        true,
			"RegisterServer2":       true,
		}

		if !knownServices[o.ServiceType] {
			// Not an error, might be a vendor-specific service
			if o.ConfigurationData == nil {
				o.ConfigurationData = make(map[string]interface{})
			}
			o.ConfigurationData["unknown_service_type"] = o.ServiceType
		}
	}

	// Validate service node ID if present
	if o.ServiceNodeID > 0 {
		// Check if it's a known service node ID
		knownServiceNodeIDs := map[uint32]bool{
			ServiceTypeCreateSession:        true,
			ServiceTypeActivateSession:      true,
			ServiceTypeCloseSession:         true,
			ServiceTypeBrowse:               true,
			ServiceTypeBrowseNext:           true,
			ServiceTypeRead:                 true,
			ServiceTypeWrite:                true,
			ServiceTypeCall:                 true,
			ServiceTypeCreateSubscription:   true,
			ServiceTypeModifySubscription:   true,
			ServiceTypeDeleteSubscription:   true,
			ServiceTypeCreateMonitoredItems: true,
			ServiceTypeModifyMonitoredItems: true,
			ServiceTypeDeleteMonitoredItems: true,
			ServiceTypePublish:              true,
			ServiceTypeRepublish:            true,
		}

		if !knownServiceNodeIDs[o.ServiceNodeID] {
			// Not necessarily an error, might be a vendor-specific service
			if o.ConfigurationData == nil {
				o.ConfigurationData = make(map[string]interface{})
			}
			o.ConfigurationData["unknown_service_node_id"] = o.ServiceNodeID
		}
	}

	return nil
}

// IsValidForClassification returns true if the packet contains sufficient information for device classification
func (o *OPCUA) IsValidForClassification() bool {
	// Must have valid message type
	if o.MessageType == "" {
		return false
	}

	// Error messages are less useful for classification
	if o.MessageType == OPCUAMessageTypeError {
		return false
	}

	// For classification, we need either security info, service info, or endpoint info
	hasSecurityInfo := o.SecurityPolicy != "" || o.SecurityMode != ""
	hasServiceInfo := o.ServiceType != "" || o.ServiceNodeID > 0
	hasEndpointInfo := o.EndpointURL != "" || o.ApplicationName != ""

	return hasSecurityInfo || hasServiceInfo || hasEndpointInfo
}

// ExtractSecurityInfo safely extracts security-related information
func (o *OPCUA) ExtractSecurityInfo() map[string]interface{} {
	security := make(map[string]interface{})

	// Extract security policy
	if o.SecurityPolicy != "" {
		security["security_policy"] = o.SecurityPolicy
	}

	// Extract security mode
	if o.SecurityMode != "" {
		security["security_mode"] = o.SecurityMode
	}

	// Extract secure channel information
	if o.SecureChannelID > 0 {
		security["secure_channel_id"] = o.SecureChannelID
	}

	// Extract session information
	if len(o.SessionID) > 0 {
		security["has_session"] = true
	}

	if len(o.AuthenticationToken) > 0 {
		security["has_auth_token"] = true
	}

	// Determine security level based on policy and mode
	securityLevel := "none"
	if o.SecurityPolicy != "" && o.SecurityPolicy != SecurityPolicyNone {
		securityLevel = "basic"
		if o.SecurityMode == SecurityModeSignAndEncrypt {
			securityLevel = "high"
		} else if o.SecurityMode == SecurityModeSign {
			securityLevel = "medium"
		}
	}
	security["security_level"] = securityLevel

	// Include any additional security-related data
	if o.ConfigurationData != nil {
		for k, v := range o.ConfigurationData {
			if strings.Contains(strings.ToLower(k), "security") ||
				strings.Contains(strings.ToLower(k), "auth") ||
				strings.Contains(strings.ToLower(k), "encrypt") ||
				strings.Contains(strings.ToLower(k), "sign") {
				security[k] = v
			}
		}
	}

	return security
}

// ExtractServiceInfo safely extracts service-related information
func (o *OPCUA) ExtractServiceInfo() map[string]interface{} {
	service := make(map[string]interface{})

	// Extract service type
	if o.ServiceType != "" {
		service["service_type"] = o.ServiceType
	}

	// Extract service node ID
	if o.ServiceNodeID > 0 {
		service["service_node_id"] = o.ServiceNodeID
	}

	// Extract endpoint information
	if o.EndpointURL != "" {
		service["endpoint_url"] = o.EndpointURL
	}

	if o.ApplicationName != "" {
		service["application_name"] = o.ApplicationName
	}

	if o.ApplicationURI != "" {
		service["application_uri"] = o.ApplicationURI
	}

	if o.ProductURI != "" {
		service["product_uri"] = o.ProductURI
	}

	// Extract session information
	if len(o.SessionID) > 0 {
		service["has_session"] = true
	}

	if o.SubscriptionID > 0 {
		service["subscription_id"] = o.SubscriptionID
	}

	if o.RequestHandle > 0 {
		service["request_handle"] = o.RequestHandle
	}

	// Extract communication patterns
	service["is_handshake"] = o.IsHandshake
	service["is_session_mgmt"] = o.IsSessionMgmt
	service["is_subscription"] = o.IsSubscription
	service["is_data_access"] = o.IsDataAccess
	service["is_method_call"] = o.IsMethodCall
	service["is_browse"] = o.IsBrowse
	service["is_security_exchange"] = o.IsSecurityExchange

	// Include any additional service-related data
	if o.ConfigurationData != nil {
		for k, v := range o.ConfigurationData {
			service[k] = v
		}
	}

	return service
}

// ExtractDeviceIdentityInfo safely extracts device identity information
func (o *OPCUA) ExtractDeviceIdentityInfo() map[string]interface{} {
	identity := make(map[string]interface{})

	// Extract application information
	if o.ApplicationName != "" {
		identity["application_name"] = o.ApplicationName
	}

	if o.ApplicationURI != "" {
		identity["application_uri"] = o.ApplicationURI
	}

	if o.ProductURI != "" {
		identity["product_uri"] = o.ProductURI
	}

	if o.ApplicationType != "" {
		identity["application_type"] = o.ApplicationType
	}

	// Extract endpoint information
	if o.EndpointURL != "" {
		identity["endpoint_url"] = o.EndpointURL
	}

	if o.GatewayServerURI != "" {
		identity["gateway_server_uri"] = o.GatewayServerURI
	}

	if len(o.DiscoveryURLs) > 0 {
		identity["discovery_urls"] = o.DiscoveryURLs
	}

	// Include server/client role based on message patterns
	if o.ServiceType != "" {
		// Determine role based on service patterns
		serverServices := map[string]bool{
			"GetEndpoints":    true,
			"FindServers":     true,
			"RegisterServer":  true,
			"RegisterServer2": true,
		}

		clientServices := map[string]bool{
			"CreateSession":      true,
			"ActivateSession":    true,
			"CreateSubscription": true,
			"Browse":             true,
			"Read":               true,
			"Write":              true,
		}

		if serverServices[o.ServiceType] {
			identity["inferred_role"] = "server"
		} else if clientServices[o.ServiceType] {
			identity["inferred_role"] = "client"
		}
	}

	// Infer role from application type
	if o.ApplicationType != "" {
		switch o.ApplicationType {
		case "Server":
			identity["inferred_role"] = "server"
		case "Client":
			identity["inferred_role"] = "client"
		case "ClientAndServer":
			identity["inferred_role"] = "client_and_server"
		case "DiscoveryServer":
			identity["inferred_role"] = "discovery_server"
		}
	}

	return identity
}
