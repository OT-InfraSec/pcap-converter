package parser

import (
	"errors"
	"fmt"
	"time"

	lib_layers "github.com/InfraSecConsult/pcap-importer-go/lib/layers"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// IndustrialProtocolInfo represents information extracted from industrial protocol packets
type IndustrialProtocolInfo struct {
	Protocol        string                 `json:"protocol"`         // Protocol name (e.g., "ethernetip", "opcua")
	Port            uint16                 `json:"port"`             // Port number used
	Direction       string                 `json:"direction"`        // "inbound", "outbound", "bidirectional"
	DeviceIdentity  map[string]interface{} `json:"device_identity"`  // Device identity information
	SecurityInfo    map[string]interface{} `json:"security_info"`    // Security-related information
	ServiceType     string                 `json:"service_type"`     // Type of service/operation
	MessageType     string                 `json:"message_type"`     // Message type (e.g., "discovery", "data_transfer")
	IsRealTimeData  bool                   `json:"is_real_time"`     // True if real-time I/O data
	IsDiscovery     bool                   `json:"is_discovery"`     // True if discovery message
	IsConfiguration bool                   `json:"is_configuration"` // True if configuration message
	Confidence      float64                `json:"confidence"`       // Confidence level (0.0-1.0)
	Timestamp       time.Time              `json:"timestamp"`        // Packet timestamp
	AdditionalData  map[string]interface{} `json:"additional_data"`  // Protocol-specific additional data
}

// IndustrialProtocolParser defines the interface for parsing industrial protocols
type IndustrialProtocolParser interface {
	// ParseIndustrialProtocols analyzes a packet for industrial protocol information
	ParseIndustrialProtocols(packet gopacket.Packet) ([]IndustrialProtocolInfo, error)

	// DetectDeviceType determines device type based on protocol usage patterns
	DetectDeviceType(protocols []IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType

	// AnalyzeCommunicationPatterns analyzes communication patterns between devices
	AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern

	// GetSupportedProtocols returns a list of supported industrial protocols
	GetSupportedProtocols() []string

	// IsIndustrialProtocol checks if a packet contains industrial protocol data
	IsIndustrialProtocol(packet gopacket.Packet) bool

	// CollectProtocolUsageStats collects protocol usage statistics from industrial protocol information
	CollectProtocolUsageStats(deviceAddress string, protocols []IndustrialProtocolInfo) (*model.ProtocolUsageStats, error)

	// UpdateProtocolUsageStats updates existing protocol usage statistics with new data
	UpdateProtocolUsageStats(existing *model.ProtocolUsageStats, protocols []IndustrialProtocolInfo) (*model.ProtocolUsageStats, error)

	// AggregateProtocolUsageStats aggregates multiple protocol usage statistics
	AggregateProtocolUsageStats(statsList []*model.ProtocolUsageStats) (*model.ProtocolUsageStats, error)

	// SetErrorHandler sets the error handler for the parser
	SetErrorHandler(handler ErrorHandler)

	// GetErrorHandler returns the current error handler
	GetErrorHandler() ErrorHandler
}

// IndustrialProtocolParserImpl implements the IndustrialProtocolParser interface
type IndustrialProtocolParserImpl struct {
	// Configuration options
	enableEtherNetIP    bool
	enableOPCUA         bool
	confidenceThreshold float64
	// Error handling
	errorHandler ErrorHandler
}

// SetErrorHandler sets the error handler for the parser
func (p *IndustrialProtocolParserImpl) SetErrorHandler(handler ErrorHandler) {
	if handler != nil {
		p.errorHandler = handler
	}
}

// GetErrorHandler returns the current error handler
func (p *IndustrialProtocolParserImpl) GetErrorHandler() ErrorHandler {
	return p.errorHandler
}

// NewIndustrialProtocolParser creates a new industrial protocol parser
func NewIndustrialProtocolParser() IndustrialProtocolParser {
	return &IndustrialProtocolParserImpl{
		enableEtherNetIP:    true,
		enableOPCUA:         true,
		confidenceThreshold: 0.7, // Default confidence threshold
		errorHandler:        NewDefaultErrorHandler(nil),
	}
}

// NewIndustrialProtocolParserWithErrorHandler creates a new industrial protocol parser with custom error handler
func NewIndustrialProtocolParserWithErrorHandler(errorHandler ErrorHandler) IndustrialProtocolParser {
	return &IndustrialProtocolParserImpl{
		enableEtherNetIP:    true,
		enableOPCUA:         true,
		confidenceThreshold: 0.7,
		errorHandler:        errorHandler,
	}
}

// ParseIndustrialProtocols analyzes a packet for industrial protocol information
func (p *IndustrialProtocolParserImpl) ParseIndustrialProtocols(packet gopacket.Packet) ([]IndustrialProtocolInfo, error) {
	var protocols []IndustrialProtocolInfo

	// Validate packet first
	if packet == nil {
		err := NewParsingError("unknown", packet, fmt.Errorf("packet is nil"), "packet validation", false)
		if handleErr := p.errorHandler.HandleProtocolError(err); handleErr != nil {
			return nil, handleErr
		}
		return protocols, nil
	}

	timestamp := packet.Metadata().Timestamp

	// Check if error threshold has been exceeded
	if p.errorHandler.IsErrorThresholdExceeded() {
		return nil, fmt.Errorf("error threshold exceeded, stopping protocol parsing")
	}

	// Check for EtherNet/IP protocol
	if p.enableEtherNetIP {
		ethernetIPInfo, err := p.parseEtherNetIPWithErrorHandling(packet, timestamp)
		if err != nil {
			// Handle the error but continue processing
			if handleErr := p.errorHandler.HandleProtocolError(err); handleErr != nil {
				return protocols, handleErr // Stop processing if error handler says so
			}
		} else if ethernetIPInfo != nil {
			protocols = append(protocols, *ethernetIPInfo)
		}
	}

	// Check for OPC UA protocol
	if p.enableOPCUA {
		opcuaInfo, err := p.parseOPCUAWithErrorHandling(packet, timestamp)
		if err != nil {
			// Handle the error but continue processing
			if handleErr := p.errorHandler.HandleProtocolError(err); handleErr != nil {
				return protocols, handleErr // Stop processing if error handler says so
			}
		} else if opcuaInfo != nil {
			protocols = append(protocols, *opcuaInfo)
		}
	}

	return protocols, nil
}

// DetectDeviceType determines device type based on protocol usage patterns
func (p *IndustrialProtocolParserImpl) DetectDeviceType(protocols []IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType {
	if len(protocols) == 0 {
		return model.DeviceTypeUnknown
	}

	// Add error handling for device classification
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic during device type detection: %v", r)
			p.errorHandler.HandleClassificationError("unknown", err)
		}
	}()

	// Count protocol usage patterns
	ethernetIPCount := 0
	opcuaClientCount := 0
	opcuaServerCount := 0
	realTimeDataCount := 0
	discoveryCount := 0

	for _, protocol := range protocols {
		switch protocol.Protocol {
		case "ethernetip":
			ethernetIPCount++
			if protocol.IsRealTimeData {
				realTimeDataCount++
			}
		case "opcua":
			if protocol.Direction == "outbound" {
				opcuaClientCount++
			} else if protocol.Direction == "inbound" {
				opcuaServerCount++
			}
		}
		if protocol.IsDiscovery {
			discoveryCount++
		}
	}

	// Classification logic based on protocol usage patterns
	if ethernetIPCount > 0 && realTimeDataCount > 0 {
		// Device using EtherNet/IP with real-time data suggests I/O device or PLC
		if opcuaServerCount > 0 {
			return model.DeviceTypePLC // PLC often serves both EtherNet/IP I/O and OPC UA
		}
		return model.DeviceTypeIODevice
	}

	if opcuaClientCount > 0 && opcuaServerCount == 0 {
		// Pure OPC UA client suggests HMI or engineering workstation
		if discoveryCount > 0 {
			return model.DeviceTypeEngWorkstation // Engineering tools often do discovery
		}
		return model.DeviceTypeHMI
	}

	if opcuaServerCount > 0 {
		// OPC UA server suggests PLC, historian, or SCADA server
		if ethernetIPCount > 0 {
			return model.DeviceTypePLC // Dual protocol suggests PLC
		}
		return model.DeviceTypeHistorian // Pure OPC UA server often historian
	}

	if ethernetIPCount > 0 {
		// EtherNet/IP without real-time data suggests controller
		return model.DeviceTypePLC
	}

	return model.DeviceTypeUnknown
}

// AnalyzeCommunicationPatterns analyzes communication patterns between devices
func (p *IndustrialProtocolParserImpl) AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern {
	var patterns []model.CommunicationPattern

	for _, flow := range flows {
		// Skip non-industrial protocols
		if !p.isIndustrialProtocol(flow.Protocol) {
			continue
		}

		pattern := model.CommunicationPattern{
			SourceDevice:      flow.Source,
			DestinationDevice: flow.Destination,
			Protocol:          flow.Protocol,
			DataVolume:        int64(flow.Bytes),
		}

		// Determine pattern type based on flow characteristics
		duration := flow.LastSeen.Sub(flow.FirstSeen)
		if duration > 0 {
			pattern.Frequency = duration / time.Duration(flow.Packets)
		}

		// Classify pattern type
		if pattern.Frequency > 0 && pattern.Frequency < time.Second {
			pattern.PatternType = "continuous"
			pattern.Criticality = "high"
		} else if pattern.Frequency >= time.Second && pattern.Frequency < time.Minute {
			pattern.PatternType = "periodic"
			pattern.Criticality = "medium"
		} else {
			pattern.PatternType = "event-driven"
			pattern.Criticality = "low"
		}

		// Adjust criticality based on protocol and data volume
		if flow.Protocol == "ethernetip" && pattern.DataVolume > 1000 {
			pattern.Criticality = "critical"
		}

		patterns = append(patterns, pattern)
	}

	return patterns
}

// GetSupportedProtocols returns a list of supported industrial protocols
func (p *IndustrialProtocolParserImpl) GetSupportedProtocols() []string {
	var protocols []string
	if p.enableEtherNetIP {
		protocols = append(protocols, "ethernetip")
	}
	if p.enableOPCUA {
		protocols = append(protocols, "opcua")
	}
	return protocols
}

// IsIndustrialProtocol checks if a packet contains industrial protocol data
func (p *IndustrialProtocolParserImpl) IsIndustrialProtocol(packet gopacket.Packet) bool {
	// Check for industrial protocol layers
	if p.enableEtherNetIP && p.hasEtherNetIPLayer(packet) {
		return true
	}
	if p.enableOPCUA && p.hasOPCUALayer(packet) {
		return true
	}

	// Check for industrial protocol ports
	return p.hasIndustrialPorts(packet)
}

// Helper methods for protocol detection and parsing

// parseEtherNetIP parses EtherNet/IP protocol information from a packet
func (p *IndustrialProtocolParserImpl) parseEtherNetIP(packet gopacket.Packet, timestamp time.Time) *IndustrialProtocolInfo {
	// Check if packet has EtherNet/IP layer or uses EtherNet/IP ports
	if !p.hasEtherNetIPLayer(packet) && !p.hasEtherNetIPPorts(packet) {
		return nil
	}

	info := &IndustrialProtocolInfo{
		Protocol:       "ethernetip",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
		Confidence:     0.8, // Default confidence for EtherNet/IP detection
	}

	// Try to get EtherNet/IP layer for detailed parsing
	if ethernetIPLayer := p.getEtherNetIPLayer(packet); ethernetIPLayer != nil {
		info.Confidence = 1.0 // High confidence when layer is present

		// Extract device identity information
		deviceIdentity := ethernetIPLayer.GetDeviceIdentity()
		for k, v := range deviceIdentity {
			info.DeviceIdentity[k] = v
		}

		// Extract CIP information
		cipInfo := ethernetIPLayer.GetCIPInfo()
		for k, v := range cipInfo {
			info.AdditionalData[k] = v
		}

		// Determine message characteristics
		info.IsDiscovery = ethernetIPLayer.IsDiscoveryMessage()
		info.IsRealTimeData = ethernetIPLayer.IsImplicitMsg
		info.IsConfiguration = ethernetIPLayer.IsExplicitMsg

		// Set message type
		if info.IsDiscovery {
			info.MessageType = "discovery"
		} else if info.IsRealTimeData {
			info.MessageType = "real_time_io"
		} else if info.IsConfiguration {
			info.MessageType = "configuration"
		} else {
			info.MessageType = "data_transfer"
		}

		// Extract service type from CIP info
		if serviceName, ok := cipInfo["service_name"].(string); ok {
			info.ServiceType = serviceName
		}
	} else {
		// Port-based detection only
		info.Confidence = 0.6
		info.MessageType = "unknown"

		// Extract port information
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if uint16(tcp.DstPort) == 44818 || uint16(tcp.SrcPort) == 44818 {
				info.Port = 44818
				info.AdditionalData["transport"] = "tcp"
			}
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if uint16(udp.DstPort) == 2222 || uint16(udp.SrcPort) == 2222 {
				info.Port = 2222
				info.AdditionalData["transport"] = "udp"
			}
		}
	}

	// Determine direction based on port usage
	info.Direction = p.determineDirection(packet, []uint16{44818, 2222})

	return info
}

// parseOPCUA parses OPC UA protocol information from a packet
func (p *IndustrialProtocolParserImpl) parseOPCUA(packet gopacket.Packet, timestamp time.Time) *IndustrialProtocolInfo {
	// Check if packet has OPC UA layer or uses OPC UA ports
	if !p.hasOPCUALayer(packet) && !p.hasOPCUAPorts(packet) {
		return nil
	}

	info := &IndustrialProtocolInfo{
		Protocol:       "opcua",
		Port:           4840,
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
		Confidence:     0.8, // Default confidence for OPC UA detection
	}

	// Try to get OPC UA layer for detailed parsing
	if opcuaLayer := p.getOPCUALayer(packet); opcuaLayer != nil {
		info.Confidence = 1.0 // High confidence when layer is present

		// Extract security information
		securityInfo := opcuaLayer.GetSecurityInfo()
		for k, v := range securityInfo {
			info.SecurityInfo[k] = v
		}

		// Extract service information
		serviceInfo := opcuaLayer.GetServiceInfo()
		for k, v := range serviceInfo {
			info.AdditionalData[k] = v
		}

		// Determine message characteristics
		info.IsDiscovery = opcuaLayer.IsHandshake
		info.IsRealTimeData = opcuaLayer.IsRealTimeData()
		info.IsConfiguration = opcuaLayer.IsSessionMgmt

		// Set message type
		if info.IsDiscovery {
			info.MessageType = "handshake"
		} else if info.IsRealTimeData {
			info.MessageType = "subscription_data"
		} else if info.IsConfiguration {
			info.MessageType = "session_management"
		} else {
			info.MessageType = "service_call"
		}

		// Extract service type
		if opcuaLayer.ServiceType != "" {
			info.ServiceType = opcuaLayer.ServiceType
		}

		// Store message type and security mode
		info.AdditionalData["message_type"] = opcuaLayer.MessageType
		info.AdditionalData["chunk_type"] = opcuaLayer.ChunkType
		if opcuaLayer.SecurityMode != "" {
			info.AdditionalData["security_mode"] = opcuaLayer.SecurityMode
		}
	} else {
		// Port-based detection only
		info.Confidence = 0.6
		info.MessageType = "unknown"
		info.AdditionalData["transport"] = "tcp"
	}

	// Determine direction based on port usage
	info.Direction = p.determineDirection(packet, []uint16{4840})

	return info
}

// parseEtherNetIPWithErrorHandling parses EtherNet/IP protocol with comprehensive error handling
func (p *IndustrialProtocolParserImpl) parseEtherNetIPWithErrorHandling(packet gopacket.Packet, timestamp time.Time) (*IndustrialProtocolInfo, *IndustrialProtocolError) {
	// Validate packet
	if packet == nil {
		return nil, NewParsingError("ethernetip", packet, fmt.Errorf("packet is nil"), "packet validation", false)
	}

	// Check if packet has EtherNet/IP layer or uses EtherNet/IP ports
	if !p.hasEtherNetIPLayer(packet) && !p.hasEtherNetIPPorts(packet) {
		return nil, nil // Not an EtherNet/IP packet, not an error
	}

	// Attempt to parse with recovery
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error
			err := fmt.Errorf("panic during EtherNet/IP parsing: %v", r)
			p.errorHandler.HandleProtocolError(NewParsingError("ethernetip", packet, err, "panic recovery", false))
		}
	}()

	info := &IndustrialProtocolInfo{
		Protocol:       "ethernetip",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
		Confidence:     0.8, // Default confidence for EtherNet/IP detection
	}

	// Try to get EtherNet/IP layer for detailed parsing
	if ethernetIPLayer := p.getEtherNetIPLayer(packet); ethernetIPLayer != nil {
		// Validate layer data
		if err := p.validateEtherNetIPLayer(ethernetIPLayer); err != nil {
			return nil, NewMalformedPacketError("ethernetip", packet, err, "layer validation")
		}

		info.Confidence = 1.0 // High confidence when layer is present

		// Extract device identity information with error handling
		deviceIdentity, err := p.safeGetDeviceIdentity(ethernetIPLayer)
		if err != nil {
			// Log error but continue with partial data
			p.errorHandler.HandleValidationError(ethernetIPLayer, err)
		} else {
			for k, v := range deviceIdentity {
				info.DeviceIdentity[k] = v
			}
		}

		// Extract CIP information with error handling
		cipInfo, err := p.safeGetCIPInfo(ethernetIPLayer)
		if err != nil {
			// Log error but continue with partial data
			p.errorHandler.HandleValidationError(ethernetIPLayer, err)
		} else {
			for k, v := range cipInfo {
				info.AdditionalData[k] = v
			}
		}

		// Determine message characteristics with error handling
		info.IsDiscovery = p.safeIsDiscoveryMessage(ethernetIPLayer)
		info.IsRealTimeData = ethernetIPLayer.IsImplicitMsg
		info.IsConfiguration = ethernetIPLayer.IsExplicitMsg

		// Set message type
		if info.IsDiscovery {
			info.MessageType = "discovery"
		} else if info.IsRealTimeData {
			info.MessageType = "real_time_io"
		} else if info.IsConfiguration {
			info.MessageType = "configuration"
		} else {
			info.MessageType = "data_transfer"
		}

		// Extract service type from CIP info
		if serviceName, ok := cipInfo["service_name"].(string); ok {
			info.ServiceType = serviceName
		}
	} else {
		// Port-based detection only
		info.Confidence = 0.6
		info.MessageType = "unknown"

		// Extract port information with error handling
		if err := p.extractPortInfo(packet, info, []uint16{44818, 2222}); err != nil {
			return nil, NewMalformedPacketError("ethernetip", packet, err, "port extraction")
		}
	}

	// Determine direction based on port usage
	info.Direction = p.determineDirection(packet, []uint16{44818, 2222})

	return info, nil
}

// parseOPCUAWithErrorHandling parses OPC UA protocol with comprehensive error handling
func (p *IndustrialProtocolParserImpl) parseOPCUAWithErrorHandling(packet gopacket.Packet, timestamp time.Time) (*IndustrialProtocolInfo, *IndustrialProtocolError) {
	// Validate packet
	if packet == nil {
		return nil, NewParsingError("opcua", packet, fmt.Errorf("packet is nil"), "packet validation", false)
	}

	// Check if packet has OPC UA layer or uses OPC UA ports
	if !p.hasOPCUALayer(packet) && !p.hasOPCUAPorts(packet) {
		return nil, nil // Not an OPC UA packet, not an error
	}

	// Attempt to parse with recovery
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error
			err := fmt.Errorf("panic during OPC UA parsing: %v", r)
			p.errorHandler.HandleProtocolError(NewParsingError("opcua", packet, err, "panic recovery", false))
		}
	}()

	info := &IndustrialProtocolInfo{
		Protocol:       "opcua",
		Port:           4840,
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
		Confidence:     0.8, // Default confidence for OPC UA detection
	}

	// Try to get OPC UA layer for detailed parsing
	if opcuaLayer := p.getOPCUALayer(packet); opcuaLayer != nil {
		// Validate layer data
		if err := p.validateOPCUALayer(opcuaLayer); err != nil {
			return nil, NewMalformedPacketError("opcua", packet, err, "layer validation")
		}

		info.Confidence = 1.0 // High confidence when layer is present

		// Extract security information with error handling
		securityInfo, err := p.safeGetSecurityInfo(opcuaLayer)
		if err != nil {
			// Log error but continue with partial data
			p.errorHandler.HandleValidationError(opcuaLayer, err)
		} else {
			for k, v := range securityInfo {
				info.SecurityInfo[k] = v
			}
		}

		// Extract service information with error handling
		serviceInfo, err := p.safeGetServiceInfo(opcuaLayer)
		if err != nil {
			// Log error but continue with partial data
			p.errorHandler.HandleValidationError(opcuaLayer, err)
		} else {
			for k, v := range serviceInfo {
				info.AdditionalData[k] = v
			}
		}

		// Determine message characteristics with error handling
		info.IsDiscovery = opcuaLayer.IsHandshake
		info.IsRealTimeData = p.safeIsRealTimeData(opcuaLayer)
		info.IsConfiguration = opcuaLayer.IsSessionMgmt

		// Set message type
		if info.IsDiscovery {
			info.MessageType = "handshake"
		} else if info.IsRealTimeData {
			info.MessageType = "subscription_data"
		} else if info.IsConfiguration {
			info.MessageType = "session_management"
		} else {
			info.MessageType = "service_call"
		}

		// Extract service type
		if opcuaLayer.ServiceType != "" {
			info.ServiceType = opcuaLayer.ServiceType
		}

		// Store message type and security mode
		info.AdditionalData["message_type"] = opcuaLayer.MessageType
		info.AdditionalData["chunk_type"] = opcuaLayer.ChunkType
		if opcuaLayer.SecurityMode != "" {
			info.AdditionalData["security_mode"] = opcuaLayer.SecurityMode
		}
	} else {
		// Port-based detection only
		info.Confidence = 0.6
		info.MessageType = "unknown"
		info.AdditionalData["transport"] = "tcp"
	}

	// Determine direction based on port usage
	info.Direction = p.determineDirection(packet, []uint16{4840})

	return info, nil
}

// Helper methods for safe data extraction and validation

// validateEtherNetIPLayer validates EtherNet/IP layer data
func (p *IndustrialProtocolParserImpl) validateEtherNetIPLayer(layer *lib_layers.EtherNetIP) error {
	if layer == nil {
		return fmt.Errorf("EtherNet/IP layer is nil")
	}
	// Add more validation as needed based on the layer structure
	return nil
}

// validateOPCUALayer validates OPC UA layer data
func (p *IndustrialProtocolParserImpl) validateOPCUALayer(layer *lib_layers.OPCUA) error {
	if layer == nil {
		return fmt.Errorf("OPC UA layer is nil")
	}
	// Add more validation as needed based on the layer structure
	return nil
}

// safeGetDeviceIdentity safely extracts device identity information
func (p *IndustrialProtocolParserImpl) safeGetDeviceIdentity(layer *lib_layers.EtherNetIP) (map[string]interface{}, error) {
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error for logging
		}
	}()

	if layer == nil {
		return nil, fmt.Errorf("layer is nil")
	}

	return layer.GetDeviceIdentity(), nil
}

// safeGetCIPInfo safely extracts CIP information
func (p *IndustrialProtocolParserImpl) safeGetCIPInfo(layer *lib_layers.EtherNetIP) (map[string]interface{}, error) {
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error for logging
		}
	}()

	if layer == nil {
		return nil, fmt.Errorf("layer is nil")
	}

	return layer.GetCIPInfo(), nil
}

// safeIsDiscoveryMessage safely checks if message is discovery
func (p *IndustrialProtocolParserImpl) safeIsDiscoveryMessage(layer *lib_layers.EtherNetIP) bool {
	defer func() {
		if r := recover(); r != nil {
			// Return false on panic
		}
	}()

	if layer == nil {
		return false
	}

	return layer.IsDiscoveryMessage()
}

// safeGetSecurityInfo safely extracts security information
func (p *IndustrialProtocolParserImpl) safeGetSecurityInfo(layer *lib_layers.OPCUA) (map[string]interface{}, error) {
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error for logging
		}
	}()

	if layer == nil {
		return nil, fmt.Errorf("layer is nil")
	}

	return layer.GetSecurityInfo(), nil
}

// safeGetServiceInfo safely extracts service information
func (p *IndustrialProtocolParserImpl) safeGetServiceInfo(layer *lib_layers.OPCUA) (map[string]interface{}, error) {
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error for logging
		}
	}()

	if layer == nil {
		return nil, fmt.Errorf("layer is nil")
	}

	return layer.GetServiceInfo(), nil
}

// safeIsRealTimeData safely checks if data is real-time
func (p *IndustrialProtocolParserImpl) safeIsRealTimeData(layer *lib_layers.OPCUA) bool {
	defer func() {
		if r := recover(); r != nil {
			// Return false on panic
		}
	}()

	if layer == nil {
		return false
	}

	return layer.IsRealTimeData()
}

// extractPortInfo safely extracts port information from packet
func (p *IndustrialProtocolParserImpl) extractPortInfo(packet gopacket.Packet, info *IndustrialProtocolInfo, ports []uint16) error {
	// Extract TCP port information
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		for _, port := range ports {
			if uint16(tcp.DstPort) == port || uint16(tcp.SrcPort) == port {
				info.Port = port
				info.AdditionalData["transport"] = "tcp"
				return nil
			}
		}
	}

	// Extract UDP port information
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		for _, port := range ports {
			if uint16(udp.DstPort) == port || uint16(udp.SrcPort) == port {
				info.Port = port
				info.AdditionalData["transport"] = "udp"
				return nil
			}
		}
	}

	return fmt.Errorf("no matching industrial ports found")
}

// Helper methods for layer detection

func (p *IndustrialProtocolParserImpl) hasEtherNetIPLayer(packet gopacket.Packet) bool {
	return p.getEtherNetIPLayer(packet) != nil
}

func (p *IndustrialProtocolParserImpl) hasOPCUALayer(packet gopacket.Packet) bool {
	return p.getOPCUALayer(packet) != nil
}

func (p *IndustrialProtocolParserImpl) getEtherNetIPLayer(packet gopacket.Packet) *lib_layers.EtherNetIP {
	if layer := packet.Layer(lib_layers.LayerTypeEtherNetIP); layer != nil {
		if ethernetIP, ok := layer.(*lib_layers.EtherNetIP); ok {
			return ethernetIP
		}
	}
	return nil
}

func (p *IndustrialProtocolParserImpl) getOPCUALayer(packet gopacket.Packet) *lib_layers.OPCUA {
	if layer := packet.Layer(lib_layers.LayerTypeOPCUA); layer != nil {
		if opcua, ok := layer.(*lib_layers.OPCUA); ok {
			return opcua
		}
	}
	return nil
}

func (p *IndustrialProtocolParserImpl) hasEtherNetIPPorts(packet gopacket.Packet) bool {
	return p.hasPortsInPacket(packet, []uint16{44818, 2222})
}

func (p *IndustrialProtocolParserImpl) hasOPCUAPorts(packet gopacket.Packet) bool {
	return p.hasPortsInPacket(packet, []uint16{4840})
}

func (p *IndustrialProtocolParserImpl) hasIndustrialPorts(packet gopacket.Packet) bool {
	industrialPorts := []uint16{44818, 2222, 4840} // EtherNet/IP and OPC UA ports
	return p.hasPortsInPacket(packet, industrialPorts)
}

func (p *IndustrialProtocolParserImpl) hasPortsInPacket(packet gopacket.Packet, ports []uint16) bool {
	// Check TCP ports
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)
		for _, port := range ports {
			if srcPort == port || dstPort == port {
				return true
			}
		}
	}

	// Check UDP ports
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)
		for _, port := range ports {
			if srcPort == port || dstPort == port {
				return true
			}
		}
	}

	return false
}

func (p *IndustrialProtocolParserImpl) determineDirection(packet gopacket.Packet, industrialPorts []uint16) string {
	// Check TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		for _, port := range industrialPorts {
			if dstPort == port {
				return "outbound" // Client connecting to server
			}
			if srcPort == port {
				return "inbound" // Server responding to client
			}
		}
	}

	// Check UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)

		for _, port := range industrialPorts {
			if dstPort == port {
				return "outbound"
			}
			if srcPort == port {
				return "inbound"
			}
		}
	}

	return "bidirectional"
}

func (p *IndustrialProtocolParserImpl) isIndustrialProtocol(protocol string) bool {
	industrialProtocols := []string{"ethernetip", "opcua", "modbus", "profinet", "dnp3"}
	for _, proto := range industrialProtocols {
		if protocol == proto {
			return true
		}
	}
	return false
}

// CollectProtocolUsageStats collects protocol usage statistics from industrial protocol information
func (p *IndustrialProtocolParserImpl) CollectProtocolUsageStats(deviceAddress string, protocols []IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	if len(protocols) == 0 {
		return nil, nil
	}

	// Group protocols by type and collect statistics
	protocolStats := make(map[string]*model.ProtocolUsageStats)

	for _, protocol := range protocols {
		stats, exists := protocolStats[protocol.Protocol]
		if !exists {
			stats = &model.ProtocolUsageStats{
				DeviceID:          deviceAddress,
				Protocol:          protocol.Protocol,
				PacketCount:       0,
				ByteCount:         0,
				FirstSeen:         protocol.Timestamp,
				LastSeen:          protocol.Timestamp,
				CommunicationRole: p.determineCommunicationRole(protocol),
				PortsUsed:         []uint16{},
			}
			protocolStats[protocol.Protocol] = stats
		}

		// Update statistics
		stats.PacketCount++
		if protocol.Timestamp.Before(stats.FirstSeen) {
			stats.FirstSeen = protocol.Timestamp
		}
		if protocol.Timestamp.After(stats.LastSeen) {
			stats.LastSeen = protocol.Timestamp
		}

		// Add port if not already present
		if protocol.Port > 0 {
			portExists := false
			for _, port := range stats.PortsUsed {
				if port == protocol.Port {
					portExists = true
					break
				}
			}
			if !portExists {
				stats.PortsUsed = append(stats.PortsUsed, protocol.Port)
			}
		}

		// Update communication role if needed
		newRole := p.determineCommunicationRole(protocol)
		if stats.CommunicationRole != newRole && stats.CommunicationRole != "both" {
			if stats.CommunicationRole == "client" && newRole == "server" ||
				stats.CommunicationRole == "server" && newRole == "client" {
				stats.CommunicationRole = "both"
			}
		}

		// Estimate byte count based on protocol type and message characteristics
		stats.ByteCount += p.estimatePacketSize(protocol)
	}

	// Return the first protocol stats (in a real implementation, you might want to return all)
	for _, stats := range protocolStats {
		return stats, nil
	}

	return nil, nil
}

// UpdateProtocolUsageStats updates existing protocol usage statistics with new data
func (p *IndustrialProtocolParserImpl) UpdateProtocolUsageStats(existing *model.ProtocolUsageStats, protocols []IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	if existing == nil {
		return nil, errors.New("existing stats cannot be nil")
	}

	updated := *existing // Copy existing stats

	for _, protocol := range protocols {
		// Only update if protocol matches
		if protocol.Protocol != existing.Protocol {
			continue
		}

		// Update packet count
		updated.PacketCount++

		// Update timestamps
		if protocol.Timestamp.Before(updated.FirstSeen) {
			updated.FirstSeen = protocol.Timestamp
		}
		if protocol.Timestamp.After(updated.LastSeen) {
			updated.LastSeen = protocol.Timestamp
		}

		// Add port if not already present
		if protocol.Port > 0 {
			portExists := false
			for _, port := range updated.PortsUsed {
				if port == protocol.Port {
					portExists = true
					break
				}
			}
			if !portExists {
				updated.PortsUsed = append(updated.PortsUsed, protocol.Port)
			}
		}

		// Update communication role if needed
		newRole := p.determineCommunicationRole(protocol)
		if updated.CommunicationRole != newRole && updated.CommunicationRole != "both" {
			if updated.CommunicationRole == "client" && newRole == "server" ||
				updated.CommunicationRole == "server" && newRole == "client" {
				updated.CommunicationRole = "both"
			}
		}

		// Update byte count
		updated.ByteCount += p.estimatePacketSize(protocol)
	}

	return &updated, nil
}

// AggregateProtocolUsageStats aggregates multiple protocol usage statistics
func (p *IndustrialProtocolParserImpl) AggregateProtocolUsageStats(statsList []*model.ProtocolUsageStats) (*model.ProtocolUsageStats, error) {
	if len(statsList) == 0 {
		return nil, nil
	}

	// Group by device and protocol
	aggregated := make(map[string]*model.ProtocolUsageStats)

	for _, stats := range statsList {
		if stats == nil {
			continue
		}

		key := stats.DeviceID + ":" + stats.Protocol
		existing, exists := aggregated[key]

		if !exists {
			// Create a copy of the stats
			newStats := *stats
			aggregated[key] = &newStats
		} else {
			// Aggregate the statistics
			existing.PacketCount += stats.PacketCount
			existing.ByteCount += stats.ByteCount

			// Update timestamps
			if stats.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = stats.FirstSeen
			}
			if stats.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = stats.LastSeen
			}

			// Merge ports
			for _, port := range stats.PortsUsed {
				portExists := false
				for _, existingPort := range existing.PortsUsed {
					if existingPort == port {
						portExists = true
						break
					}
				}
				if !portExists {
					existing.PortsUsed = append(existing.PortsUsed, port)
				}
			}

			// Update communication role
			if existing.CommunicationRole != stats.CommunicationRole && existing.CommunicationRole != "both" {
				if existing.CommunicationRole == "client" && stats.CommunicationRole == "server" ||
					existing.CommunicationRole == "server" && stats.CommunicationRole == "client" {
					existing.CommunicationRole = "both"
				}
			}
		}
	}

	// Return the first aggregated stats (in a real implementation, you might want to return all)
	for _, stats := range aggregated {
		return stats, nil
	}

	return nil, nil
}

// Helper methods for statistics collection

// determineCommunicationRole determines the communication role based on protocol information
func (p *IndustrialProtocolParserImpl) determineCommunicationRole(protocol IndustrialProtocolInfo) string {
	switch protocol.Direction {
	case "outbound":
		return "client"
	case "inbound":
		return "server"
	case "bidirectional":
		return "both"
	default:
		// Fallback based on protocol characteristics
		if protocol.IsDiscovery {
			return "client" // Discovery usually initiated by client
		}
		if protocol.ServiceType != "" {
			return "server" // Providing services suggests server role
		}
		return "client" // Default to client
	}
}

// estimatePacketSize estimates the packet size based on protocol information
func (p *IndustrialProtocolParserImpl) estimatePacketSize(protocol IndustrialProtocolInfo) int64 {
	// Base packet size estimates for different protocols
	baseSize := int64(64) // Minimum Ethernet frame size

	switch protocol.Protocol {
	case "ethernetip":
		if protocol.IsRealTimeData {
			return baseSize + 32 // Real-time I/O data is typically small
		}
		if protocol.IsConfiguration {
			return baseSize + 256 // Configuration messages are larger
		}
		return baseSize + 128 // Default EtherNet/IP message size

	case "opcua":
		if protocol.IsDiscovery {
			return baseSize + 512 // Handshake messages contain certificates
		}
		if protocol.IsRealTimeData {
			return baseSize + 64 // Subscription data varies
		}
		return baseSize + 256 // Default OPC UA message size

	default:
		return baseSize + 64 // Default industrial protocol message size
	}
}
