package parser

import (
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// IndustrialProtocolParser defines the interface for parsing industrial protocols
// and performing device classification based on protocol usage patterns
type IndustrialProtocolParser interface {
	// ParseIndustrialProtocols analyzes a packet for industrial protocol information
	// Returns a slice of IndustrialProtocolInfo containing detected protocols
	ParseIndustrialProtocols(packet gopacket.Packet) ([]IndustrialProtocolInfo, error)

	// DetectDeviceType classifies a device based on its protocol usage patterns and communication flows
	// Returns the most likely device type based on the analysis
	DetectDeviceType(protocols []IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType

	// AnalyzeCommunicationPatterns analyzes network flows to identify communication patterns
	// Returns patterns that help determine device roles and criticality
	AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern

	// CollectProtocolUsageStats collects protocol usage statistics for a device
	// Returns protocol usage statistics based on detected protocols
	CollectProtocolUsageStats(deviceID string, protocols []IndustrialProtocolInfo) (*model.ProtocolUsageStats, error)
}

// IndustrialProtocolInfo represents information extracted from an industrial protocol packet
type IndustrialProtocolInfo struct {
	// Basic protocol information
	Protocol   string    `json:"protocol"`   // Protocol name (e.g., "EtherNet/IP", "OPC UA")
	Port       uint16    `json:"port"`       // Port number used
	Direction  string    `json:"direction"`  // "inbound", "outbound", "bidirectional"
	Timestamp  time.Time `json:"timestamp"`  // When this protocol info was captured
	Confidence float64   `json:"confidence"` // Confidence level (0.0-1.0) of protocol detection

	// Protocol classification
	ServiceType     string `json:"service_type"`     // Type of service (e.g., "explicit_messaging", "implicit_io")
	MessageType     string `json:"message_type"`     // Specific message type within protocol
	IsRealTimeData  bool   `json:"is_real_time"`     // True if this is real-time I/O data
	IsDiscovery     bool   `json:"is_discovery"`     // True if this is device discovery
	IsConfiguration bool   `json:"is_configuration"` // True if this is configuration/setup

	// Device and security information
	DeviceIdentity map[string]interface{} `json:"device_identity"` // Device identity information
	SecurityInfo   map[string]interface{} `json:"security_info"`   // Security-related information
	AdditionalData map[string]interface{} `json:"additional_data"` // Protocol-specific additional data
}

// IndustrialProtocolParserImpl implements the IndustrialProtocolParser interface
type IndustrialProtocolParserImpl struct {
	// Configuration and state
	enabledProtocols    map[string]bool
	confidenceThreshold float64
}

// NewIndustrialProtocolParser creates a new instance of IndustrialProtocolParser
func NewIndustrialProtocolParser() IndustrialProtocolParser {
	return &IndustrialProtocolParserImpl{
		enabledProtocols: map[string]bool{
			"EtherNet/IP": true,
			"OPC UA":      true,
			"Modbus":      true,
		},
		confidenceThreshold: 0.7, // Default confidence threshold
	}
}

// ParseIndustrialProtocols analyzes a packet for industrial protocol information
func (p *IndustrialProtocolParserImpl) ParseIndustrialProtocols(packet gopacket.Packet) ([]IndustrialProtocolInfo, error) {
	var protocols []IndustrialProtocolInfo
	timestamp := packet.Metadata().Timestamp

	// Check for EtherNet/IP protocol
	if ethernetIPInfo := p.parseEtherNetIP(packet, timestamp); ethernetIPInfo != nil {
		protocols = append(protocols, *ethernetIPInfo)
	}

	// Check for OPC UA protocol
	if opcuaInfo := p.parseOPCUA(packet, timestamp); opcuaInfo != nil {
		protocols = append(protocols, *opcuaInfo)
	}

	// Check for Modbus TCP protocol
	if modbusInfo := p.parseModbusTCP(packet, timestamp); modbusInfo != nil {
		protocols = append(protocols, *modbusInfo)
	}

	return protocols, nil
}

// DetectDeviceType classifies a device based on its protocol usage patterns and communication flows
func (p *IndustrialProtocolParserImpl) DetectDeviceType(protocols []IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType {
	if len(protocols) == 0 {
		return model.DeviceTypeUnknown
	}

	// Analyze protocol patterns to determine device type
	protocolCounts := make(map[string]int)
	hasRealTimeData := false
	hasConfiguration := false
	hasDiscovery := false
	isServerRole := false
	isClientRole := false

	// Analyze protocol usage patterns
	for _, protocol := range protocols {
		protocolCounts[protocol.Protocol]++

		if protocol.IsRealTimeData {
			hasRealTimeData = true
		}
		if protocol.IsConfiguration {
			hasConfiguration = true
		}
		if protocol.IsDiscovery {
			hasDiscovery = true
		}

		// Determine communication role based on direction and service type
		if protocol.Direction == "inbound" || protocol.ServiceType == "server" {
			isServerRole = true
		}
		if protocol.Direction == "outbound" || protocol.ServiceType == "client" {
			isClientRole = true
		}
	}

	// Analyze communication patterns from flows
	inboundFlows := 0
	outboundFlows := 0
	totalDataVolume := int64(0)

	for _, flow := range flows {
		if flow.Destination != "" {
			inboundFlows++
		}
		if flow.Source != "" {
			outboundFlows++
		}
		totalDataVolume += int64(flow.Bytes)
	}

	// Classification logic based on protocol patterns and communication behavior
	return p.classifyDeviceByPatterns(protocolCounts, hasRealTimeData, hasConfiguration,
		hasDiscovery, isServerRole, isClientRole, inboundFlows, outboundFlows, totalDataVolume)
}

// AnalyzeCommunicationPatterns analyzes network flows to identify communication patterns
func (p *IndustrialProtocolParserImpl) AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern {
	var patterns []model.CommunicationPattern

	// Group flows by source-destination pairs
	flowGroups := make(map[string][]model.Flow)
	for _, flow := range flows {
		key := flow.Source + "->" + flow.Destination
		flowGroups[key] = append(flowGroups[key], flow)
	}

	// Analyze each flow group for patterns
	for _, groupFlows := range flowGroups {
		if len(groupFlows) == 0 {
			continue
		}

		pattern := p.analyzeFlowGroup(groupFlows)
		if pattern != nil {
			patterns = append(patterns, *pattern)
		}
	}

	return patterns
}

// parseEtherNetIP extracts EtherNet/IP protocol information from a packet
func (p *IndustrialProtocolParserImpl) parseEtherNetIP(packet gopacket.Packet, timestamp time.Time) *IndustrialProtocolInfo {
	// Check if packet contains EtherNet/IP layer
	ethernetIPLayer := packet.Layer(gopacket.LayerType(1004)) // LayerTypeEtherNetIP
	if ethernetIPLayer == nil {
		return nil
	}

	// Type assertion to get EtherNet/IP specific data
	// Note: This would need to import the actual EtherNet/IP layer type
	// For now, we'll extract basic information from the layer

	info := &IndustrialProtocolInfo{
		Protocol:       "EtherNet/IP",
		Timestamp:      timestamp,
		Confidence:     0.9, // High confidence for detected EtherNet/IP
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}

	// Determine port based on transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		info.Port = 44818 // Standard EtherNet/IP TCP port
		info.Direction = p.determineDirection(packet)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		info.Port = 2222 // Standard EtherNet/IP UDP port
		info.Direction = p.determineDirection(packet)
	}

	// Extract EtherNet/IP specific information
	p.extractEtherNetIPDetails(packet, info)

	return info
}

// parseOPCUA extracts OPC UA protocol information from a packet
func (p *IndustrialProtocolParserImpl) parseOPCUA(packet gopacket.Packet, timestamp time.Time) *IndustrialProtocolInfo {
	// Check if packet contains OPC UA layer
	opcuaLayer := packet.Layer(gopacket.LayerType(1005)) // LayerTypeOPCUA
	if opcuaLayer == nil {
		return nil
	}

	info := &IndustrialProtocolInfo{
		Protocol:       "OPC UA",
		Port:           4840, // Standard OPC UA port
		Timestamp:      timestamp,
		Confidence:     0.9, // High confidence for detected OPC UA
		Direction:      p.determineDirection(packet),
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}

	// Extract OPC UA specific information
	p.extractOPCUADetails(packet, info)

	return info
}

// parseModbusTCP extracts Modbus TCP protocol information from a packet
func (p *IndustrialProtocolParserImpl) parseModbusTCP(packet gopacket.Packet, timestamp time.Time) *IndustrialProtocolInfo {
	// Check for Modbus TCP on port 502
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	// Simple port-based detection for Modbus TCP
	// In a full implementation, this would include protocol validation
	tcp := tcpLayer.(*layers.TCP)

	// Check if it's on Modbus port 502
	if tcp.SrcPort != 502 && tcp.DstPort != 502 {
		return nil
	}

	// Note: This is simplified - real implementation would validate Modbus protocol structure
	payload := packet.ApplicationLayer()
	if payload == nil || len(payload.LayerContents()) < 6 {
		return nil
	}

	info := &IndustrialProtocolInfo{
		Protocol:       "Modbus TCP",
		Port:           502,
		Timestamp:      timestamp,
		Confidence:     0.7, // Medium confidence for port-based detection
		Direction:      p.determineDirection(packet),
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}

	// Extract basic Modbus information
	p.extractModbusDetails(payload.LayerContents(), info)

	return info
}

// determineDirection determines the communication direction based on packet flow
func (p *IndustrialProtocolParserImpl) determineDirection(packet gopacket.Packet) string {
	// This is a simplified implementation
	// In practice, this would analyze source/destination IPs and ports
	// to determine if this is inbound, outbound, or bidirectional communication

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		// For now, return bidirectional for TCP connections
		return "bidirectional"
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		// For UDP, we'd need more context to determine direction
		return "bidirectional"
	}

	return "unknown"
}

// extractEtherNetIPDetails extracts detailed information from EtherNet/IP packet
func (p *IndustrialProtocolParserImpl) extractEtherNetIPDetails(packet gopacket.Packet, info *IndustrialProtocolInfo) {
	// This would extract specific EtherNet/IP information
	// For now, we'll set some basic classification flags

	info.ServiceType = "explicit_messaging" // Default assumption
	info.IsRealTimeData = false             // Would be determined from actual packet analysis
	info.IsDiscovery = false
	info.IsConfiguration = false

	// Store layer-specific data
	info.AdditionalData["layer_type"] = "EtherNet/IP"
	info.AdditionalData["detected_via"] = "gopacket_layer"
}

// extractOPCUADetails extracts detailed information from OPC UA packet
func (p *IndustrialProtocolParserImpl) extractOPCUADetails(packet gopacket.Packet, info *IndustrialProtocolInfo) {
	// This would extract specific OPC UA information
	// For now, we'll set some basic classification flags

	info.ServiceType = "service_call" // Default assumption
	info.IsRealTimeData = false       // Would be determined from service type
	info.IsDiscovery = false
	info.IsConfiguration = false

	// Store layer-specific data
	info.AdditionalData["layer_type"] = "OPC UA"
	info.AdditionalData["detected_via"] = "gopacket_layer"
}

// extractModbusDetails extracts detailed information from Modbus TCP payload
func (p *IndustrialProtocolParserImpl) extractModbusDetails(payload []byte, info *IndustrialProtocolInfo) {
	if len(payload) < 6 {
		return
	}

	// Basic Modbus TCP header parsing
	// Transaction ID: bytes 0-1
	// Protocol ID: bytes 2-3 (should be 0x0000 for Modbus)
	// Length: bytes 4-5

	protocolID := uint16(payload[2])<<8 | uint16(payload[3])
	if protocolID != 0x0000 {
		info.Confidence = 0.3 // Lower confidence if protocol ID doesn't match
		return
	}

	info.ServiceType = "modbus_request" // Default assumption
	info.IsRealTimeData = true          // Modbus is typically real-time
	info.IsDiscovery = false
	info.IsConfiguration = false

	// Store Modbus-specific data
	info.AdditionalData["protocol_id"] = protocolID
	info.AdditionalData["detected_via"] = "port_and_header"
}

// classifyDeviceByPatterns performs device classification based on analyzed patterns
func (p *IndustrialProtocolParserImpl) classifyDeviceByPatterns(
	protocolCounts map[string]int,
	hasRealTimeData, hasConfiguration, hasDiscovery, isServerRole, isClientRole bool,
	inboundFlows, outboundFlows int,
	totalDataVolume int64) model.IndustrialDeviceType {

	// Classification logic based on protocol usage patterns

	// PLC classification: typically uses EtherNet/IP or Modbus, acts as server, handles real-time data
	if (protocolCounts["EtherNet/IP"] > 0 || protocolCounts["Modbus TCP"] > 0) &&
		isServerRole && hasRealTimeData {
		return model.DeviceTypePLC
	}

	// HMI classification: typically uses OPC UA as client, may have configuration access
	if protocolCounts["OPC UA"] > 0 && isClientRole && hasConfiguration {
		return model.DeviceTypeHMI
	}

	// SCADA classification: uses OPC UA, high data volume, both client and server roles
	if protocolCounts["OPC UA"] > 0 && isClientRole && isServerRole && totalDataVolume > 10000 {
		return model.DeviceTypeSCADA
	}

	// Engineering Workstation: uses multiple protocols, has configuration and discovery
	if len(protocolCounts) > 1 && hasConfiguration && hasDiscovery {
		return model.DeviceTypeEngWorkstation
	}

	// I/O Device: primarily EtherNet/IP or Modbus, real-time data, mostly server role
	if (protocolCounts["EtherNet/IP"] > 0 || protocolCounts["Modbus TCP"] > 0) &&
		hasRealTimeData && isServerRole && !isClientRole {
		return model.DeviceTypeIODevice
	}

	// Historian: OPC UA client with high data volume
	if protocolCounts["OPC UA"] > 0 && isClientRole && totalDataVolume > 50000 {
		return model.DeviceTypeHistorian
	}

	// Default to unknown if patterns don't match known device types
	return model.DeviceTypeUnknown
}

// analyzeFlowGroup analyzes a group of flows between the same source-destination pair
func (p *IndustrialProtocolParserImpl) analyzeFlowGroup(flows []model.Flow) *model.CommunicationPattern {
	if len(flows) == 0 {
		return nil
	}

	firstFlow := flows[0]

	// Calculate total data volume
	totalBytes := int64(0)
	for _, flow := range flows {
		totalBytes += int64(flow.Bytes)
	}

	// Determine pattern type based on flow characteristics
	patternType := p.determinePatternType(flows)

	// Determine criticality based on protocol and data volume
	criticality := p.determineCriticality(firstFlow.Protocol, totalBytes, len(flows))

	// Calculate frequency (simplified - time between first and last flow divided by number of flows)
	var frequency time.Duration
	if len(flows) > 1 {
		timeSpan := flows[len(flows)-1].LastSeen.Sub(flows[0].FirstSeen)
		frequency = timeSpan / time.Duration(len(flows))
	}

	return &model.CommunicationPattern{
		SourceDevice:      firstFlow.Source,
		DestinationDevice: firstFlow.Destination,
		Protocol:          firstFlow.Protocol,
		Frequency:         frequency,
		DataVolume:        totalBytes,
		PatternType:       patternType,
		Criticality:       criticality,
	}
}

// determinePatternType determines the communication pattern type
func (p *IndustrialProtocolParserImpl) determinePatternType(flows []model.Flow) string {
	if len(flows) == 1 {
		return "event-driven"
	}

	// Analyze timing patterns to determine if periodic or continuous
	if len(flows) > 5 {
		// Check for regular intervals (simplified)
		return "periodic"
	}

	// Check for continuous data flow
	totalTimeSpan := flows[len(flows)-1].LastSeen.Sub(flows[0].FirstSeen)
	if totalTimeSpan > time.Minute && len(flows) > 10 {
		return "continuous"
	}

	return "event-driven"
}

// determineCriticality determines the criticality level of communication
func (p *IndustrialProtocolParserImpl) determineCriticality(protocol string, dataVolume int64, flowCount int) string {
	// Industrial protocols are generally more critical
	switch protocol {
	case "EtherNet/IP", "Modbus TCP":
		if dataVolume > 10000 || flowCount > 20 {
			return "critical"
		}
		return "high"
	case "OPC UA":
		if dataVolume > 50000 || flowCount > 50 {
			return "high"
		}
		return "medium"
	default:
		if dataVolume > 100000 {
			return "medium"
		}
		return "low"
	}
}

// CollectProtocolUsageStats collects protocol usage statistics for a device
func (p *IndustrialProtocolParserImpl) CollectProtocolUsageStats(deviceID string, protocols []IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	if len(protocols) == 0 {
		return nil, nil
	}

	// For now, we'll create stats for the first protocol
	// In a full implementation, this might aggregate multiple protocols or return multiple stats
	protocol := protocols[0]

	stats := &model.ProtocolUsageStats{
		DeviceID:          deviceID,
		Protocol:          protocol.Protocol,
		PacketCount:       1, // This would be accumulated over time
		ByteCount:         0, // This would need to be calculated from packet size
		FirstSeen:         protocol.Timestamp,
		LastSeen:          protocol.Timestamp,
		CommunicationRole: p.determineCommunicationRole(protocol),
		PortsUsed:         []uint16{protocol.Port},
	}

	return stats, nil
}

// determineCommunicationRole determines the communication role based on protocol info
func (p *IndustrialProtocolParserImpl) determineCommunicationRole(protocol IndustrialProtocolInfo) string {
	switch protocol.Direction {
	case "inbound":
		return "server"
	case "outbound":
		return "client"
	case "bidirectional":
		return "both"
	default:
		return "both"
	}
}

// classifyDeviceByPatterns performs device classification based on analyzed patterns
func (p *IndustrialProtocolParserImpl) classifyDeviceByPatterns(
	protocolCounts map[string]int,
	hasRealTimeData, hasConfiguration, hasDiscovery, isServerRole, isClientRole bool,
	inboundFlows, outboundFlows int,
	totalDataVolume int64) model.IndustrialDeviceType {

	// Classification logic based on protocol usage patterns

	// PLC classification: typically uses EtherNet/IP or Modbus, acts as server, handles real-time data
	if (protocolCounts["EtherNet/IP"] > 0 || protocolCounts["Modbus TCP"] > 0) &&
		isServerRole && hasRealTimeData {
		return model.DeviceTypePLC
	}

	// HMI classification: typically uses OPC UA as client, may have configuration access
	if protocolCounts["OPC UA"] > 0 && isClientRole && hasConfiguration {
		return model.DeviceTypeHMI
	}

	// SCADA classification: uses OPC UA, high data volume, both client and server roles
	if protocolCounts["OPC UA"] > 0 && isClientRole && isServerRole && totalDataVolume > 10000 {
		return model.DeviceTypeSCADA
	}

	// Engineering Workstation: uses multiple protocols, has configuration and discovery
	if len(protocolCounts) > 1 && hasConfiguration && hasDiscovery {
		return model.DeviceTypeEngWorkstation
	}

	// I/O Device: primarily EtherNet/IP or Modbus, real-time data, mostly server role
	if (protocolCounts["EtherNet/IP"] > 0 || protocolCounts["Modbus TCP"] > 0) &&
		hasRealTimeData && isServerRole && !isClientRole {
		return model.DeviceTypeIODevice
	}

	// Additional check for Modbus TCP devices that are primarily servers
	if protocolCounts["Modbus TCP"] > 0 && hasRealTimeData && isServerRole {
		return model.DeviceTypeIODevice
	}

	// Historian: OPC UA client with high data volume
	if protocolCounts["OPC UA"] > 0 && isClientRole && totalDataVolume > 50000 {
		return model.DeviceTypeHistorian
	}

	// Default to unknown if patterns don't match known device types
	return model.DeviceTypeUnknown
}

// determinePatternType determines the communication pattern type
func (p *IndustrialProtocolParserImpl) determinePatternType(flows []model.Flow) string {
	if len(flows) == 1 {
		return "event-driven"
	}

	// Check for continuous data flow first (many flows over time)
	totalTimeSpan := flows[len(flows)-1].LastSeen.Sub(flows[0].FirstSeen)
	if totalTimeSpan > time.Minute && len(flows) > 10 {
		return "continuous"
	}

	// Analyze timing patterns to determine if periodic or continuous
	if len(flows) > 5 {
		// Check for regular intervals (simplified)
		return "periodic"
	}

	return "event-driven"
}
