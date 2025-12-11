package parser

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	lib_layers "github.com/InfraSecConsult/pcap-importer-go/lib/layers"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

// Allow tests in this package to use IndustrialProtocolInfo without model qualifier
type IndustrialProtocolInfo = model.IndustrialProtocolInfo

// IndustrialProtocolParser defines the interface for parsing industrial protocols
// and performing device classification based on protocol usage patterns
type IndustrialProtocolParser interface {
	// ParseIndustrialProtocols analyzes a packet for industrial protocol information
	// Returns a slice of model.IndustrialProtocolInfo containing detected protocols
	ParseIndustrialProtocols(packet gopacket.Packet) ([]model.IndustrialProtocolInfo, error)

	// DetectDeviceType classifies a device based on its protocol usage patterns and communication flows
	// Returns the most likely device type based on the analysis
	DetectDeviceType(protocols []model.IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType

	// AnalyzeCommunicationPatterns analyzes network flows to identify communication patterns
	// Returns patterns that help determine device roles and criticality
	AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern

	// CollectProtocolUsageStats collects protocol usage statistics for a device
	// Returns protocol usage statistics based on detected protocols
	CollectProtocolUsageStats(deviceID string, protocols []model.IndustrialProtocolInfo) (*model.ProtocolUsageStats, error)

	// SetErrorHandler sets the error handler for the parser
	SetErrorHandler(handler ErrorHandler)

	// GetErrorHandler returns the current error handler
	GetErrorHandler() ErrorHandler
}

const PATTERN_TYPE_UNKNOWN = "unknown"
const PATTERN_TYPE_PERIODIC = "periodic"
const PATTERN_TYPE_EVENT_DRIVEN = "event-driven"
const PATTERN_TYPE_CONTINUOUS = "continuous"

const CRITICALITY_UNKNOWN = "unknown"
const CRITICALITY_LOW = "low"
const CRITICALITY_MEDIUM = "medium"
const CRITICALITY_HIGH = "high"
const CRITICALITY_CRITICAL = "critical"

// IndustrialParserConfig contains configuration options for the industrial protocol parser
type IndustrialParserConfig struct {
	// Protocol enablement
	EnableEtherNetIP bool `json:"enable_ethernetip"`
	EnableOPCUA      bool `json:"enable_opcua"`
	EnableModbus     bool `json:"enable_modbus"`
	EnableDNP3       bool `json:"enable_dnp3"`
	EnableS7         bool `json:"enable_s7"`

	// Confidence thresholds
	ConfidenceThreshold               float64 `json:"confidence_threshold"`
	MinDeviceClassificationConfidence float64 `json:"min_device_classification_confidence"`

	// Performance optimization
	MaxPacketsPerFlow      int  `json:"max_packets_per_flow"`
	MaxConcurrentAnalysis  int  `json:"max_concurrent_analysis"`
	EnableCaching          bool `json:"enable_caching"`
	CacheExpirationMinutes int  `json:"cache_expiration_minutes"`

	// Analysis depth
	EnableDeepPacketInspection bool `json:"enable_deep_packet_inspection"`
	EnableDeviceFingerprinting bool `json:"enable_device_fingerprinting"`
	EnableSecurityAnalysis     bool `json:"enable_security_analysis"`

	// Error handling
	MaxErrorsPerFlow int    `json:"max_errors_per_flow"`
	ContinueOnError  bool   `json:"continue_on_error"`
	LogLevel         string `json:"log_level"`
}

// DefaultIndustrialParserConfig returns a default configuration
func DefaultIndustrialParserConfig() IndustrialParserConfig {
	return IndustrialParserConfig{
		// Enable common industrial protocols by default
		EnableEtherNetIP: true,
		EnableOPCUA:      true,
		EnableModbus:     true,
		EnableDNP3:       false,
		EnableS7:         false,

		// Conservative confidence thresholds
		ConfidenceThreshold:               0.7,
		MinDeviceClassificationConfidence: 0.6,

		// Reasonable performance defaults
		MaxPacketsPerFlow:      1000,
		MaxConcurrentAnalysis:  4,
		EnableCaching:          true,
		CacheExpirationMinutes: 60,

		// Enable comprehensive analysis by default
		EnableDeepPacketInspection: true,
		EnableDeviceFingerprinting: true,
		EnableSecurityAnalysis:     true,

		// Robust error handling
		MaxErrorsPerFlow: 10,
		ContinueOnError:  true,
		LogLevel:         "info",
	}
}

// Validate validates the configuration
func (c *IndustrialParserConfig) Validate() error {
	if c.ConfidenceThreshold < 0.0 || c.ConfidenceThreshold > 1.0 {
		return errors.New("confidence threshold must be between 0.0 and 1.0")
	}
	if c.MinDeviceClassificationConfidence < 0.0 || c.MinDeviceClassificationConfidence > 1.0 {
		return errors.New("minimum device classification confidence must be between 0.0 and 1.0")
	}
	if c.MaxPacketsPerFlow < 1 {
		return errors.New("max packets per flow must be at least 1")
	}
	if c.MaxConcurrentAnalysis < 1 {
		return errors.New("max concurrent analysis must be at least 1")
	}
	if c.CacheExpirationMinutes < 1 {
		return errors.New("cache expiration must be at least 1 minute")
	}
	if c.MaxErrorsPerFlow < 0 {
		return errors.New("max errors per flow cannot be negative")
	}

	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return errors.New("log level must be one of: debug, info, warn, error")
	}

	return nil
}

// IndustrialProtocolParserImpl implements the IndustrialProtocolParser interface
type IndustrialProtocolParserImpl struct {
	// Configuration
	config IndustrialParserConfig

	// Legacy configuration fields (deprecated, use config instead)
	enabledProtocols    map[string]bool
	confidenceThreshold float64
	enableEtherNetIP    bool
	enableOPCUA         bool
	errorHandler        ErrorHandler

	// Performance optimization
	packetCache map[string]model.IndustrialProtocolInfo
	deviceCache map[string]model.IndustrialDeviceType
}

// NewIndustrialProtocolParser creates a new instance of IndustrialProtocolParser with default configuration
func NewIndustrialProtocolParser() IndustrialProtocolParser {
	config := DefaultIndustrialParserConfig()
	return NewIndustrialProtocolParserWithConfig(config)
}

// NewIndustrialProtocolParserWithConfig creates a new instance of IndustrialProtocolParser with custom configuration
func NewIndustrialProtocolParserWithConfig(config IndustrialParserConfig) IndustrialProtocolParser {
	if err := config.Validate(); err != nil {
		// Fall back to default config if validation fails
		log.Printf("Invalid configuration, using defaults: %v", err)
		config = DefaultIndustrialParserConfig()
	}

	return &IndustrialProtocolParserImpl{
		config: config,

		// Legacy fields for backward compatibility
		enabledProtocols: map[string]bool{
			"EtherNet/IP": config.EnableEtherNetIP,
			"OPC UA":      config.EnableOPCUA,
			"Modbus":      config.EnableModbus,
			"DNP3":        config.EnableDNP3,
			"S7":          config.EnableS7,
		},
		confidenceThreshold: config.ConfidenceThreshold,
		enableEtherNetIP:    config.EnableEtherNetIP,
		enableOPCUA:         config.EnableOPCUA,
		errorHandler:        NewNoOpErrorHandler(),

		// Initialize caches if caching is enabled
		packetCache: func() map[string]model.IndustrialProtocolInfo {
			if config.EnableCaching {
				return make(map[string]model.IndustrialProtocolInfo)
			}
			return nil
		}(),
		deviceCache: func() map[string]model.IndustrialDeviceType {
			if config.EnableCaching {
				return make(map[string]model.IndustrialDeviceType)
			}
			return nil
		}(),
	}
}

// NewIndustrialProtocolParserWithErrorHandler creates a new parser with specified error handler
func NewIndustrialProtocolParserWithErrorHandler(errorHandler ErrorHandler) IndustrialProtocolParser {
	parser := NewIndustrialProtocolParserWithConfig(DefaultIndustrialParserConfig()).(*IndustrialProtocolParserImpl)
	if errorHandler != nil {
		parser.errorHandler = errorHandler
	}
	return parser
}

// NewIndustrialProtocolParserWithConfigAndErrorHandler creates a new parser with custom config and error handler
func NewIndustrialProtocolParserWithConfigAndErrorHandler(config IndustrialParserConfig, errorHandler ErrorHandler) IndustrialProtocolParser {
	parser := NewIndustrialProtocolParserWithConfig(config).(*IndustrialProtocolParserImpl)
	if errorHandler != nil {
		parser.errorHandler = errorHandler
	}
	return parser
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

// GetConfig returns the current configuration
func (p *IndustrialProtocolParserImpl) GetConfig() IndustrialParserConfig {
	return p.config
}

// UpdateConfig updates the parser configuration
func (p *IndustrialProtocolParserImpl) UpdateConfig(config IndustrialParserConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	p.config = config

	// Update legacy fields for backward compatibility
	p.enabledProtocols = map[string]bool{
		"EtherNet/IP": config.EnableEtherNetIP,
		"OPC UA":      config.EnableOPCUA,
		"Modbus":      config.EnableModbus,
		"DNP3":        config.EnableDNP3,
		"S7":          config.EnableS7,
	}
	p.confidenceThreshold = config.ConfidenceThreshold
	p.enableEtherNetIP = config.EnableEtherNetIP
	p.enableOPCUA = config.EnableOPCUA

	// Initialize or clear caches based on configuration
	if config.EnableCaching {
		if p.packetCache == nil {
			p.packetCache = make(map[string]model.IndustrialProtocolInfo)
		}
		if p.deviceCache == nil {
			p.deviceCache = make(map[string]model.IndustrialDeviceType)
		}
	} else {
		p.packetCache = nil
		p.deviceCache = nil
	}

	return nil
}

// ParseIndustrialProtocols analyzes a packet for industrial protocol information
func (p *IndustrialProtocolParserImpl) ParseIndustrialProtocols(packet gopacket.Packet) ([]model.IndustrialProtocolInfo, error) {
	if packet == nil {
		err := &IndustrialProtocolError{
			Protocol:    "unknown",
			Packet:      packet,
			Err:         errors.New("packet is nil"),
			Context:     "ParseIndustrialProtocols",
			Recoverable: true,
			Timestamp:   time.Now(),
		}
		if handlerErr := p.errorHandler.HandleProtocolError(err); handlerErr != nil {
			return nil, handlerErr
		}
		return []model.IndustrialProtocolInfo{}, nil
	}

	if p.errorHandler.ThresholdExceeded() {
		return nil, errors.New("error threshold exceeded, stopping industrial protocol parsing")
	}

	var protocols []model.IndustrialProtocolInfo
	timestamp := packet.Metadata().Timestamp

	// Check for EtherNet/IP protocol
	if p.config.EnableEtherNetIP {
		if enipInfo := p.parseEtherNetIP(packet, timestamp); enipInfo != nil && enipInfo.Confidence >= p.config.ConfidenceThreshold {
			protocols = append(protocols, *enipInfo)
		}
	}

	// Check for OPC UA protocol
	if p.config.EnableOPCUA {
		if opcuaInfo, err := p.parseOPCUAWithErrorHandling(packet, timestamp); err != nil {
			protocolErr := &IndustrialProtocolError{
				Protocol:    "opcua",
				Packet:      packet,
				Err:         err,
				Context:     "parseOPCUA",
				Recoverable: true,
				Timestamp:   timestamp,
			}
			if handlerErr := p.errorHandler.HandleProtocolError(protocolErr); handlerErr != nil && !p.config.ContinueOnError {
				return nil, handlerErr
			}
		} else if opcuaInfo != nil && opcuaInfo.Confidence >= p.config.ConfidenceThreshold {
			protocols = append(protocols, *opcuaInfo)
		}
	}

	// Check for Modbus TCP protocol
	if p.config.EnableModbus {
		if modbusInfo := p.parseModbusTCP(packet, timestamp); modbusInfo != nil && modbusInfo.Confidence >= p.config.ConfidenceThreshold {
			protocols = append(protocols, *modbusInfo)
		}
	}

	// Check for CIFS Browser protocol
	if cifsInfo := p.parseCIFSBrowser(packet, timestamp); cifsInfo != nil && cifsInfo.Confidence >= p.config.ConfidenceThreshold {
		protocols = append(protocols, *cifsInfo)
	}

	return protocols, nil
}

// parseOPCUAWithErrorHandling parses OPC UA with comprehensive error handling
func (p *IndustrialProtocolParserImpl) parseOPCUAWithErrorHandling(packet gopacket.Packet, timestamp time.Time) (*model.IndustrialProtocolInfo, error) {
	if packet == nil {
		return nil, errors.New("packet is nil")
	}

	// First check if this looks like OPC UA based on ports
	if !p.isOPCUAPort(packet) {
		return nil, nil // Not an error, just not OPC UA
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "opcua",
		Timestamp:      timestamp,
		Confidence:     0.7, // Start with medium confidence
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}

	// Extract port information
	if err := p.extractPortInfo(packet, info, []uint16{4840}); err != nil {
		return nil, fmt.Errorf("failed to extract port info: %w", err)
	}

	// Try to extract OPC UA specific information
	if err := p.extractOPCUADetails(packet, info); err != nil {
		// Log error but continue with basic info
		info.Confidence = 0.5 // Lower confidence due to extraction issues
	} else {
		info.Confidence = 0.9 // High confidence for successful extraction
	}

	return info, nil
}

func (p *IndustrialProtocolParserImpl) DetectDeviceType(protocols []model.IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType {
	if len(protocols) == 0 {
		return model.DeviceTypeUnknown
	}

	// Analyze protocol patterns to determine device type
	ethernetIPCount := 0
	opcuaCount := 0
	modbusCount := 0
	cifsCount := 0
	hasOutboundConnections := false
	hasInboundConnections := false

	// Check CIFS Browser flags for device type hints
	var cifsDeviceType model.IndustrialDeviceType

	for _, protocol := range protocols {
		protocolLower := strings.ToLower(protocol.Protocol)

		switch {
		case strings.Contains(protocolLower, "ethernet"):
			ethernetIPCount++
		case strings.Contains(protocolLower, "opc"):
			opcuaCount++
		case strings.Contains(protocolLower, "modbus"):
			modbusCount++
		case protocolLower == "cifsbrowser":
			cifsCount++
			// Check CIFS Browser specific device identity information
			if len(protocol.DeviceIdentity) > 0 {
				// Check for printer flag
				if isPrinter, ok := protocol.DeviceIdentity["is_printer"].(bool); ok && isPrinter {
					cifsDeviceType = model.DeviceTypePrinter
				}
				// Check for domain controller flag
				if isDomainController, ok := protocol.DeviceIdentity["is_domain_controller"].(bool); ok && isDomainController {
					cifsDeviceType = model.DeviceTypeDomainController
				}
				// Check for workstation flag
				if isWorkstation, ok := protocol.DeviceIdentity["is_workstation"].(bool); ok && isWorkstation {
					if cifsDeviceType == "" { // Don't override more specific types
						cifsDeviceType = model.DeviceTypeEngWorkstation
					}
				}
				// Check for server flag (generic server/IO device)
				if isServer, ok := protocol.DeviceIdentity["is_server"].(bool); ok && isServer {
					if cifsDeviceType == "" { // Don't override more specific types
						cifsDeviceType = model.DeviceTypeIODevice
					}
				}
			}
		}

		if protocol.Direction == "outbound" {
			hasOutboundConnections = true
		} else if protocol.Direction == "inbound" {
			hasInboundConnections = true
		}
	}

	// If CIFS Browser detected a specific device type, return it (highest priority)
	if cifsCount > 0 && cifsDeviceType != "" {
		return cifsDeviceType
	}

	// Classification logic based on protocol usage patterns
	// If multiple protocols, it's an engineering workstation
	if (ethernetIPCount > 0 && opcuaCount > 0) || (ethernetIPCount > 0 && modbusCount > 0) || (opcuaCount > 0 && modbusCount > 0) {
		return model.DeviceTypeEngWorkstation
	}

	// Single protocol analysis - order matters
	if ethernetIPCount > 0 {
		return model.DeviceTypePLC
	}

	if opcuaCount > 0 {
		if hasOutboundConnections && !hasInboundConnections {
			return model.DeviceTypeHMI
		}
		if hasInboundConnections {
			return model.DeviceTypePLC
		}
	}

	if modbusCount > 0 {
		if hasInboundConnections {
			return model.DeviceTypeIODevice
		}
		return model.DeviceTypePLC
	}

	return model.DeviceTypeUnknown
}

func (p *IndustrialProtocolParserImpl) AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern {
	patterns := make([]model.CommunicationPattern, 0)

	// Group flows by source-destination pairs
	flowGroups := make(map[string][]model.Flow)
	for _, flow := range flows {
		key := fmt.Sprintf("%s-%s", flow.SrcIP.String(), flow.DstIP.String())
		flowGroups[key] = append(flowGroups[key], flow)
	}

	// Analyze each group for patterns
	for _, groupFlows := range flowGroups {
		if len(groupFlows) > 0 {
			pattern := p.analyzeFlowGroup(groupFlows)
			if pattern != nil {
				patterns = append(patterns, *pattern)
			}
		}
	}

	return patterns
}

func (p *IndustrialProtocolParserImpl) CollectProtocolUsageStats(deviceID string, protocols []model.IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	if len(protocols) == 0 {
		return nil, errors.New("no protocols provided")
	}

	stats := &model.ProtocolUsageStats{
		DeviceID:          deviceID,
		PacketCount:       int64(len(protocols)),
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
		CommunicationRole: "unknown",
		PortsUsed:         make([]uint16, 0),
	}

	// Determine primary protocol and role
	protocolCounts := make(map[string]int)
	ports := make(map[uint16]bool)
	hasInbound := false
	hasOutbound := false

	for _, protocol := range protocols {
		protocolCounts[protocol.Protocol]++
		ports[protocol.Port] = true

		if protocol.Direction == "inbound" {
			hasInbound = true
		} else if protocol.Direction == "outbound" {
			hasOutbound = true
		}

		if protocol.Timestamp.Before(stats.FirstSeen) {
			stats.FirstSeen = protocol.Timestamp
		}
		if protocol.Timestamp.After(stats.LastSeen) {
			stats.LastSeen = protocol.Timestamp
		}
	}

	// Find most common protocol
	maxCount := 0
	for protocol, count := range protocolCounts {
		if count > maxCount {
			maxCount = count
			stats.Protocol = protocol
		}
	}

	// Determine communication role
	if hasInbound && hasOutbound {
		stats.CommunicationRole = "both"
	} else if hasInbound {
		stats.CommunicationRole = "server"
	} else if hasOutbound {
		stats.CommunicationRole = "client"
	}

	// Convert ports to slice
	for port := range ports {
		stats.PortsUsed = append(stats.PortsUsed, port)
	}

	return stats, nil
}

// Helper method for analyzing flow groups
func (p *IndustrialProtocolParserImpl) analyzeFlowGroup(flows []model.Flow) *model.CommunicationPattern {
	if len(flows) == 0 {
		return nil
	}

	firstFlow := flows[0]
	pattern := &model.CommunicationPattern{
		SourceDevice:        firstFlow.SrcIP.String(),
		DestinationDevice:   firstFlow.DstIP.String(),
		Protocol:            firstFlow.Protocol,
		Frequency:           time.Duration(0),
		DataVolume:          0,
		FlowCount:           0,
		DeviationFrequency:  0.0,
		DeviationDataVolume: 0.0,
		PatternType:         "unknown",
		Criticality:         "low",
	}

	pattern.FlowCount = int64(len(flows))

	// Sort flows by LastSeen time
	sortedFlows := make([]model.Flow, len(flows))
	copy(sortedFlows, flows)
	sort.Slice(sortedFlows, func(i, j int) bool {
		return sortedFlows[i].LastSeen.Before(sortedFlows[j].LastSeen)
	})

	// Calculate frequency as average time between flows
	flowLen := len(sortedFlows)
	if flowLen > 1 {
		timeSpan := sortedFlows[flowLen-1].LastSeen.Sub(sortedFlows[0].FirstSeen)
		pattern.Frequency = timeSpan / time.Duration(flowLen-1)
	} else {
		pattern.Frequency = 0
	}

	// Calculate deviations and dataVolume
	totalBytes := int64(sortedFlows[0].ByteCount)
	if pattern.Frequency > 0 {
		frequencyVarianceSum := float64(0)
		dataVolumeVarianceSum := float64(0)
		for i := 1; i < flowLen; i++ {
			interval := sortedFlows[i].FirstSeen.Sub(sortedFlows[i-1].LastSeen)
			frequencyDeviation := float64(interval - pattern.Frequency)
			frequencyVarianceSum += frequencyDeviation * frequencyDeviation

			dataVolumeDeviation := float64(int64(sortedFlows[i].ByteCount) - (pattern.DataVolume / pattern.FlowCount))
			dataVolumeVarianceSum += dataVolumeDeviation * dataVolumeDeviation

			totalBytes += int64(sortedFlows[i].ByteCount)
		}
		pattern.DeviationFrequency = frequencyVarianceSum / float64(flowLen-1)
		pattern.DeviationDataVolume = dataVolumeVarianceSum / float64(flowLen-1)
	} else {
		pattern.DeviationFrequency = 0.0
		pattern.DeviationDataVolume = 0.0
	}
	pattern.DataVolume = totalBytes

	// Determine pattern type based on frequency and deviations
	if pattern.Frequency > 0 && pattern.DeviationFrequency < float64(pattern.Frequency)/2 {
		pattern.PatternType = PATTERN_TYPE_PERIODIC
	} else if pattern.Frequency > 0 {
		pattern.PatternType = PATTERN_TYPE_EVENT_DRIVEN
	} else if pattern.FlowCount > 0 {
		pattern.PatternType = PATTERN_TYPE_CONTINUOUS
	} else {
		pattern.PatternType = PATTERN_TYPE_UNKNOWN
	}

	// Determine criticality based on pattern type, data volume and deviations
	if pattern.PatternType == PATTERN_TYPE_PERIODIC && pattern.DataVolume > 1000000 {
		pattern.Criticality = CRITICALITY_HIGH
	} else if pattern.PatternType == PATTERN_TYPE_EVENT_DRIVEN && pattern.DeviationDataVolume > 500000 {
		pattern.Criticality = CRITICALITY_MEDIUM
	} else {
		pattern.Criticality = CRITICALITY_LOW
	}

	if err := pattern.Validate(); err != nil {
		log.Error().Err(err).Msg("invalid communication pattern")
		return nil
	}

	return pattern
}

// IndustrialProtocolParserImpl methods

// Validation methods
func (p *IndustrialProtocolParserImpl) validateEtherNetIPLayer(layer interface{}) error {
	if layer == nil {
		return errors.New("EtherNet/IP layer is nil")
	}
	// Additional validation would go here for actual layer type
	return nil
}

func (p *IndustrialProtocolParserImpl) validateOPCUALayer(layer interface{}) error {
	if layer == nil {
		return errors.New("OPC UA layer is nil")
	}
	// Additional validation would go here for actual layer type
	return nil
}

// Safe extraction methods
func (p *IndustrialProtocolParserImpl) safeGetDeviceIdentity(layer interface{}) (map[string]interface{}, error) {
	if layer == nil {
		return nil, errors.New("layer is nil")
	}
	// Extract device identity information safely
	identity := make(map[string]interface{})
	// Implementation would extract actual device identity from layer
	return identity, nil
}

func (p *IndustrialProtocolParserImpl) safeGetCIPInfo(layer interface{}) (map[string]interface{}, error) {
	if layer == nil {
		return nil, errors.New("layer is nil")
	}
	// Extract CIP information safely
	cipInfo := make(map[string]interface{})
	// Implementation would extract actual CIP data from layer
	return cipInfo, nil
}

func (p *IndustrialProtocolParserImpl) safeIsDiscoveryMessage(layer interface{}) bool {
	if layer == nil {
		return false
	}
	// Check if this is a discovery message
	return false // Placeholder implementation
}

func (p *IndustrialProtocolParserImpl) safeGetSecurityInfo(layer interface{}) (map[string]interface{}, error) {
	if layer == nil {
		return nil, errors.New("layer is nil")
	}
	// Extract security information safely
	securityInfo := make(map[string]interface{})
	// Implementation would extract actual security data from layer
	return securityInfo, nil
}

func (p *IndustrialProtocolParserImpl) safeGetServiceInfo(layer interface{}) (map[string]interface{}, error) {
	if layer == nil {
		return nil, errors.New("layer is nil")
	}
	// Extract service information safely
	serviceInfo := make(map[string]interface{})
	// Implementation would extract actual service data from layer
	return serviceInfo, nil
}

func (p *IndustrialProtocolParserImpl) safeIsRealTimeData(layer interface{}) bool {
	if layer == nil {
		return false
	}
	// Check if this is real-time data
	return false // Placeholder implementation
}

// Port detection methods
func (p *IndustrialProtocolParserImpl) isEtherNetIPPort(packet gopacket.Packet) bool {
	if p.isLikelyEtherNetIPPayload(packet) {
		return true
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return tcp.SrcPort == 44818 || tcp.DstPort == 44818
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return udp.SrcPort == 2222 || udp.DstPort == 2222
	}
	return false
}

// isLikelyEtherNetIPPayload returns true if application payload looks like an ENIP encapsulation header.
func (p *IndustrialProtocolParserImpl) isLikelyEtherNetIPPayload(packet gopacket.Packet) bool {
	if app := packet.TransportLayer(); app != nil {
		b := app.LayerContents()
		if len(b) < 24 { // ENIP encapsulation header is 24 bytes
			return false
		}
		cmd := binary.LittleEndian.Uint16(b[0:2])
		length := int(binary.LittleEndian.Uint16(b[2:4]))
		// basic sanity checks: non\-zero command and length consistent with total payload
		if cmd == 0 || length < 0 {
			return false
		}
		// ensure claimed length fits in the remaining payload
		if length <= len(b)-24 {
			return true
		}
	}
	return false
}

func (p *IndustrialProtocolParserImpl) isOPCUAPort(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return tcp.SrcPort == 4840 || tcp.DstPort == 4840
	}
	return false
}

func (p *IndustrialProtocolParserImpl) isModbusTCPPort(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return tcp.SrcPort == 502 || tcp.DstPort == 502
	}
	return false
}

// extractPortInfo extracts port and transport information from a packet
func (p *IndustrialProtocolParserImpl) extractPortInfo(packet gopacket.Packet, info *model.IndustrialProtocolInfo, ports []uint16) error {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		for _, port := range ports {
			if tcp.SrcPort == layers.TCPPort(port) || tcp.DstPort == layers.TCPPort(port) {
				info.Port = port
				info.Direction = p.determineDirection(packet)
				info.AdditionalData["transport"] = "tcp"
				return nil
			}
		}
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		for _, port := range ports {
			if udp.SrcPort == layers.UDPPort(port) || udp.DstPort == layers.UDPPort(port) {
				info.Port = port
				info.Direction = p.determineDirection(packet)
				info.AdditionalData["transport"] = "udp"
				return nil
			}
		}
	}
	return errors.New("no matching ports found")
}

// determineDirection determines the communication direction based on port numbers
func (p *IndustrialProtocolParserImpl) determineDirection(packet gopacket.Packet) string {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort == 44818 || tcp.SrcPort == 4840 || tcp.SrcPort == 502 {
			return "inbound"
		}
		if tcp.DstPort == 44818 || tcp.DstPort == 4840 || tcp.DstPort == 502 {
			return "outbound"
		}
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.SrcPort == 2222 {
			return "inbound"
		}
		if udp.DstPort == 2222 || udp.DstPort == 138 {
			return "outbound"
		}
	}
	return "bidirectional"
}

// Protocol-specific parsing methods

// parseOPCUA parses OPC UA protocol (backward compatibility)
func (p *IndustrialProtocolParserImpl) parseOPCUA(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	info, _ := p.parseOPCUAWithErrorHandling(packet, timestamp)
	return info
}

// parseModbusTCP parses Modbus TCP protocol
func (p *IndustrialProtocolParserImpl) parseModbusTCP(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	if !p.isModbusTCPPort(packet) {
		return nil
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "modbus",
		Timestamp:      timestamp,
		Confidence:     0.7,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}

	if err := p.extractPortInfo(packet, info, []uint16{502}); err != nil {
		return nil
	}

	info.Confidence = 0.8
	return info
}

// parseEtherNetIP parses EtherNet/IP (ENIP) protocol
func (p *IndustrialProtocolParserImpl) parseEtherNetIP(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	if !p.isEtherNetIPPort(packet) {
		return nil
	}
	info := &model.IndustrialProtocolInfo{
		Protocol:       "EtherNet/IP",
		Timestamp:      timestamp,
		Confidence:     0.6,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	// Determine ports and direction
	if err := p.extractPortInfo(packet, info, []uint16{44818, 2222}); err != nil {
		// Not necessarily an error; leave default info
		info.Confidence = 0.5
	} else {
		info.Confidence = 0.9
	}
	return info
}

// parseCIFSBrowser parses CIFS Browser protocol (NetBIOS/Windows network discovery)
func (p *IndustrialProtocolParserImpl) parseCIFSBrowser(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	if !p.isCIFSBrowserPort(packet) {
		return nil
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "CIFSBROWSER",
		Timestamp:      timestamp,
		Confidence:     0.6,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
		Port:           uint16(packet.TransportLayer().(*layers.UDP).SrcPort),
		Direction:      p.determineDirection(packet),
	}

	// Try to extract CIFS Browser specific data
	// Check for CIFS Browser Announcement layer (the most common message type)
	if announcementLayer := packet.Layer(lib_layers.LayerTypeCIFSBrowser); announcementLayer != nil {
		if announcement, ok := announcementLayer.(*lib_layers.CIFSBrowserAnnouncement); ok {
			info.Confidence = 1

			// We can't directly use the iec62443 package functions here (would create circular dependency)
			// Instead, extract basic information
			info.DeviceIdentity["server_name"] = announcement.ServerName
			info.DeviceIdentity["is_workstation"] = announcement.ServerTypeFlags.IsWorkstation
			info.DeviceIdentity["is_server"] = announcement.ServerTypeFlags.IsServer
			info.DeviceIdentity["is_printer"] = announcement.ServerTypeFlags.IsPrintQueueServer
			info.DeviceIdentity["is_domain_controller"] = announcement.ServerTypeFlags.IsDomainController
			info.DeviceIdentity["is_apple"] = announcement.ServerTypeFlags.IsAppleServer

			info.AdditionalData["command"] = announcement.Command.String()
			info.AdditionalData["os_version"] = fmt.Sprintf("%d.%d", announcement.OSMajorVersion, announcement.OSMinorVersion)
		} else {
			fmt.Println("Failed to cast CIFS Browser layer to Announcement")
		}
	} else {
		fmt.Println("CIFS Browser layer not found in packet")
	}

	// Determine port direction
	if err := p.extractPortInfo(packet, info, []uint16{137, 138}); err != nil {
		info.Confidence -= 0.2
	} else {
		info.Confidence = 1
	}

	// Mark as network discovery protocol
	info.SecurityInfo["network_discovery_detected"] = true
	info.SecurityInfo["windows_network_protocol"] = true

	return info
}

// isCIFSBrowserPort checks if packet is CIFS Browser protocol based on port
func (p *IndustrialProtocolParserImpl) isCIFSBrowserPort(packet gopacket.Packet) bool {
	// CIFS Browser uses UDP port 138 (NetBIOS Datagram Service)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return udp.SrcPort == 138 || udp.DstPort == 138
	}

	// Also check for CIFS Browser layer directly
	if packet.Layer(lib_layers.LayerTypeCIFSBrowser) != nil {
		return true
	}

	return false
}

// extractOPCUADetails extracts OPC UA specific information
func (p *IndustrialProtocolParserImpl) extractOPCUADetails(packet gopacket.Packet, info *model.IndustrialProtocolInfo) error {
	// Look for OPC UA layer in the packet
	opcuaLayer := packet.Layer(lib_layers.LayerTypeOPCUA)
	if opcuaLayer == nil {
		// Try to parse from raw application data
		return p.parseRawOPCUAData(packet, info)
	}

	opcua, ok := opcuaLayer.(*lib_layers.OPCUA)
	if !ok {
		return fmt.Errorf("failed to cast layer to OPC UA")
	}

	// Validate the OPC UA layer data
	if err := opcua.Validate(); err != nil {
		return fmt.Errorf("OPC UA validation failed: %w", err)
	}

	// Extract security information
	if err := p.extractOPCUASecurityInfo(opcua, info); err != nil {
		// Log but don't fail completely
		info.AdditionalData["security_extraction_error"] = err.Error()
	}

	// Extract service information
	if err := p.extractOPCUAServiceInfo(opcua, info); err != nil {
		// Log but don't fail completely
		info.AdditionalData["service_extraction_error"] = err.Error()
	}

	// Classify message type and service
	p.classifyOPCUAMessage(opcua, info)

	return nil
}

// parseRawOPCUAData attempts to parse OPC UA from raw packet data
func (p *IndustrialProtocolParserImpl) parseRawOPCUAData(packet gopacket.Packet, info *model.IndustrialProtocolInfo) error {
	// Look for TCP layer
	var payload []byte
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			payload = tcp.Payload
		}
	}

	if len(payload) < 8 { // Minimum OPC UA header size
		return fmt.Errorf("payload too short for OPC UA")
	}

	// Try to parse as OPC UA
	opcua := &lib_layers.OPCUA{}
	if err := opcua.DecodeFromBytes(payload, nil); err != nil {
		return fmt.Errorf("failed to decode OPC UA: %w", err)
	}

	// Validate the parsed data
	if err := opcua.Validate(); err != nil {
		return fmt.Errorf("OPC UA validation failed: %w", err)
	}

	// Extract information from the parsed layer
	if err := p.extractOPCUASecurityInfo(opcua, info); err != nil {
		info.AdditionalData["security_extraction_error"] = err.Error()
	}

	if err := p.extractOPCUAServiceInfo(opcua, info); err != nil {
		info.AdditionalData["service_extraction_error"] = err.Error()
	}

	p.classifyOPCUAMessage(opcua, info)

	return nil
}

// extractOPCUASecurityInfo extracts security information from OPC UA
func (p *IndustrialProtocolParserImpl) extractOPCUASecurityInfo(opcua *lib_layers.OPCUA, info *model.IndustrialProtocolInfo) error {
	if opcua.SecurityPolicy != "" {
		info.SecurityInfo["security_policy"] = opcua.SecurityPolicy
	}
	if opcua.SecurityMode != "" {
		info.SecurityInfo["security_mode"] = opcua.SecurityMode
	}
	if opcua.SecureChannelID != 0 {
		info.SecurityInfo["secure_channel_id"] = opcua.SecureChannelID
	}
	if opcua.ClientCertificate != nil && len(opcua.ClientCertificate) > 0 {
		info.SecurityInfo["has_client_certificate"] = true
		info.SecurityInfo["client_certificate_length"] = len(opcua.ClientCertificate)
	}
	if opcua.ServerCertificate != nil && len(opcua.ServerCertificate) > 0 {
		info.SecurityInfo["has_server_certificate"] = true
		info.SecurityInfo["server_certificate_length"] = len(opcua.ServerCertificate)
	}

	return nil
}

// extractOPCUAServiceInfo extracts service information from OPC UA
func (p *IndustrialProtocolParserImpl) extractOPCUAServiceInfo(opcua *lib_layers.OPCUA, info *model.IndustrialProtocolInfo) error {
	if opcua.ServiceType != "" {
		info.AdditionalData["opcua_service_type"] = opcua.ServiceType
	}
	if opcua.ServiceNodeID != 0 {
		info.AdditionalData["service_node_id"] = opcua.ServiceNodeID
	}
	if opcua.ApplicationURI != "" {
		info.AdditionalData["application_uri"] = opcua.ApplicationURI
	}
	if opcua.ProductURI != "" {
		info.AdditionalData["product_uri"] = opcua.ProductURI
	}
	if opcua.ApplicationName != "" {
		info.AdditionalData["application_name"] = opcua.ApplicationName
	}
	if opcua.RequestHandle != 0 {
		info.AdditionalData["request_handle"] = opcua.RequestHandle
	}

	return nil
}

// classifyOPCUAMessage classifies OPC UA message type and service
func (p *IndustrialProtocolParserImpl) classifyOPCUAMessage(opcua *lib_layers.OPCUA, info *model.IndustrialProtocolInfo) {
	// Classify based on message type
	switch opcua.MessageType {
	case "HEL":
		info.ServiceType = "handshake"
		info.MessageType = "hello"
		info.IsDiscovery = true
	case "ACK":
		info.ServiceType = "handshake"
		info.MessageType = "acknowledge"
		info.IsDiscovery = true
	case "OPN":
		info.ServiceType = "secure_channel"
		info.MessageType = "open_secure_channel"
		info.IsConfiguration = true
	case "CLO":
		info.ServiceType = "secure_channel"
		info.MessageType = "close_secure_channel"
		info.IsConfiguration = true
	case "MSG":
		info.ServiceType = "service_call"
		info.MessageType = "message"
		// Could be real-time data depending on service
		if opcua.ServiceType != "" {
			// Classify based on service type
			switch opcua.ServiceType {
			case "Read": // Read service
				info.MessageType = "read_request"
			case "Write": // Write service
				info.MessageType = "write_request"
				info.IsConfiguration = true
			case "Call": // Method call
				info.MessageType = "method_call"
			case "CreateSubscription": // Create subscription
				info.MessageType = "create_subscription"
				info.IsRealTimeData = true
			case "Publish": // Publish request
				info.MessageType = "publish_request"
				info.IsRealTimeData = true
			}
		}
	default:
		info.ServiceType = "unknown"
		info.MessageType = "unknown"
	}

	// Additional security classification
	if opcua.SecurityPolicy != "" && opcua.SecurityPolicy != "http://opcfoundation.org/UA/SecurityPolicy#None" {
		info.SecurityInfo["secure_communication"] = true
	} else {
		info.SecurityInfo["secure_communication"] = false
	}
}

func (p *IndustrialProtocolParserImpl) DetermineCriticality(protocol string, volume int64, count int) interface{} {
	proto := strings.ToLower(protocol)
	switch proto {
	case "ethernetip", "ethernet/ip":
		if volume > 10000 || count >= 25 {
			return CRITICALITY_CRITICAL
		} else if volume > 2000 || count >= 10 {
			return CRITICALITY_HIGH
		}
		return CRITICALITY_MEDIUM
	case "opc ua", "opcua":
		if volume > 50000 || count >= 50 {
			return CRITICALITY_HIGH
		} else if volume > 20000 || count >= 20 {
			return CRITICALITY_MEDIUM
		}
		return CRITICALITY_LOW
	default:
		// Unknown protocols: treat high volumes and counts as medium
		if volume > 100000 || count > 100 {
			return CRITICALITY_MEDIUM
		}
		return CRITICALITY_LOW
	}
}

func (p *IndustrialProtocolParserImpl) DeterminePatternType(flows []model.Flow) interface{} {
	patterns := p.AnalyzeCommunicationPatterns(flows)
	if len(patterns) == 0 {
		return ""
	}
	return patterns[0].PatternType
}
