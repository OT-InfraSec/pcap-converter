package parser

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
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
		EnableDNP3:       true,
		EnableS7:         true,

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

	// Modbus connections and unfinished messages, see detect.ModbusTracker.
	modbusMu sync.Mutex
	modbus   *detect.ModbusTracker

	// EtherNet/IP connections and unfinished messages, see detect.ENIPTracker.
	enipMu sync.Mutex
	enip   *detect.ENIPTracker

	// S7comm connections and unfinished frames, see detect.S7Tracker.
	// DNP3 connections and unfinished frames and fragments, see detect.DNP3Tracker.
	dnp3Mu sync.Mutex
	dnp3   *detect.DNP3Tracker

	s7Mu sync.Mutex
	s7   *detect.S7Tracker

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

	// Check for S7comm
	if p.config.EnableS7 {
		if s7Info := p.parseS7(packet, timestamp); s7Info != nil && s7Info.Confidence >= p.config.ConfidenceThreshold {
			protocols = append(protocols, *s7Info)
		}
	}

	// Check for DNP3
	if p.config.EnableDNP3 {
		if dnpInfo := p.parseDNP3(packet, timestamp); dnpInfo != nil && dnpInfo.Confidence >= p.config.ConfidenceThreshold {
			protocols = append(protocols, *dnpInfo)
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
	ethernetIPTCPCount := 0
	ethernetIPUDPCount := 0
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
		case strings.Contains(protocolLower, "ethernet/ip(tcp)"):
			ethernetIPTCPCount++
		case strings.Contains(protocolLower, "ethernet/ip(udp)"):
			ethernetIPUDPCount++
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
	if (ethernetIPTCPCount > 0 && opcuaCount > 0) || (ethernetIPTCPCount > 0 && modbusCount > 0) || (opcuaCount > 0 && modbusCount > 0) {
		return model.DeviceTypeEngWorkstation
	}

	// Single protocol analysis - order matters
	if ethernetIPUDPCount > 0 {
		return model.DeviceTypePLC
	}

	if opcuaCount > 0 {
		if hasOutboundConnections && !hasInboundConnections {
			return model.DeviceTypePLC
		}
		if hasInboundConnections {
			return model.DeviceTypeHMI
		}
	}

	if modbusCount > 0 {
		if hasInboundConnections {
			return model.DeviceTypeIODevice
		}
		return model.DeviceTypePLC
	}

	if ethernetIPTCPCount > 0 {
		return model.DeviceTypeHMI
	}

	return model.DeviceTypeUnknown
}

func (p *IndustrialProtocolParserImpl) AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern {
	patterns := make([]model.CommunicationPattern, 0)

	// Group flows by source-destination pairs
	/*flowGroups := make(map[string][]model.Flow)
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
	}*/

	return patterns
}

func (p *IndustrialProtocolParserImpl) CollectProtocolUsageStats(deviceID string, protocols []model.IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	if len(protocols) == 0 {
		return nil, errors.New("no protocols provided")
	}

	stats := &model.ProtocolUsageStats{
		DeviceID:          deviceID,
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
	totalBytes := int64(sortedFlows[0].ByteCountOut + sortedFlows[0].ByteCountIn)
	if pattern.Frequency > 0 {
		frequencyVarianceSum := float64(0)
		dataVolumeVarianceSum := float64(0)
		for i := 1; i < flowLen; i++ {
			interval := sortedFlows[i].FirstSeen.Sub(sortedFlows[i-1].LastSeen)
			frequencyDeviation := float64(interval - pattern.Frequency)
			frequencyVarianceSum += frequencyDeviation * frequencyDeviation

			flowBytes := int64(sortedFlows[i].ByteCountOut + sortedFlows[i].ByteCountIn)
			dataVolumeDeviation := float64(flowBytes - (pattern.DataVolume / pattern.FlowCount))
			dataVolumeVarianceSum += dataVolumeDeviation * dataVolumeDeviation

			totalBytes += flowBytes
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

// transportPayload returns the transport protocol, ports and application
// payload (not the TCP/UDP header) of a packet.
func transportPayload(packet gopacket.Packet) (detect.Transport, uint16, uint16, []byte, bool) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return detect.TCP, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.Payload, true
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return detect.UDP, uint16(udp.SrcPort), uint16(udp.DstPort), udp.Payload, true
	}
	return 0, 0, 0, nil, false
}

// detectEtherNetIP runs the registry's EtherNet/IP probe on the packet payload.
// The returned match is nil if the packet is not EtherNet/IP.
func (p *IndustrialProtocolParserImpl) detectEtherNetIP(packet gopacket.Packet) *detect.Match {
	return p.detectProtocol(packet, "EtherNet/IP")
}

// detectProtocol runs the registry on the packet payload and returns the match
// for the named protocol, or nil.
func (p *IndustrialProtocolParserImpl) detectProtocol(packet gopacket.Packet, name string) *detect.Match {
	transport, src, dst, payload, ok := transportPayload(packet)
	if !ok {
		return nil
	}
	for _, m := range detect.Default().Detect(transport, src, dst, payload) {
		if m.Protocol == name {
			m := m
			return &m
		}
	}
	return nil
}

func (p *IndustrialProtocolParserImpl) isOPCUAPort(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return tcp.SrcPort == 4840 || tcp.DstPort == 4840
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
		if tcp.SrcPort == 44818 || tcp.SrcPort == 4840 || tcp.SrcPort == 502 || uint16(tcp.SrcPort) == detect.DNP3Port || uint16(tcp.SrcPort) == detect.S7Port {
			return "inbound"
		}
		if tcp.DstPort == 44818 || tcp.DstPort == 4840 || tcp.DstPort == 502 || uint16(tcp.DstPort) == detect.DNP3Port || uint16(tcp.DstPort) == detect.S7Port {
			return "outbound"
		}
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.SrcPort == 2222 || udp.SrcPort == 44818 || uint16(udp.SrcPort) == detect.DNP3Port {
			return "inbound"
		}
		if udp.DstPort == 2222 || udp.DstPort == 44818 || udp.DstPort == 138 || uint16(udp.DstPort) == detect.DNP3Port {
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

// parseModbusTCP parses Modbus TCP protocol.
//
// A connection is recognised as Modbus by content (an MBAP header with
// protocol ID 0, a consistent length and a valid function code); port 502 only
// raises confidence. From then on every segment of it is Modbus: malformed
// frames are decoded and reported as events (as Suricata does), and a message
// split across segments is decoded when its last segment arrives. See
// detect.ModbusTracker. A packet on port 502 without payload, such as a
// handshake segment, is reported below the default confidence threshold.
func (p *IndustrialProtocolParserImpl) parseModbusTCP(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok || transport != detect.TCP {
		return nil
	}
	m := p.detectProtocol(packet, "Modbus")

	var msgs []detect.ModbusMessage
	known := false
	if nl := packet.NetworkLayer(); nl != nil {
		key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
		hint := srcPort == detect.ModbusPort || dstPort == detect.ModbusPort
		p.modbusMu.Lock()
		if p.modbus == nil {
			p.modbus = detect.NewModbusTracker()
		}
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		msgs = p.modbus.FeedTCP(key, dstPort == detect.ModbusPort, detect.TCPSegment{
			Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
		}, hint)
		known = p.modbus.Known(key)
		p.modbusMu.Unlock()
	}
	if m == nil && !known {
		return nil
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "modbus",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	portErr := p.extractPortInfo(packet, info, []uint16{detect.ModbusPort})

	switch {
	case m != nil && m.Result == detect.Recognized && m.PortHint && portErr == nil:
		info.Confidence = 0.9
	case m != nil && m.Result == detect.Recognized:
		info.Confidence = 0.8
	case known && len(payload) > 0 && portErr == nil:
		// Inside a recognised connection: a continuation segment, a bare
		// header or a malformed frame.
		info.Confidence = 0.9
	case known && len(payload) > 0:
		info.Confidence = 0.8
	default:
		info.Confidence = 0.5
	}
	decodeModbusInto(msgs, info)
	return info
}

// parseEtherNetIP parses EtherNet/IP (ENIP) protocol.
//
// Detection is by content (see detect.ProbeENIPEncapsulation); the port only
// raises confidence. A packet on an EtherNet/IP port that carries no payload
// (for example a TCP handshake segment) or only a partial header is reported
// with low confidence, which the default threshold filters out.
func (p *IndustrialProtocolParserImpl) parseEtherNetIP(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	m := p.detectEtherNetIP(packet)
	msgs, known := p.enipMessages(packet)
	if m == nil && !known {
		return nil
	}

	protocolName := "EtherNet/IP"
	ports := []uint16{detect.ENIPPortExplicit, detect.ENIPPortImplicit}
	switch packet.TransportLayer().(type) {
	case *layers.TCP:
		protocolName = "EtherNet/IP(TCP)"
		ports = []uint16{detect.ENIPPortExplicit}
	case *layers.UDP:
		protocolName = "EtherNet/IP(UDP)"
		ports = []uint16{detect.ENIPPortExplicit, detect.ENIPPortImplicit}
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       protocolName,
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	// Port and direction are best effort; a content match on another port is
	// still EtherNet/IP.
	portErr := p.extractPortInfo(packet, info, ports)

	switch {
	case m != nil && m.Result == detect.Recognized && m.PortHint && portErr == nil:
		info.Confidence = 0.9
	case m != nil && m.Result == detect.Recognized:
		info.Confidence = 0.8
	case known && portErr == nil:
		// Inside a recognised connection: a continuation segment, or a message
		// the strict probe would not accept first.
		info.Confidence = 0.9
	case known:
		info.Confidence = 0.8
	default:
		// Hint port with an empty or partial payload: not enough evidence.
		info.Confidence = 0.5
	}
	decodeENIPInto(msgs, info)
	return info
}

// enipMessages returns the encapsulation messages the packet completes, and
// whether its TCP connection is known to be EtherNet/IP. A UDP datagram stands
// alone; implicit I/O (UDP 2222) has no encapsulation header and is not decoded.
func (p *IndustrialProtocolParserImpl) enipMessages(packet gopacket.Packet) ([]detect.ENIPMessage, bool) {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok {
		return nil, false
	}
	if transport == detect.UDP {
		if msg, ok := detect.DecodeENIPDatagram(payload); ok {
			return []detect.ENIPMessage{msg}, false
		}
		return nil, false
	}
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	nl := packet.NetworkLayer()
	if tcp == nil || nl == nil {
		return nil, false
	}
	key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
	hint := srcPort == detect.ENIPPortExplicit || dstPort == detect.ENIPPortExplicit
	p.enipMu.Lock()
	defer p.enipMu.Unlock()
	if p.enip == nil {
		p.enip = detect.NewENIPTracker()
	}
	msgs := p.enip.FeedTCP(key, dstPort == detect.ENIPPortExplicit, detect.TCPSegment{
		Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
	}, hint)
	return msgs, p.enip.Known(key)
}

// decodeENIPInto adds the decoded view of the packet's messages: the command,
// the CIP request or reply, and, for a ListIdentity reply, the identity of the
// device that answered. Details come from the first message; events cover all.
func decodeENIPInto(msgs []detect.ENIPMessage, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var events []string
	for _, m := range msgs {
		events = append(events, m.Events...)
	}
	m := msgs[0]
	info.MessageType = m.CommandName
	info.AdditionalData["command"] = m.Command
	info.AdditionalData["command_name"] = m.CommandName
	info.AdditionalData["status"] = m.Status
	info.AdditionalData["status_name"] = m.StatusName
	info.AdditionalData["session_handle"] = m.Session
	info.AdditionalData["message_count"] = len(msgs)
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	switch m.Command {
	case detect.ENIPListIdentity, detect.ENIPListServices, detect.ENIPListInterfaces:
		info.IsDiscovery = true
	}
	if m.RegisterSession != nil {
		info.AdditionalData["protocol_version"] = m.RegisterSession.ProtocolVersion
	}
	for _, it := range m.Items {
		if id := it.Identity; id != nil {
			info.DeviceIdentity["vendor_id"] = id.VendorID
			info.DeviceIdentity["device_type"] = id.DeviceType
			info.DeviceIdentity["product_code"] = id.ProductCode
			info.DeviceIdentity["revision"] = fmt.Sprintf("%d.%d", id.RevisionMajor, id.RevisionMinor)
			info.DeviceIdentity["serial"] = id.Serial
			info.DeviceIdentity["product_name"] = id.ProductName
			info.DeviceIdentity["status"] = id.Status
			info.DeviceIdentity["state"] = id.State
			info.DeviceIdentity["ip_address"] = id.IP
			break
		}
	}
	if c := m.CIP; c != nil {
		info.AdditionalData["cip_service"] = c.Service
		info.AdditionalData["cip_service_name"] = c.ServiceName
		info.AdditionalData["cip_is_response"] = c.IsResponse
		if c.IsResponse {
			info.AdditionalData["cip_status"] = c.GeneralStatus
			info.AdditionalData["cip_status_name"] = c.GeneralStatusName
		} else {
			if c.Class >= 0 {
				info.AdditionalData["cip_class"] = c.Class
			}
			if c.Instance >= 0 {
				info.AdditionalData["cip_instance"] = c.Instance
			}
			if c.Attribute >= 0 {
				info.AdditionalData["cip_attribute"] = c.Attribute
			}
			if c.Symbol != "" {
				info.AdditionalData["cip_symbol"] = c.Symbol
			}
		}
		switch c.Service {
		case 0x02, 0x04, 0x10, 0x4d, 0x53:
			info.IsConfiguration = true // writes
		}
	}
}

// parseCIFSBrowser parses CIFS Browser protocol (NetBIOS/Windows network discovery)
func (p *IndustrialProtocolParserImpl) parseCIFSBrowser(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	if !p.isCIFSBrowserPort(packet) {
		return nil
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "cifsbrowser",
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
	switch {
	case proto == "ethernetip" || strings.HasPrefix(proto, "ethernet/ip"):
		if volume > 10000 || count >= 25 {
			return CRITICALITY_CRITICAL
		} else if volume > 2000 || count >= 10 {
			return CRITICALITY_HIGH
		}
		return CRITICALITY_MEDIUM
	case proto == "opc ua" || proto == "opcua":
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

// decodeModbusInto adds the function-level view of the segment's messages:
// what was asked (function, address range) or answered (exception). The
// details come from the first message; the access class, function codes and
// events cover all of them.
func decodeModbusInto(msgs []detect.ModbusMessage, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var codes []uint8
	var events []string
	access := detect.ModbusUnknown
	rank := map[detect.ModbusAccess]int{detect.ModbusUnknown: 0, detect.ModbusOther: 1, detect.ModbusRead: 2,
		detect.ModbusDiagnostic: 3, detect.ModbusReadWrite: 4, detect.ModbusWrite: 5}
	for i, m := range msgs {
		codes = append(codes, m.FunctionCode)
		events = append(events, m.Events...)
		if rank[m.Access] > rank[access] {
			access = m.Access
		}
		if i > 0 {
			continue
		}
		info.MessageType = m.FunctionName
		info.AdditionalData["function_code"] = m.FunctionCode
		info.AdditionalData["transaction_id"] = m.TransactionID
		info.AdditionalData["unit_id"] = m.UnitID
		info.AdditionalData["is_exception"] = m.IsException
		if m.IsException {
			info.AdditionalData["exception_code"] = m.ExceptionCode
			if m.ExceptionName != "" {
				info.AdditionalData["exception"] = m.ExceptionName
			}
		}
		if m.Address >= 0 {
			info.AdditionalData["address"] = m.Address
			info.AdditionalData["quantity"] = m.Quantity
		}
		if m.WriteAddress >= 0 {
			info.AdditionalData["write_address"] = m.WriteAddress
			info.AdditionalData["write_quantity"] = m.WriteQuantity
		}
	}
	info.AdditionalData["access"] = string(access)
	info.AdditionalData["message_count"] = len(codes)
	info.AdditionalData["function_codes"] = codes
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	info.IsConfiguration = access == detect.ModbusWrite || access == detect.ModbusReadWrite
}

// parseDNP3 parses DNP3 (IEEE 1815) over TCP and UDP. A connection is DNP3
// when a payload starts with a link frame (start bytes 0x05 0x64 and a valid
// length), as in Suricata; the port only raises the confidence.
func (p *IndustrialProtocolParserImpl) parseDNP3(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok {
		return nil
	}
	var msgs []detect.DNP3Message
	known := false
	switch transport {
	case detect.UDP:
		msgs = detect.DecodeDNP3Datagram(payload)
	case detect.TCP:
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		nl := packet.NetworkLayer()
		if tcp == nil || nl == nil {
			return nil
		}
		key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
		hint := srcPort == detect.DNP3Port || dstPort == detect.DNP3Port
		p.dnp3Mu.Lock()
		if p.dnp3 == nil {
			p.dnp3 = detect.NewDNP3Tracker()
		}
		msgs = p.dnp3.FeedTCP(key, dstPort == detect.DNP3Port, detect.TCPSegment{
			Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
		}, hint)
		known = p.dnp3.Known(key)
		p.dnp3Mu.Unlock()
	}
	if len(msgs) == 0 && !known {
		return nil
	}
	info := &model.IndustrialProtocolInfo{
		Protocol:       "dnp3",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	portErr := p.extractPortInfo(packet, info, []uint16{detect.DNP3Port})
	switch {
	case len(msgs) > 0 && portErr == nil:
		info.Confidence = 0.9
	case len(msgs) > 0:
		info.Confidence = 0.8
	case portErr == nil:
		info.Confidence = 0.8 // continuation segment of a recognised connection
	default:
		info.Confidence = 0.5
	}
	decodeDNP3Into(msgs, info)
	return info
}

// decodeDNP3Into adds the decoded view of the packet's frames: link addresses
// and function, and the application function, IIN and object headers of the
// first completed fragment. Events cover all frames.
func decodeDNP3Into(msgs []detect.DNP3Message, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var events []string
	var app *detect.DNP3Message
	for i, m := range msgs {
		events = append(events, m.Events...)
		if app == nil && m.App != nil {
			app = &msgs[i]
		}
	}
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	info.AdditionalData["message_count"] = len(msgs)
	m := msgs[0]
	if app != nil {
		m = *app
	}
	f := m.Frame
	info.AdditionalData["source_address"] = f.Src
	info.AdditionalData["destination_address"] = f.Dest
	info.AdditionalData["from_master"] = f.FromMaster()
	if info.Direction == "" {
		// Not on the DNP3 port: the link layer's DIR bit says which side sent it,
		// the master being the client.
		info.Direction = "inbound"
		if f.FromMaster() {
			info.Direction = "outbound"
		}
	}
	info.AdditionalData["link_function"] = f.LinkFunction()
	info.AdditionalData["link_function_name"] = m.LinkName
	info.MessageType = m.LinkName
	if m.HasTransport {
		info.AdditionalData["transport_seq"] = m.TransportSeq
	}
	a := m.App
	if a == nil {
		return
	}
	info.MessageType = a.FunctionName
	info.AdditionalData["function"] = a.Function
	info.AdditionalData["function_name"] = a.FunctionName
	info.AdditionalData["app_sequence"] = a.Sequence()
	info.AdditionalData["unsolicited"] = a.Unsolicited()
	info.AdditionalData["confirm_requested"] = a.Confirm()
	if a.IsResponse {
		info.AdditionalData["iin"] = a.IIN
	}
	info.AdditionalData["object_count"] = len(a.Objects)
	if len(a.Objects) > 0 {
		o := a.Objects[0]
		info.AdditionalData["group"] = o.Group
		info.AdditionalData["variation"] = o.Variation
		info.AdditionalData["qualifier"] = o.Qualifier
		info.AdditionalData["points"] = o.Count
	}
	switch a.Function {
	case 2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 25, 26, 27, 31:
		// Writes, controls, restarts, application and unsolicited control,
		// class assignment, file changes and configuration activation.
		info.IsConfiguration = true
	}
	if f.FromMaster() {
		info.DeviceIdentity["dnp3_master_address"] = f.Src
	} else {
		info.DeviceIdentity["dnp3_outstation_address"] = f.Src
	}
}

// parseS7 parses S7comm (Siemens, ISO-on-TCP). A connection is S7 when its data
// TPDUs carry the S7 protocol id; port 102 alone proves nothing (MMS uses it).
// The connection request on that port is decoded for its rack and slot, which
// later S7 messages of the connection carry, but it is not reported as S7 on
// its own: the result is below the default confidence threshold until a PDU
// shows the protocol.
func (p *IndustrialProtocolParserImpl) parseS7(packet gopacket.Packet, timestamp time.Time) *model.IndustrialProtocolInfo {
	transport, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok || transport != detect.TCP {
		return nil
	}
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	nl := packet.NetworkLayer()
	if tcp == nil || nl == nil {
		return nil
	}
	key := connKey(transport, nl.NetworkFlow().Src().String(), srcPort, nl.NetworkFlow().Dst().String(), dstPort, model.VLANTag{})
	hint := srcPort == detect.S7Port || dstPort == detect.S7Port
	p.s7Mu.Lock()
	if p.s7 == nil {
		p.s7 = detect.NewS7Tracker()
	}
	msgs := p.s7.FeedTCP(key, dstPort == detect.S7Port, detect.TCPSegment{
		Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: payload,
	}, hint)
	plus := p.s7.SawS7Plus(key)
	known := p.s7.SawS7(key) || plus
	p.s7Mu.Unlock()
	if len(msgs) == 0 && !known {
		return nil
	}
	hasS7 := false
	for _, m := range msgs {
		hasS7 = hasS7 || m.HasS7 || m.Plus != nil
		plus = plus || m.Plus != nil
	}

	info := &model.IndustrialProtocolInfo{
		Protocol:       "s7",
		Timestamp:      timestamp,
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}
	portErr := p.extractPortInfo(packet, info, []uint16{detect.S7Port})
	switch {
	case hasS7 && portErr == nil:
		info.Confidence = 0.9
	case hasS7:
		info.Confidence = 0.8
	case known && len(payload) > 0 && portErr == nil:
		// A continuation segment of a connection that has shown S7 PDUs.
		info.Confidence = 0.8
	default:
		info.Confidence = 0.5
	}
	if plus {
		// S7CommPlus (S7-1200 fw 4+, S7-1500): same port and framing, different PDU.
		info.Protocol = "s7commplus"
	}
	decodeS7Into(msgs, info)
	return info
}

// decodeS7Into adds the decoded view of the packet's messages: the S7 service
// (function, items, data), the connection's rack and slot, and for an SZL reply
// the identity of the CPU. Details come from the first S7 message; events cover
// all messages.
func decodeS7Into(msgs []detect.S7Message, info *model.IndustrialProtocolInfo) {
	if len(msgs) == 0 {
		return
	}
	var events []string
	var first *detect.S7Message
	for i, m := range msgs {
		events = append(events, m.Events...)
		if first == nil && (m.HasS7 || m.Plus != nil) {
			first = &msgs[i]
		}
	}
	if len(events) > 0 {
		info.AdditionalData["events"] = events
	}
	info.AdditionalData["message_count"] = len(msgs)
	m := msgs[0]
	if first != nil {
		m = *first
	}
	info.AdditionalData["cotp_type"] = m.COTPName
	if m.Rack >= 0 {
		info.AdditionalData["rack"] = m.Rack
		info.AdditionalData["slot"] = m.Slot
	}
	if m.TPDUSize > 0 {
		info.AdditionalData["tpdu_size"] = m.TPDUSize
	}
	if h := m.Plus; h != nil {
		info.AdditionalData["s7plus_version"] = h.Version
		info.AdditionalData["s7plus_opcode"] = h.Opcode
		info.AdditionalData["s7plus_opcode_name"] = h.OpcodeName
		info.MessageType = h.OpcodeName
		if h.HasFields {
			info.AdditionalData["s7plus_function"] = h.Function
			info.AdditionalData["s7plus_function_name"] = h.FunctionName
			info.AdditionalData["s7plus_sequence"] = h.Sequence
			info.AdditionalData["s7plus_session_id"] = h.SessionID
		}
		return
	}
	if !m.HasS7 {
		return
	}
	info.MessageType = m.ROSCTRName
	info.AdditionalData["rosctr"] = m.ROSCTR
	info.AdditionalData["rosctr_name"] = m.ROSCTRName
	info.AdditionalData["pdu_reference"] = m.PDURef
	info.AdditionalData["function"] = m.Function
	info.AdditionalData["function_name"] = m.FunctionName
	if m.ErrorClass != 0 || m.ErrorCode != 0 {
		info.AdditionalData["error_class"] = m.ErrorClass
		info.AdditionalData["error_code"] = m.ErrorCode
	}
	if m.Setup != nil {
		info.AdditionalData["pdu_length"] = m.Setup.PDULength
	}
	if len(m.Items) > 0 {
		it := m.Items[0]
		info.AdditionalData["item_count"] = len(m.Items)
		info.AdditionalData["area"] = it.Area
		info.AdditionalData["area_name"] = it.AreaName
		info.AdditionalData["db_number"] = it.DB
		info.AdditionalData["address"] = it.ByteAddress
		info.AdditionalData["bit"] = it.Bit
		info.AdditionalData["length"] = it.Length
	}
	if m.PLCService != "" {
		info.AdditionalData["plc_service"] = m.PLCService
	}
	switch {
	case m.ROSCTR == 1 && (m.Function == 0x05 || m.Function == 0x28 || m.Function == 0x29 ||
		(m.Function >= 0x1a && m.Function <= 0x1f)):
		info.IsConfiguration = true // writes, PLC start and stop, program transfer
	}
	if u := m.Userdata; u != nil {
		info.AdditionalData["function_group"] = u.FunctionGroup
		info.AdditionalData["function_group_name"] = u.FunctionGroupName
		info.AdditionalData["userdata_type"] = u.TypeName
		if u.SZLID != 0 {
			info.AdditionalData["szl_id"] = u.SZLID
			info.AdditionalData["szl_index"] = u.SZLIndex
		}
		if u.FunctionGroup == 4 && u.SubFunction == 1 {
			info.IsDiscovery = true
		}
		if u.FunctionGroup == 7 && (u.SubFunction == 2 || u.SubFunction == 4) {
			info.IsConfiguration = true // set clock
		}
		if id := u.Identity; id != nil {
			names := map[uint16]string{1: "system_name", 2: "module_name", 3: "plant_id", 4: "copyright", 5: "serial_number", 7: "module_type_name", 8: "memory_card_serial"}
			for idx, v := range id.Strings {
				if k, ok := names[idx]; ok {
					info.DeviceIdentity[k] = v
				}
			}
			if id.OrderNumber != "" {
				info.DeviceIdentity["order_number"] = id.OrderNumber
				info.DeviceIdentity["module_type"] = id.ModuleType
				info.DeviceIdentity["version"] = fmt.Sprintf("%d.%d", id.Version[0], id.Version[1])
			}
		}
	}
}
