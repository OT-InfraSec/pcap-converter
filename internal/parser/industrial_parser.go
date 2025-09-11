package parser

import (
	"errors"
	"fmt"
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
	enableEtherNetIP    bool
	enableOPCUA         bool
	errorHandler        ErrorHandler
}

func (p *IndustrialProtocolParserImpl) DetectDeviceType(protocols []IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType {
	//TODO implement me
	panic("implement me: DetectDeviceType")
}

func (p *IndustrialProtocolParserImpl) AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern {
	//TODO implement me
	panic("implement me: AnalyzeCommunicationPatterns")
}

func (p *IndustrialProtocolParserImpl) CollectProtocolUsageStats(deviceID string, protocols []IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	//TODO implement me
	panic("implement me: CollectProtocolUsageStats")
}

// NewIndustrialProtocolParser creates a new instance of IndustrialProtocolParser
func NewIndustrialProtocolParser() IndustrialProtocolParser {
	return &IndustrialProtocolParserImpl{
		enabledProtocols: map[string]bool{
			"EtherNet/IP": true,
			"OPC UA":      true,
			"Modbus":      true,
		},
		confidenceThreshold: 0.7,
		enableEtherNetIP:    true,
		enableOPCUA:         true,
		errorHandler:        NewNoOpErrorHandler(),
	}
}

// NewIndustrialProtocolParserWithErrorHandler creates a new parser with specified error handler
func NewIndustrialProtocolParserWithErrorHandler(errorHandler ErrorHandler) IndustrialProtocolParser {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)
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

// ParseIndustrialProtocols analyzes a packet for industrial protocol information
func (p *IndustrialProtocolParserImpl) ParseIndustrialProtocols(packet gopacket.Packet) ([]IndustrialProtocolInfo, error) {
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
		return []IndustrialProtocolInfo{}, nil
	}

	if p.errorHandler.IsThresholdExceeded() {
		return nil, errors.New("error threshold exceeded, stopping industrial protocol parsing")
	}

	var protocols []IndustrialProtocolInfo
	timestamp := packet.Metadata().Timestamp

	// Check for EtherNet/IP protocol
	if p.enableEtherNetIP {
		if ethernetIPInfo, err := p.parseEtherNetIPWithErrorHandling(packet, timestamp); err != nil {
			protocolErr := &IndustrialProtocolError{
				Protocol:    "ethernetip",
				Packet:      packet,
				Err:         err,
				Context:     "parseEtherNetIP",
				Recoverable: true,
				Timestamp:   timestamp,
			}
			p.errorHandler.HandleProtocolError(protocolErr)
		} else if ethernetIPInfo != nil {
			protocols = append(protocols, *ethernetIPInfo)
		}
	}

	// Check for OPC UA protocol
	if p.enableOPCUA {
		if opcuaInfo, err := p.parseOPCUAWithErrorHandling(packet, timestamp); err != nil {
			protocolErr := &IndustrialProtocolError{
				Protocol:    "opcua",
				Packet:      packet,
				Err:         err,
				Context:     "parseOPCUA",
				Recoverable: true,
				Timestamp:   timestamp,
			}
			p.errorHandler.HandleProtocolError(protocolErr)
		} else if opcuaInfo != nil {
			protocols = append(protocols, *opcuaInfo)
		}
	}

	// Check for Modbus TCP protocol
	if modbusInfo := p.parseModbusTCP(packet, timestamp); modbusInfo != nil {
		protocols = append(protocols, *modbusInfo)
	}

	return protocols, nil
}

// parseEtherNetIPWithErrorHandling parses EtherNet/IP with comprehensive error handling
func (p *IndustrialProtocolParserImpl) parseEtherNetIPWithErrorHandling(packet gopacket.Packet, timestamp time.Time) (*IndustrialProtocolInfo, error) {
	if packet == nil {
		return nil, errors.New("packet is nil")
	}

	// First check if this looks like EtherNet/IP based on ports
	if !p.isEtherNetIPPort(packet) {
		return nil, nil // Not an error, just not EtherNet/IP
	}

	info := &IndustrialProtocolInfo{
		Protocol:       "ethernetip",
		Timestamp:      timestamp,
		Confidence:     0.7, // Start with medium confidence
		DeviceIdentity: make(map[string]interface{}),
		SecurityInfo:   make(map[string]interface{}),
		AdditionalData: make(map[string]interface{}),
	}

	// Extract port information
	if err := p.extractPortInfo(packet, info, []uint16{44818, 2222}); err != nil {
		return nil, fmt.Errorf("failed to extract port info: %w", err)
	}

	// Try to extract EtherNet/IP specific information
	if err := p.extractEtherNetIPDetails(packet, info); err != nil {
		// Log error but continue with basic info
		info.Confidence = 0.5 // Lower confidence due to extraction issues
	} else {
		info.Confidence = 0.9 // High confidence for successful extraction
	}

	return info, nil
}

// parseOPCUAWithErrorHandling parses OPC UA with comprehensive error handling
func (p *IndustrialProtocolParserImpl) parseOPCUAWithErrorHandling(packet gopacket.Packet, timestamp time.Time) (*IndustrialProtocolInfo, error) {
	if packet == nil {
		return nil, errors.New("packet is nil")
	}

	// First check if this looks like OPC UA based on ports
	if !p.isOPCUAPort(packet) {
		return nil, nil // Not an error, just not OPC UA
	}

	info := &IndustrialProtocolInfo{
		Protocol:       "opcua",
		Timestamp:      timestamp,
		Confidence:     0.7,
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
		info.Confidence = 0.5
	} else {
		info.Confidence = 0.9
	}

	return info, nil
}

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

// Helper methods
func (p *IndustrialProtocolParserImpl) isEtherNetIPPort(packet gopacket.Packet) bool {
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

func (p *IndustrialProtocolParserImpl) isOPCUAPort(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return tcp.SrcPort == 4840 || tcp.DstPort == 4840
	}
	return false
}

func (p *IndustrialProtocolParserImpl) extractPortInfo(packet gopacket.Packet, info *IndustrialProtocolInfo, ports []uint16) error {
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

// ParseIndustrialProtocols analyzes a packet for industrial protocol information
func (p *IndustrialProtocolParserImpl) ParseIndustrialProtocols(packet gopacket.Packet) ([]IndustrialProtocolInfo, error) {
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
		return []IndustrialProtocolInfo{}, nil
	}

	if p.errorHandler.IsThresholdExceeded() {
		return nil, errors.New("error threshold exceeded, stopping industrial protocol parsing")
	}

	var protocols []IndustrialProtocolInfo
	timestamp := packet.Metadata().Timestamp

	// Check for EtherNet/IP protocol
	if p.enableEtherNetIP {
		if ethernetIPInfo, err := p.parseEtherNetIPWithErrorHandling(packet, timestamp); err != nil {
			protocolErr := &IndustrialProtocolError{
				Protocol:    "ethernetip",
				Packet:      packet,
				Err:         err,
				Context:     "parseEtherNetIP",
				Recoverable: true,
				Timestamp:   timestamp,
			}
			p.errorHandler.HandleProtocolError(protocolErr)
		} else if ethernetIPInfo != nil {
			protocols = append(protocols, *ethernetIPInfo)
		}
	}

	// Check for OPC UA protocol
	if p.enableOPCUA {
		if opcuaInfo, err := p.parseOPCUAWithErrorHandling(packet, timestamp); err != nil {
			protocolErr := &IndustrialProtocolError{
				Protocol:    "opcua",
				Packet:      packet,
				Err:         err,
				Context:     "parseOPCUA",
				Recoverable: true,
				Timestamp:   timestamp,
			}
			p.errorHandler.HandleProtocolError(protocolErr)
		} else if opcuaInfo != nil {
			protocols = append(protocols, *opcuaInfo)
		}
	}

	// Check for Modbus TCP protocol
	if modbusInfo := p.parseModbusTCP(packet, timestamp); modbusInfo != nil {
		protocols = append(protocols, *modbusInfo)
	}

	return protocols, nil
}
