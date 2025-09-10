package testutil

import (
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// IndustrialProtocolInfo represents information extracted from industrial protocol analysis
// This is a copy to avoid import cycles in tests
type IndustrialProtocolInfo struct {
	Protocol       string                 `json:"protocol"`
	Port           uint16                 `json:"port"`
	Direction      string                 `json:"direction"` // "inbound", "outbound", "bidirectional"
	DeviceIdentity map[string]interface{} `json:"device_identity"`
	SecurityInfo   map[string]interface{} `json:"security_info"`
	ServiceType    string                 `json:"service_type"`
}

// IndustrialDeviceClassification represents the result of device classification
// This is a copy to avoid import cycles in tests
type IndustrialDeviceClassification struct {
	DeviceType    model.IndustrialDeviceType `json:"device_type"`
	Role          model.IndustrialDeviceRole `json:"role"`
	Confidence    float64                    `json:"confidence"`
	Protocols     []string                   `json:"protocols"`
	SecurityLevel model.SecurityLevel        `json:"security_level"`
	LastUpdated   time.Time                  `json:"last_updated"`
	Reasoning     string                     `json:"reasoning"` // Explanation of classification logic
}

// ProtocolAnalysisResult represents the result of protocol usage analysis
// This is a copy to avoid import cycles in tests
type ProtocolAnalysisResult struct {
	PrimaryProtocols   []string                     `json:"primary_protocols"`
	SecondaryProtocols []string                     `json:"secondary_protocols"`
	DeviceTypeHints    []model.IndustrialDeviceType `json:"device_type_hints"`
	RoleHints          []model.IndustrialDeviceRole `json:"role_hints"`
	SecurityIndicators map[string]interface{}       `json:"security_indicators"`
}

// CommunicationAnalysisResult represents the result of communication pattern analysis
// This is a copy to avoid import cycles in tests
type CommunicationAnalysisResult struct {
	RelationshipType  string                       `json:"relationship_type"`   // "producer-consumer", "client-server", "peer-to-peer"
	CommunicationRole string                       `json:"communication_role"`  // "initiator", "responder", "both"
	DataFlowDirection string                       `json:"data_flow_direction"` // "inbound", "outbound", "bidirectional"
	CriticalityLevel  string                       `json:"criticality_level"`   // "low", "medium", "high", "critical"
	DeviceTypeHints   []model.IndustrialDeviceType `json:"device_type_hints"`
	RoleHints         []model.IndustrialDeviceRole `json:"role_hints"`
}
