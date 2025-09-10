package iec62443

import (
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// IndustrialProtocolInfo represents information extracted from industrial protocol analysis
type IndustrialProtocolInfo struct {
	Protocol       string                 `json:"protocol"`
	Port           uint16                 `json:"port"`
	Direction      string                 `json:"direction"` // "inbound", "outbound", "bidirectional"
	DeviceIdentity map[string]interface{} `json:"device_identity"`
	SecurityInfo   map[string]interface{} `json:"security_info"`
	ServiceType    string                 `json:"service_type"`
}

// IndustrialDeviceClassification represents the result of device classification
type IndustrialDeviceClassification struct {
	DeviceType    model.IndustrialDeviceType `json:"device_type"`
	Role          model.IndustrialDeviceRole `json:"role"`
	Confidence    float64                    `json:"confidence"`
	Protocols     []string                   `json:"protocols"`
	SecurityLevel model.SecurityLevel        `json:"security_level"`
	LastUpdated   time.Time                  `json:"last_updated"`
	Reasoning     string                     `json:"reasoning"` // Explanation of classification logic
}

// DeviceClassifier defines the interface for industrial device classification
type DeviceClassifier interface {
	// ClassifyDevice analyzes a device and its communication patterns to determine its industrial type and role
	ClassifyDevice(device model.Device, protocols []IndustrialProtocolInfo, patterns []model.CommunicationPattern) IndustrialDeviceClassification

	// UpdateDeviceRole updates the role of a device based on new information
	UpdateDeviceRole(deviceID string, newRole model.IndustrialDeviceRole) error

	// GetDevicesByType retrieves devices of a specific industrial type
	GetDevicesByType(deviceType model.IndustrialDeviceType) ([]model.Device, error)

	// AnalyzeProtocolUsage analyzes protocol usage patterns to infer device characteristics
	AnalyzeProtocolUsage(protocols []IndustrialProtocolInfo) ProtocolAnalysisResult

	// AnalyzeCommunicationPatterns analyzes communication patterns for producer-consumer and client-server relationships
	AnalyzeCommunicationPatterns(patterns []model.CommunicationPattern) CommunicationAnalysisResult

	// CalculateConfidence calculates confidence score for device classification
	CalculateConfidence(device model.Device, protocols []IndustrialProtocolInfo, patterns []model.CommunicationPattern) float64

	// CalculateAdvancedConfidence calculates advanced confidence score with detailed breakdown
	CalculateAdvancedConfidence(device model.Device, protocols []IndustrialProtocolInfo, patterns []model.CommunicationPattern) ConfidenceScore

	// ValidateClassification validates a device classification and returns validation result
	ValidateClassification(classification IndustrialDeviceClassification) ValidationResult

	// GetUncertaintyIndicators returns uncertainty indicators for low-confidence classifications
	GetUncertaintyIndicators(classification IndustrialDeviceClassification) UncertaintyIndicators

	// AnalyzePeriodicCommunication detects and analyzes periodic communication patterns (Requirement 5.3)
	AnalyzePeriodicCommunication(flows []model.Flow) []PeriodicPattern

	// AnalyzeRequestResponsePatterns identifies request-response patterns and determines criticality (Requirement 5.4)
	AnalyzeRequestResponsePatterns(flows []model.Flow) []RequestResponsePattern

	// UpdateClassificationFromPatternChanges updates device classifications based on pattern changes (Requirement 5.5)
	UpdateClassificationFromPatternChanges(deviceID string, oldPatterns, newPatterns []model.CommunicationPattern) (IndustrialDeviceClassification, error)

	// DetermineCommunicationCriticality calculates criticality levels based on pattern analysis
	DetermineCommunicationCriticality(patterns []model.CommunicationPattern) CriticalityAssessment

	// DetectPatternChanges identifies changes in communication patterns over time
	DetectPatternChanges(oldPatterns, newPatterns []model.CommunicationPattern) []PatternChange
}

// ProtocolAnalysisResult represents the result of protocol usage analysis
type ProtocolAnalysisResult struct {
	PrimaryProtocols   []string                     `json:"primary_protocols"`
	SecondaryProtocols []string                     `json:"secondary_protocols"`
	DeviceTypeHints    []model.IndustrialDeviceType `json:"device_type_hints"`
	RoleHints          []model.IndustrialDeviceRole `json:"role_hints"`
	SecurityIndicators map[string]interface{}       `json:"security_indicators"`
}

// CommunicationAnalysisResult represents the result of communication pattern analysis
type CommunicationAnalysisResult struct {
	RelationshipType  string                       `json:"relationship_type"`   // "producer-consumer", "client-server", "peer-to-peer"
	CommunicationRole string                       `json:"communication_role"`  // "initiator", "responder", "both"
	DataFlowDirection string                       `json:"data_flow_direction"` // "inbound", "outbound", "bidirectional"
	CriticalityLevel  string                       `json:"criticality_level"`   // "low", "medium", "high", "critical"
	DeviceTypeHints   []model.IndustrialDeviceType `json:"device_type_hints"`
	RoleHints         []model.IndustrialDeviceRole `json:"role_hints"`
}

// ConfidenceScore represents detailed confidence scoring breakdown
type ConfidenceScore struct {
	OverallConfidence  float64            `json:"overall_confidence"`  // 0.0 to 1.0
	ProtocolConfidence float64            `json:"protocol_confidence"` // Confidence from protocol analysis
	PatternConfidence  float64            `json:"pattern_confidence"`  // Confidence from communication patterns
	IdentityConfidence float64            `json:"identity_confidence"` // Confidence from device identity information
	ConsistencyScore   float64            `json:"consistency_score"`   // How consistent the evidence is
	EvidenceCount      int                `json:"evidence_count"`      // Number of evidence points
	ConfidenceFactors  map[string]float64 `json:"confidence_factors"`  // Detailed breakdown of confidence factors
	UncertaintyReasons []string           `json:"uncertainty_reasons"` // Reasons for uncertainty
	RecommendedActions []string           `json:"recommended_actions"` // Actions to improve confidence
}

// ValidationResult represents the result of classification validation
type ValidationResult struct {
	IsValid          bool     `json:"is_valid"`
	ValidationErrors []string `json:"validation_errors"`
	ValidationScore  float64  `json:"validation_score"` // 0.0 to 1.0
	CriticalErrors   []string `json:"critical_errors"`  // Errors that prevent classification
	Warnings         []string `json:"warnings"`         // Non-critical validation issues
}

// UncertaintyIndicators represents indicators for low-confidence classifications
type UncertaintyIndicators struct {
	HasLowConfidence     bool     `json:"has_low_confidence"`
	ConfidenceThreshold  float64  `json:"confidence_threshold"`
	UncertaintyLevel     string   `json:"uncertainty_level"`    // "low", "medium", "high"
	MissingEvidence      []string `json:"missing_evidence"`     // Types of evidence that are missing
	ConflictingEvidence  []string `json:"conflicting_evidence"` // Evidence that conflicts
	RequiresManualReview bool     `json:"requires_manual_review"`
	SuggestedActions     []string `json:"suggested_actions"` // Actions to reduce uncertainty
}
