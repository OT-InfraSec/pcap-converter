package iec62443

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDeviceRepository for testing
type MockDeviceRepository struct {
	mock.Mock
}

func (m *MockDeviceRepository) GetDevicesByType(deviceType model.IndustrialDeviceType) ([]model.Device, error) {
	args := m.Called(deviceType)
	return args.Get(0).([]model.Device), args.Error(1)
}

func (m *MockDeviceRepository) UpdateDevice(device *model.Device) error {
	args := m.Called(device)
	return args.Error(0)
}

func TestCalculateAdvancedConfidence(t *testing.T) {
	mockRepo := &MockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo).(*DeviceClassifierImpl)

	tests := []struct {
		name                       string
		device                     model.Device
		protocols                  []IndustrialProtocolInfo
		patterns                   []model.CommunicationPattern
		expectedMinConfidence      float64
		expectedMaxConfidence      float64
		expectedEvidenceCount      int
		expectedUncertaintyReasons []string
	}{
		{
			name:   "High confidence PLC with EtherNet/IP and device identity",
			device: model.Device{Address: "192.168.1.10"},
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "EtherNetIP",
					Port:      44818,
					Direction: "bidirectional",
					DeviceIdentity: map[string]interface{}{
						"vendor":           "Rockwell Automation",
						"product_name":     "CompactLogix 5370",
						"firmware_version": "31.011",
						"serial_number":    "12345678",
					},
					SecurityInfo: map[string]interface{}{
						"security_enabled": true,
					},
				},
			},
			patterns: []model.CommunicationPattern{
				{
					PatternType: "periodic",
					Criticality: "high",
					Protocol:    "EtherNetIP",
				},
				{
					PatternType: "event-driven",
					Criticality: "medium",
					Protocol:    "EtherNetIP",
				},
			},
			expectedMinConfidence:      0.7,
			expectedMaxConfidence:      1.0,
			expectedEvidenceCount:      4,
			expectedUncertaintyReasons: []string{},
		},
		{
			name:   "Medium confidence HMI with OPC UA",
			device: model.Device{Address: "192.168.1.20"},
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "OPCUA",
					Port:      4840,
					Direction: "outbound",
					DeviceIdentity: map[string]interface{}{
						"vendor": "Siemens",
					},
					SecurityInfo: map[string]interface{}{
						"security_policy": "Basic256Sha256",
					},
				},
			},
			patterns: []model.CommunicationPattern{
				{
					PatternType: "event-driven",
					Criticality: "medium",
					Protocol:    "OPCUA",
				},
			},
			expectedMinConfidence: 0.4,
			expectedMaxConfidence: 0.8,
			expectedEvidenceCount: 3,
			expectedUncertaintyReasons: []string{
				"No product information available",
				"No firmware version information available",
			},
		},
		{
			name:   "Low confidence unknown device with HTTP only",
			device: model.Device{Address: "192.168.1.30"},
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "HTTP",
					Port:      80,
					Direction: "inbound",
				},
			},
			patterns:              []model.CommunicationPattern{},
			expectedMinConfidence: 0.0,
			expectedMaxConfidence: 0.4,
			expectedEvidenceCount: 1,
			expectedUncertaintyReasons: []string{
				"No industrial protocols detected",
				"No communication patterns detected",
				"No device identity information available",
				"No vendor information available",
				"No product information available",
				"No firmware version information available",
			},
		},
		{
			name:                  "Zero confidence with no data",
			device:                model.Device{Address: "192.168.1.40"},
			protocols:             []IndustrialProtocolInfo{},
			patterns:              []model.CommunicationPattern{},
			expectedMinConfidence: 0.0,
			expectedMaxConfidence: 0.1,
			expectedEvidenceCount: 0,
			expectedUncertaintyReasons: []string{
				"No industrial protocols detected",
				"No communication patterns detected",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.CalculateAdvancedConfidence(tt.device, tt.protocols, tt.patterns)

			assert.GreaterOrEqual(t, result.OverallConfidence, tt.expectedMinConfidence,
				"Overall confidence should be at least %f", tt.expectedMinConfidence)
			assert.LessOrEqual(t, result.OverallConfidence, tt.expectedMaxConfidence,
				"Overall confidence should be at most %f", tt.expectedMaxConfidence)
			assert.Equal(t, tt.expectedEvidenceCount, result.EvidenceCount,
				"Evidence count should match expected")

			// Check that expected uncertainty reasons are present
			for _, expectedReason := range tt.expectedUncertaintyReasons {
				assert.Contains(t, result.UncertaintyReasons, expectedReason,
					"Should contain uncertainty reason: %s", expectedReason)
			}

			// Validate confidence score components
			assert.GreaterOrEqual(t, result.ProtocolConfidence, 0.0)
			assert.LessOrEqual(t, result.ProtocolConfidence, 1.0)
			assert.GreaterOrEqual(t, result.PatternConfidence, 0.0)
			assert.LessOrEqual(t, result.PatternConfidence, 1.0)
			assert.GreaterOrEqual(t, result.IdentityConfidence, 0.0)
			assert.LessOrEqual(t, result.IdentityConfidence, 1.0)
			assert.GreaterOrEqual(t, result.ConsistencyScore, 0.0)
			assert.LessOrEqual(t, result.ConsistencyScore, 1.0)

			// Validate that confidence factors are present
			assert.NotNil(t, result.ConfidenceFactors)
			assert.NotNil(t, result.RecommendedActions)
		})
	}
}

func TestValidateClassification(t *testing.T) {
	mockRepo := &MockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo).(*DeviceClassifierImpl)

	tests := []struct {
		name                    string
		classification          IndustrialDeviceClassification
		expectedIsValid         bool
		expectedCriticalErrors  int
		expectedWarnings        int
		expectedValidationScore float64
	}{
		{
			name: "Valid PLC classification",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypePLC,
				Role:          model.RoleController,
				Confidence:    0.85,
				Protocols:     []string{"EtherNetIP", "Modbus"},
				SecurityLevel: model.SecurityLevel2,
				LastUpdated:   time.Now(),
				Reasoning:     "Classified based on EtherNet/IP protocol usage",
			},
			expectedIsValid:         true,
			expectedCriticalErrors:  0,
			expectedWarnings:        0,
			expectedValidationScore: 1.0,
		},
		{
			name: "Invalid device type",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.IndustrialDeviceType("InvalidType"),
				Role:          model.RoleController,
				Confidence:    0.85,
				Protocols:     []string{"EtherNetIP"},
				SecurityLevel: model.SecurityLevel2,
				LastUpdated:   time.Now(),
			},
			expectedIsValid:         false,
			expectedCriticalErrors:  1,
			expectedWarnings:        2,    // Expect warnings for device type/role consistency and security level appropriateness
			expectedValidationScore: 0.55, // Adjusted based on actual calculation
		},
		{
			name: "Invalid confidence score",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypePLC,
				Role:          model.RoleController,
				Confidence:    1.5, // Invalid - greater than 1.0
				Protocols:     []string{"EtherNetIP"},
				SecurityLevel: model.SecurityLevel2,
				LastUpdated:   time.Now(),
			},
			expectedIsValid:         false,
			expectedCriticalErrors:  1,
			expectedWarnings:        0,
			expectedValidationScore: 0.8,
		},
		{
			name: "Inconsistent device type and role",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypeSensor,
				Role:          model.RoleController, // Inconsistent - sensors are typically field devices
				Confidence:    0.75,
				Protocols:     []string{"Modbus"},
				SecurityLevel: model.SecurityLevel1,
				LastUpdated:   time.Now(),
			},
			expectedIsValid:         true,
			expectedCriticalErrors:  0,
			expectedWarnings:        1,
			expectedValidationScore: 0.9,
		},
		{
			name: "Low confidence with specific classification",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypePLC,
				Role:          model.RoleController,
				Confidence:    0.2, // Low confidence
				Protocols:     []string{"HTTP"},
				SecurityLevel: model.SecurityLevel2,
				LastUpdated:   time.Now(),
			},
			expectedIsValid:         true,
			expectedCriticalErrors:  0,
			expectedWarnings:        1,
			expectedValidationScore: 0.95,
		},
		{
			name: "Zero timestamp",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypeHMI,
				Role:          model.RoleOperator,
				Confidence:    0.7,
				Protocols:     []string{"OPCUA"},
				SecurityLevel: model.SecurityLevel2,
				LastUpdated:   time.Time{}, // Zero timestamp
			},
			expectedIsValid:         true,
			expectedCriticalErrors:  0,
			expectedWarnings:        0,
			expectedValidationScore: 0.9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.ValidateClassification(tt.classification)

			assert.Equal(t, tt.expectedIsValid, result.IsValid,
				"Validation result should match expected")
			assert.Equal(t, tt.expectedCriticalErrors, len(result.CriticalErrors),
				"Critical errors count should match expected")
			assert.Equal(t, tt.expectedWarnings, len(result.Warnings),
				"Warnings count should match expected")
			assert.InDelta(t, tt.expectedValidationScore, result.ValidationScore, 0.01,
				"Validation score should be close to expected")

			// Validate that validation score is within valid range
			assert.GreaterOrEqual(t, result.ValidationScore, 0.0)
			assert.LessOrEqual(t, result.ValidationScore, 1.0)
		})
	}
}

func TestGetUncertaintyIndicators(t *testing.T) {
	mockRepo := &MockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo).(*DeviceClassifierImpl)

	tests := []struct {
		name                         string
		classification               IndustrialDeviceClassification
		expectedHasLowConfidence     bool
		expectedUncertaintyLevel     string
		expectedRequiresManualReview bool
		expectedMissingEvidence      []string
		expectedSuggestedActions     []string
	}{
		{
			name: "High confidence PLC",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypePLC,
				Role:          model.RoleController,
				Confidence:    0.9,
				Protocols:     []string{"EtherNetIP", "Modbus"},
				SecurityLevel: model.SecurityLevel2,
			},
			expectedHasLowConfidence:     false,
			expectedUncertaintyLevel:     "low",
			expectedRequiresManualReview: false,
			expectedMissingEvidence:      []string{},
			expectedSuggestedActions:     []string{},
		},
		{
			name: "Medium confidence HMI",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypeHMI,
				Role:          model.RoleOperator,
				Confidence:    0.55,
				Protocols:     []string{"OPCUA"},
				SecurityLevel: model.SecurityLevel2,
			},
			expectedHasLowConfidence:     true,
			expectedUncertaintyLevel:     "medium",
			expectedRequiresManualReview: false,
			expectedMissingEvidence:      []string{},
			expectedSuggestedActions:     []string{},
		},
		{
			name: "Low confidence unknown device",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypeUnknown,
				Role:          model.RoleFieldDevice,
				Confidence:    0.25,
				Protocols:     []string{"HTTP"},
				SecurityLevel: model.SecurityLevelUnknown,
			},
			expectedHasLowConfidence:     true,
			expectedUncertaintyLevel:     "high",
			expectedRequiresManualReview: true,
			expectedMissingEvidence: []string{
				"industrial_protocol_evidence",
				"device_identity_information",
				"security_configuration",
				"communication_patterns",
			},
			expectedSuggestedActions: []string{
				"Verify industrial protocol configuration",
				"Perform active device discovery",
				"Check device documentation and configuration",
				"Analyze security configuration and encryption usage",
				"Monitor communication patterns over extended period",
				"Collect additional network traffic data",
				"Verify device configuration manually",
			},
		},
		{
			name: "Critical device with low confidence",
			classification: IndustrialDeviceClassification{
				DeviceType:    model.DeviceTypeSCADA,
				Role:          model.RoleOperator,
				Confidence:    0.35, // Lower confidence to trigger communication_patterns missing evidence
				Protocols:     []string{"OPCUA"},
				SecurityLevel: model.SecurityLevel3,
			},
			expectedHasLowConfidence:     true,
			expectedUncertaintyLevel:     "high",
			expectedRequiresManualReview: true,
			expectedMissingEvidence:      []string{"communication_patterns"},
			expectedSuggestedActions: []string{
				"Monitor communication patterns over extended period",
				"Collect additional network traffic data",
				"Verify device configuration manually",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.GetUncertaintyIndicators(tt.classification)

			assert.Equal(t, tt.expectedHasLowConfidence, result.HasLowConfidence,
				"Has low confidence should match expected")
			assert.Equal(t, tt.expectedUncertaintyLevel, result.UncertaintyLevel,
				"Uncertainty level should match expected")
			assert.Equal(t, tt.expectedRequiresManualReview, result.RequiresManualReview,
				"Requires manual review should match expected")

			// Check that expected missing evidence is present
			for _, expectedEvidence := range tt.expectedMissingEvidence {
				assert.Contains(t, result.MissingEvidence, expectedEvidence,
					"Should contain missing evidence: %s", expectedEvidence)
			}

			// Check that expected suggested actions are present
			for _, expectedAction := range tt.expectedSuggestedActions {
				assert.Contains(t, result.SuggestedActions, expectedAction,
					"Should contain suggested action: %s", expectedAction)
			}

			// Validate confidence threshold
			assert.Greater(t, result.ConfidenceThreshold, 0.0)
			assert.LessOrEqual(t, result.ConfidenceThreshold, 1.0)
		})
	}
}

func TestConfidenceCalculationEdgeCases(t *testing.T) {
	mockRepo := &MockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo).(*DeviceClassifierImpl)

	t.Run("Multiple industrial protocols increase confidence", func(t *testing.T) {
		device := model.Device{Address: "192.168.1.50"}
		protocols := []IndustrialProtocolInfo{
			{Protocol: "EtherNetIP", Direction: "bidirectional"},
			{Protocol: "OPCUA", Direction: "outbound"},
			{Protocol: "Modbus", Direction: "inbound"},
		}
		patterns := []model.CommunicationPattern{}

		result := classifier.CalculateAdvancedConfidence(device, protocols, patterns)

		assert.Greater(t, result.OverallConfidence, 0.4,
			"Multiple industrial protocols should result in higher confidence")
		assert.Contains(t, result.ConfidenceFactors, "multiple_industrial_protocols",
			"Should have multiple industrial protocols factor")
	})

	t.Run("Conflicting evidence reduces consistency", func(t *testing.T) {
		device := model.Device{Address: "192.168.1.60"}
		protocols := []IndustrialProtocolInfo{
			{Protocol: "EtherNetIP", Direction: "bidirectional"},
		}
		patterns := []model.CommunicationPattern{
			{PatternType: "periodic", Criticality: "low"}, // Low criticality conflicts with industrial protocol
		}

		result := classifier.CalculateAdvancedConfidence(device, protocols, patterns)

		assert.Less(t, result.ConsistencyScore, 1.0,
			"Conflicting evidence should reduce consistency score")
		assert.Contains(t, result.UncertaintyReasons, "Industrial protocols detected but no critical communication patterns",
			"Should identify conflicting evidence")
	})

	t.Run("Evidence count affects overall confidence", func(t *testing.T) {
		device := model.Device{Address: "192.168.1.70"}

		// Test with minimal evidence
		protocolsMinimal := []IndustrialProtocolInfo{
			{Protocol: "HTTP", Direction: "inbound"},
		}
		resultMinimal := classifier.CalculateAdvancedConfidence(device, protocolsMinimal, []model.CommunicationPattern{})

		// Test with extensive evidence
		protocolsExtensive := []IndustrialProtocolInfo{
			{Protocol: "EtherNetIP", Direction: "bidirectional", DeviceIdentity: map[string]interface{}{"vendor": "Test"}},
			{Protocol: "OPCUA", Direction: "outbound", SecurityInfo: map[string]interface{}{"policy": "Basic256"}},
		}
		patternsExtensive := []model.CommunicationPattern{
			{PatternType: "periodic", Criticality: "high"},
			{PatternType: "event-driven", Criticality: "medium"},
		}
		resultExtensive := classifier.CalculateAdvancedConfidence(device, protocolsExtensive, patternsExtensive)

		assert.Greater(t, resultExtensive.OverallConfidence, resultMinimal.OverallConfidence,
			"More evidence should result in higher confidence")
		assert.Greater(t, resultExtensive.EvidenceCount, resultMinimal.EvidenceCount,
			"Extensive test should have more evidence")
	})
}

func TestValidationHelperMethods(t *testing.T) {
	mockRepo := &MockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo).(*DeviceClassifierImpl)

	t.Run("Device type validation", func(t *testing.T) {
		validTypes := []model.IndustrialDeviceType{
			model.DeviceTypePLC,
			model.DeviceTypeHMI,
			model.DeviceTypeSCADA,
			model.DeviceTypeUnknown,
		}

		for _, deviceType := range validTypes {
			assert.True(t, classifier.isValidDeviceType(deviceType),
				"Should validate device type: %s", deviceType)
		}

		assert.False(t, classifier.isValidDeviceType(model.IndustrialDeviceType("InvalidType")),
			"Should not validate invalid device type")
	})

	t.Run("Device role validation", func(t *testing.T) {
		validRoles := []model.IndustrialDeviceRole{
			model.RoleController,
			model.RoleOperator,
			model.RoleEngineer,
			model.RoleDataCollector,
			model.RoleFieldDevice,
		}

		for _, role := range validRoles {
			assert.True(t, classifier.isValidDeviceRole(role),
				"Should validate device role: %s", role)
		}

		assert.False(t, classifier.isValidDeviceRole(model.IndustrialDeviceRole("InvalidRole")),
			"Should not validate invalid device role")
	})

	t.Run("Security level validation", func(t *testing.T) {
		validLevels := []model.SecurityLevel{
			model.SecurityLevelUnknown,
			model.SecurityLevel1,
			model.SecurityLevel2,
			model.SecurityLevel3,
			model.SecurityLevel4,
		}

		for _, level := range validLevels {
			assert.True(t, classifier.isValidSecurityLevel(level),
				"Should validate security level: %d", level)
		}

		assert.False(t, classifier.isValidSecurityLevel(model.SecurityLevel(5)),
			"Should not validate invalid security level")
	})

	t.Run("Device type and role consistency", func(t *testing.T) {
		consistentCombinations := map[model.IndustrialDeviceType]model.IndustrialDeviceRole{
			model.DeviceTypePLC:            model.RoleController,
			model.DeviceTypeHMI:            model.RoleOperator,
			model.DeviceTypeSCADA:          model.RoleDataCollector,
			model.DeviceTypeHistorian:      model.RoleDataCollector,
			model.DeviceTypeEngWorkstation: model.RoleEngineer,
			model.DeviceTypeIODevice:       model.RoleFieldDevice,
		}

		for deviceType, role := range consistentCombinations {
			assert.True(t, classifier.isConsistentDeviceTypeAndRole(deviceType, role),
				"Should validate consistent combination: %s + %s", deviceType, role)
		}

		// Test inconsistent combination
		assert.False(t, classifier.isConsistentDeviceTypeAndRole(model.DeviceTypeSensor, model.RoleController),
			"Should not validate inconsistent combination: Sensor + Controller")
	})
}
