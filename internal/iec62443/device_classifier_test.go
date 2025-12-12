package iec62443

import (
	"net"
	"testing"
	"time"

	addressHelper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Local mock for testing to avoid import cycles
type mockDeviceRepository struct {
	mock.Mock
}

func (m *mockDeviceRepository) GetDevicesByType(deviceType model.IndustrialDeviceType) ([]model.Device, error) {
	args := m.Called(deviceType)
	return args.Get(0).([]model.Device), args.Error(1)
}

func (m *mockDeviceRepository) UpdateDevice(device *model.Device) error {
	args := m.Called(device)
	return args.Error(0)
}

// Test helper functions
func createTestPLCDevice() model.Device {
	return model.Device{
		ID:          1,
		Address:     "192.168.1.10",
		AddressType: "IPv4",
		FirstSeen:   time.Now().Add(-24 * time.Hour),
		LastSeen:    time.Now(),
	}
}

func createTestHMIDevice() model.Device {
	return model.Device{
		ID:          2,
		Address:     "192.168.1.20",
		AddressType: "IPv4",
		FirstSeen:   time.Now().Add(-12 * time.Hour),
		LastSeen:    time.Now(),
	}
}

func createTestSCADADevice() model.Device {
	return model.Device{
		ID:          3,
		Address:     "192.168.1.30",
		AddressType: "IPv4",
		FirstSeen:   time.Now().Add(-6 * time.Hour),
		LastSeen:    time.Now(),
	}
}
func TestDeviceClassifierImpl_ClassifyDevice(t *testing.T) {
	tests := []struct {
		name               string
		device             model.Device
		protocols          []IndustrialProtocolInfo
		patterns           []model.CommunicationPattern
		expectedDeviceType model.IndustrialDeviceType
		expectedRole       model.IndustrialDeviceRole
		expectedConfidence float64
		expectedSecLevel   model.SecurityLevel
	}{
		{
			name:   "PLC with EtherNet/IP",
			device: createTestPLCDevice(),
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "EtherNetIP",
					Port:      44818,
					Direction: "inbound",
					DeviceIdentity: map[string]interface{}{
						"vendor_id":    123,
						"product_code": 456,
					},
					SecurityInfo: map[string]interface{}{
						"security_enabled": false,
					},
					ServiceType: "explicit",
				},
			},
			patterns: []model.CommunicationPattern{
				{
					SourceDevice:      "192.168.1.20",
					DestinationDevice: "192.168.1.10",
					Protocol:          "EtherNetIP",
					Frequency:         1 * time.Second,
					DataVolume:        512,
					PatternType:       "periodic",
					Criticality:       "high",
				},
			},
			expectedDeviceType: model.DeviceTypeIODevice, // Inbound EtherNet/IP suggests I/O device
			expectedRole:       model.RoleFieldDevice,    // Field device role for I/O devices
			expectedConfidence: 0.475,                    // Adjusted confidence based on new calculation
			expectedSecLevel:   model.SecurityLevel1,     // Unencrypted communication
		},
		{
			name:   "HMI with OPC UA client",
			device: createTestHMIDevice(),
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "OPCUA",
					Port:      4840,
					Direction: "outbound",
					DeviceIdentity: map[string]interface{}{
						"application_name": "HMI Client",
						"application_type": "Client",
					},
					SecurityInfo: map[string]interface{}{
						"security_policy": "Basic256Sha256",
						"security_mode":   "SignAndEncrypt",
					},
					ServiceType: "client",
				},
			},
			patterns: []model.CommunicationPattern{
				{
					SourceDevice:      "192.168.1.20",
					DestinationDevice: "192.168.1.10",
					Protocol:          "OPCUA",
					Frequency:         5 * time.Second,
					DataVolume:        2048,
					PatternType:       "event-driven",
					Criticality:       "medium",
				},
			},
			expectedDeviceType: model.DeviceTypeHMI,
			expectedRole:       model.RoleOperator,
			expectedConfidence: 0.365,
			expectedSecLevel:   model.SecurityLevel2,
		},
		{
			name:               "Unknown device with no protocols",
			device:             createTestSCADADevice(),
			protocols:          []IndustrialProtocolInfo{},
			patterns:           []model.CommunicationPattern{},
			expectedDeviceType: model.DeviceTypeUnknown,
			expectedRole:       model.RoleFieldDevice,
			expectedConfidence: 0.0,
			expectedSecLevel:   model.SecurityLevel1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := &mockDeviceRepository{}
			classifier := NewDeviceClassifier(mockRepo)

			result := classifier.ClassifyDevice(tt.device, tt.protocols, tt.patterns)

			assert.Equal(t, tt.expectedDeviceType, result.DeviceType)
			assert.Equal(t, tt.expectedRole, result.Role)
			assert.InDelta(t, tt.expectedConfidence, result.Confidence, 0.1)
			assert.Equal(t, tt.expectedSecLevel, result.SecurityLevel)
			assert.NotEmpty(t, result.Reasoning)
			assert.NotZero(t, result.LastUpdated)

			if len(tt.protocols) > 0 {
				assert.Contains(t, result.Protocols, tt.protocols[0].Protocol)
			}
		})
	}
}

func TestDeviceClassifierImpl_AnalyzeProtocolUsage(t *testing.T) {
	tests := []struct {
		name                     string
		protocols                []IndustrialProtocolInfo
		expectedPrimaryProtocols []string
		expectedDeviceTypeHints  []model.IndustrialDeviceType
		expectedRoleHints        []model.IndustrialDeviceRole
	}{
		{
			name: "EtherNet/IP inbound",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "EtherNetIP",
					Port:      44818,
					Direction: "inbound",
					DeviceIdentity: map[string]interface{}{
						"service_type": "explicit",
					},
				},
			},
			expectedPrimaryProtocols: []string{"EtherNetIP"},
			expectedDeviceTypeHints:  []model.IndustrialDeviceType{model.DeviceTypeIODevice, model.DeviceTypeSensor, model.DeviceTypeActuator},
			expectedRoleHints:        []model.IndustrialDeviceRole{model.RoleFieldDevice},
		},
		{
			name: "OPC UA outbound",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "OPCUA",
					Port:      4840,
					Direction: "outbound",
					SecurityInfo: map[string]interface{}{
						"security_policy": "Basic256Sha256",
					},
				},
			},
			expectedPrimaryProtocols: []string{"OPCUA"},
			expectedDeviceTypeHints:  []model.IndustrialDeviceType{model.DeviceTypeHMI, model.DeviceTypeSCADA, model.DeviceTypeEngWorkstation},
			expectedRoleHints:        []model.IndustrialDeviceRole{model.RoleOperator, model.RoleEngineer},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := &mockDeviceRepository{}
			classifier := NewDeviceClassifier(mockRepo)

			result := classifier.AnalyzeProtocolUsage(tt.protocols)

			for _, expectedProtocol := range tt.expectedPrimaryProtocols {
				assert.Contains(t, result.PrimaryProtocols, expectedProtocol)
			}

			hasExpectedDeviceType := false
			for _, expectedType := range tt.expectedDeviceTypeHints {
				if contains(result.DeviceTypeHints, expectedType) {
					hasExpectedDeviceType = true
					break
				}
			}
			assert.True(t, hasExpectedDeviceType, "Should contain at least one expected device type hint")

			hasExpectedRole := false
			for _, expectedRole := range tt.expectedRoleHints {
				if containsRole(result.RoleHints, expectedRole) {
					hasExpectedRole = true
					break
				}
			}
			assert.True(t, hasExpectedRole, "Should contain at least one expected role hint")
		})
	}
}

func TestDeviceClassifierImpl_AnalyzeCommunicationPatterns(t *testing.T) {
	tests := []struct {
		name                     string
		patterns                 []model.CommunicationPattern
		expectedRelationshipType string
		expectedCriticalityLevel string
	}{
		{
			name: "Periodic high-criticality patterns",
			patterns: []model.CommunicationPattern{
				{
					SourceDevice:      "192.168.1.10",
					DestinationDevice: "192.168.1.20",
					Protocol:          "EtherNetIP",
					PatternType:       "periodic",
					Criticality:       "high",
				},
				{
					SourceDevice:      "192.168.1.10",
					DestinationDevice: "192.168.1.21",
					Protocol:          "EtherNetIP",
					PatternType:       "periodic",
					Criticality:       "critical",
				},
			},
			expectedRelationshipType: "producer-consumer",
			expectedCriticalityLevel: "critical",
		},
		{
			name: "Event-driven medium-criticality patterns",
			patterns: []model.CommunicationPattern{
				{
					SourceDevice:      "192.168.1.20",
					DestinationDevice: "192.168.1.10",
					Protocol:          "OPCUA",
					PatternType:       "event-driven",
					Criticality:       "medium",
				},
			},
			expectedRelationshipType: "client-server",
			expectedCriticalityLevel: "medium",
		},
		{
			name:                     "No patterns",
			patterns:                 []model.CommunicationPattern{},
			expectedRelationshipType: "unknown",
			expectedCriticalityLevel: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := &mockDeviceRepository{}
			classifier := NewDeviceClassifier(mockRepo)

			result := classifier.AnalyzeCommunicationPatterns(tt.patterns)

			assert.Equal(t, tt.expectedRelationshipType, result.RelationshipType)
			assert.Equal(t, tt.expectedCriticalityLevel, result.CriticalityLevel)
		})
	}
}

func TestDeviceClassifierImpl_CalculateConfidence(t *testing.T) {
	tests := []struct {
		name                  string
		device                model.Device
		protocols             []IndustrialProtocolInfo
		patterns              []model.CommunicationPattern
		expectedMinConfidence float64
		expectedMaxConfidence float64
	}{
		{
			name:   "High confidence - industrial protocols + patterns + device identity",
			device: createTestPLCDevice(),
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "EtherNetIP",
					Direction: "bidirectional",
					DeviceIdentity: map[string]interface{}{
						"vendor_id": 123,
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
				},
			},
			expectedMinConfidence: 0.475,
			expectedMaxConfidence: 1.0,
		},
		{
			name:   "Medium confidence - some protocols",
			device: createTestHMIDevice(),
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "HTTP",
					Direction: "outbound",
				},
			},
			patterns:              []model.CommunicationPattern{},
			expectedMinConfidence: 0.126,
			expectedMaxConfidence: 0.6,
		},
		{
			name:                  "Low confidence - no protocols or patterns",
			device:                createTestSCADADevice(),
			protocols:             []IndustrialProtocolInfo{},
			patterns:              []model.CommunicationPattern{},
			expectedMinConfidence: 0.0,
			expectedMaxConfidence: 0.2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := &mockDeviceRepository{}
			classifier := NewDeviceClassifier(mockRepo)

			confidence := classifier.CalculateConfidence(tt.device, tt.protocols, tt.patterns)

			assert.GreaterOrEqual(t, confidence, tt.expectedMinConfidence)
			assert.LessOrEqual(t, confidence, tt.expectedMaxConfidence)
			assert.LessOrEqual(t, confidence, 1.0)
		})
	}
}

func TestDeviceClassifierImpl_GetDevicesByType(t *testing.T) {
	mockRepo := &mockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo)

	expectedDevices := []model.Device{
		createTestPLCDevice(),
	}

	mockRepo.On("GetDevicesByType", model.DeviceTypePLC).Return(expectedDevices, nil)

	devices, err := classifier.GetDevicesByType(model.DeviceTypePLC)

	assert.NoError(t, err)
	assert.Equal(t, expectedDevices, devices)
	mockRepo.AssertExpectations(t)
}

func TestDeviceClassifierImpl_UpdateDeviceRole(t *testing.T) {
	mockRepo := &mockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo)

	err := classifier.UpdateDeviceRole("device123", model.RoleController)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

// Helper functions for testing
func contains(slice []model.IndustrialDeviceType, item model.IndustrialDeviceType) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsRole(slice []model.IndustrialDeviceRole, item model.IndustrialDeviceRole) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Tests for new communication pattern analysis methods (Task 11)

func TestDeviceClassifierImpl_AnalyzePeriodicCommunication(t *testing.T) {
	mockRepo := &mockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo)

	tests := []struct {
		name                 string
		flows                []model.Flow
		expectedPatternCount int
		expectedCriticality  string
	}{
		{
			name: "Critical EtherNet/IP periodic communication",
			flows: []model.Flow{
				createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now().Add(-5*time.Second)),
				createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now().Add(-4*time.Second)),
				createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now().Add(-3*time.Second)),
				createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now().Add(-2*time.Second)),
				createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now().Add(-1*time.Second)),
				createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now()),
			},
			expectedPatternCount: 1,
			expectedCriticality:  "medium", // 1-second intervals are medium criticality
		},
		{
			name:                 "Insufficient flows for pattern detection",
			flows:                []model.Flow{createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now())},
			expectedPatternCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := classifier.AnalyzePeriodicCommunication(tt.flows)

			assert.Equal(t, tt.expectedPatternCount, len(patterns))
			if len(patterns) > 0 {
				assert.Equal(t, tt.expectedCriticality, patterns[0].CriticalityLevel)
				assert.Equal(t, "192.168.1.10", patterns[0].SourceDevice)
				assert.Equal(t, "192.168.1.20", patterns[0].DestinationDevice)
				assert.Equal(t, "EtherNetIP", patterns[0].Protocol)
			}
		})
	}
}

func TestDeviceClassifierImpl_AnalyzeRequestResponsePatterns(t *testing.T) {
	mockRepo := &mockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo)

	tests := []struct {
		name                 string
		flows                []model.Flow
		expectedPatternCount int
		expectedServiceType  string
	}{
		{
			name: "OPC UA request-response pattern",
			flows: []model.Flow{
				// Request flows
				createTestRequestFlow("192.168.1.20", "192.168.1.10", "OPCUA", time.Now().Add(-10*time.Second), 32),
				createTestRequestFlow("192.168.1.20", "192.168.1.10", "OPCUA", time.Now().Add(-8*time.Second), 32),
				createTestRequestFlow("192.168.1.20", "192.168.1.10", "OPCUA", time.Now().Add(-6*time.Second), 32),
				createTestRequestFlow("192.168.1.20", "192.168.1.10", "OPCUA", time.Now().Add(-4*time.Second), 32),
				createTestRequestFlow("192.168.1.20", "192.168.1.10", "OPCUA", time.Now().Add(-2*time.Second), 32),
				// Response flows
				createTestResponseFlow("192.168.1.10", "192.168.1.20", "OPCUA", time.Now().Add(-10*time.Second).Add(50*time.Millisecond), 128),
				createTestResponseFlow("192.168.1.10", "192.168.1.20", "OPCUA", time.Now().Add(-8*time.Second).Add(50*time.Millisecond), 128),
				createTestResponseFlow("192.168.1.10", "192.168.1.20", "OPCUA", time.Now().Add(-6*time.Second).Add(50*time.Millisecond), 128),
				createTestResponseFlow("192.168.1.10", "192.168.1.20", "OPCUA", time.Now().Add(-4*time.Second).Add(50*time.Millisecond), 128),
				createTestResponseFlow("192.168.1.10", "192.168.1.20", "OPCUA", time.Now().Add(-2*time.Second).Add(50*time.Millisecond), 128),
			},
			expectedPatternCount: 1,
			expectedServiceType:  "data_collection",
		},
		{
			name:                 "No request-response pairs",
			flows:                []model.Flow{createTestFlow("192.168.1.10", "192.168.1.20", "EtherNetIP", time.Now())},
			expectedPatternCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := classifier.AnalyzeRequestResponsePatterns(tt.flows)

			assert.Equal(t, tt.expectedPatternCount, len(patterns))
			if len(patterns) > 0 {
				assert.Equal(t, tt.expectedServiceType, patterns[0].ServiceType)
				assert.Equal(t, "192.168.1.20", patterns[0].InitiatorDevice)
				assert.Equal(t, "192.168.1.10", patterns[0].ResponderDevice)
				assert.Equal(t, "OPCUA", patterns[0].Protocol)
				assert.Greater(t, patterns[0].RequestRate, 0.0)
			}
		})
	}
}

func TestDeviceClassifierImpl_DetermineCommunicationCriticality(t *testing.T) {
	mockRepo := &mockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo)

	tests := []struct {
		name                       string
		patterns                   []model.CommunicationPattern
		expectedOverallCriticality string
		expectedCriticalCount      int
		expectedHighCount          int
	}{
		{
			name: "Critical industrial network",
			patterns: []model.CommunicationPattern{
				{
					SourceDevice:      "192.168.1.10",
					DestinationDevice: "192.168.1.20",
					Protocol:          "EtherNetIP",
					PatternType:       "periodic",
					Criticality:       "critical",
					Frequency:         100 * time.Millisecond,
				},
				{
					SourceDevice:      "192.168.1.20",
					DestinationDevice: "192.168.1.30",
					Protocol:          "OPCUA",
					PatternType:       "event-driven",
					Criticality:       "high",
					Frequency:         1 * time.Second,
				},
			},
			expectedOverallCriticality: "critical",
			expectedCriticalCount:      1,
			expectedHighCount:          1,
		},
		{
			name: "Low criticality network",
			patterns: []model.CommunicationPattern{
				{
					SourceDevice:      "192.168.1.100",
					DestinationDevice: "192.168.1.10",
					Protocol:          "HTTP",
					PatternType:       "event-driven",
					Criticality:       "low",
					Frequency:         30 * time.Second,
				},
			},
			expectedOverallCriticality: "low",
			expectedCriticalCount:      0,
			expectedHighCount:          0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := classifier.DetermineCommunicationCriticality(tt.patterns)

			assert.Equal(t, tt.expectedOverallCriticality, assessment.OverallCriticality)
			assert.Equal(t, tt.expectedCriticalCount, assessment.CriticalPatternCount)
			assert.Equal(t, tt.expectedHighCount, assessment.HighPatternCount)
			assert.NotZero(t, assessment.AssessmentTimestamp)
		})
	}
}

func TestDeviceClassifierImpl_DetectPatternChanges(t *testing.T) {
	mockRepo := &mockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo)

	oldPatterns := []model.CommunicationPattern{
		{
			SourceDevice:      "192.168.1.10",
			DestinationDevice: "192.168.1.20",
			Protocol:          "EtherNetIP",
			PatternType:       "periodic",
			Criticality:       "medium",
			Frequency:         1 * time.Second,
		},
	}

	newPatterns := []model.CommunicationPattern{
		{
			SourceDevice:      "192.168.1.10",
			DestinationDevice: "192.168.1.20",
			Protocol:          "EtherNetIP",
			PatternType:       "periodic",
			Criticality:       "critical", // Changed from medium to critical
			Frequency:         1 * time.Second,
		},
	}

	changes := classifier.DetectPatternChanges(oldPatterns, newPatterns)

	assert.Equal(t, 1, len(changes))
	assert.Equal(t, "criticality_changed", changes[0].ChangeType)
	assert.Equal(t, "192.168.1.10", changes[0].DeviceID)
	assert.True(t, changes[0].RequiresAction)
}

func TestDeviceClassifierImpl_UpdateClassificationFromPatternChanges(t *testing.T) {
	mockRepo := &mockDeviceRepository{}
	classifier := NewDeviceClassifier(mockRepo)

	oldPatterns := []model.CommunicationPattern{
		{
			SourceDevice:      "192.168.1.10",
			DestinationDevice: "192.168.1.20",
			Protocol:          "HTTP",
			PatternType:       "event-driven",
			Criticality:       "low",
			Frequency:         30 * time.Second,
		},
	}

	newPatterns := []model.CommunicationPattern{
		{
			SourceDevice:      "192.168.1.10",
			DestinationDevice: "192.168.1.20",
			Protocol:          "EtherNetIP",
			PatternType:       "periodic",
			Criticality:       "critical",
			Frequency:         100 * time.Millisecond,
		},
	}

	classification, err := classifier.UpdateClassificationFromPatternChanges("192.168.1.10", oldPatterns, newPatterns)

	assert.NoError(t, err)
	assert.Equal(t, model.DeviceTypePLC, classification.DeviceType)
	assert.Equal(t, model.RoleController, classification.Role)
	assert.Equal(t, model.SecurityLevel4, classification.SecurityLevel)
	assert.Greater(t, classification.Confidence, 0.0)
	assert.Contains(t, classification.Protocols, "EtherNetIP")
	assert.NotEmpty(t, classification.Reasoning)
}

// Helper functions for creating test flows

func createTestFlow(sourceAddr, destAddr, protocol string, timestamp time.Time) model.Flow {
	srcIP, _, _ := addressHelper.ParseAddress(sourceAddr)
	dstIP, _, _ := addressHelper.ParseAddress(destAddr)
	return model.Flow{
		ID:            1,
		SrcIP:         net.ParseIP(srcIP),
		DstIP:         net.ParseIP(dstIP),
		Protocol:      protocol,
		PacketCountIn: 1,
		ByteCountIn:   int64(64),
		FirstSeen:     timestamp,
		LastSeen:      timestamp.Add(10 * time.Millisecond),
	}
}

func createTestRequestFlow(sourceAddr, destAddr, protocol string, timestamp time.Time, byteCount int) model.Flow {
	srcIP, _, _ := addressHelper.ParseAddress(sourceAddr)
	dstIP, _, _ := addressHelper.ParseAddress(destAddr)
	return model.Flow{
		ID:             1,
		SrcIP:          net.ParseIP(srcIP),
		DstIP:          net.ParseIP(dstIP),
		Protocol:       protocol,
		PacketCountOut: 1,
		ByteCountOut:   int64(byteCount),
		FirstSeen:      timestamp,
		LastSeen:       timestamp.Add(5 * time.Millisecond),
	}
}

func createTestResponseFlow(sourceAddr, destAddr, protocol string, timestamp time.Time, byteCount int) model.Flow {
	srcIP, _, _ := addressHelper.ParseAddress(sourceAddr)
	dstIP, _, _ := addressHelper.ParseAddress(destAddr)
	return model.Flow{
		ID:            2,
		SrcIP:         net.ParseIP(srcIP),
		DstIP:         net.ParseIP(dstIP),
		Protocol:      protocol,
		PacketCountIn: 1,
		ByteCountIn:   int64(byteCount),
		FirstSeen:     timestamp,
		LastSeen:      timestamp.Add(10 * time.Millisecond),
	}
}
