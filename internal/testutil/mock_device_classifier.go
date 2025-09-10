package testutil

import (
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/iec62443"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/mock"
)

// MockDeviceClassifier is a mock implementation of the DeviceClassifier interface
type MockDeviceClassifier struct {
	mock.Mock
}

// ClassifyDevice mocks the ClassifyDevice method
func (m *MockDeviceClassifier) ClassifyDevice(device model.Device, protocols []iec62443.IndustrialProtocolInfo, patterns []model.CommunicationPattern) iec62443.IndustrialDeviceClassification {
	args := m.Called(device, protocols, patterns)
	return args.Get(0).(iec62443.IndustrialDeviceClassification)
}

// UpdateDeviceRole mocks the UpdateDeviceRole method
func (m *MockDeviceClassifier) UpdateDeviceRole(deviceID string, newRole model.IndustrialDeviceRole) error {
	args := m.Called(deviceID, newRole)
	return args.Error(0)
}

// GetDevicesByType mocks the GetDevicesByType method
func (m *MockDeviceClassifier) GetDevicesByType(deviceType model.IndustrialDeviceType) ([]model.Device, error) {
	args := m.Called(deviceType)
	return args.Get(0).([]model.Device), args.Error(1)
}

// AnalyzeProtocolUsage mocks the AnalyzeProtocolUsage method
func (m *MockDeviceClassifier) AnalyzeProtocolUsage(protocols []iec62443.IndustrialProtocolInfo) iec62443.ProtocolAnalysisResult {
	args := m.Called(protocols)
	return args.Get(0).(iec62443.ProtocolAnalysisResult)
}

// AnalyzeCommunicationPatterns mocks the AnalyzeCommunicationPatterns method
func (m *MockDeviceClassifier) AnalyzeCommunicationPatterns(patterns []model.CommunicationPattern) iec62443.CommunicationAnalysisResult {
	args := m.Called(patterns)
	return args.Get(0).(iec62443.CommunicationAnalysisResult)
}

// CalculateConfidence mocks the CalculateConfidence method
func (m *MockDeviceClassifier) CalculateConfidence(device model.Device, protocols []iec62443.IndustrialProtocolInfo, patterns []model.CommunicationPattern) float64 {
	args := m.Called(device, protocols, patterns)
	return args.Get(0).(float64)
}

// CalculateAdvancedConfidence mocks the CalculateAdvancedConfidence method
func (m *MockDeviceClassifier) CalculateAdvancedConfidence(device model.Device, protocols []iec62443.IndustrialProtocolInfo, patterns []model.CommunicationPattern) iec62443.ConfidenceScore {
	args := m.Called(device, protocols, patterns)
	return args.Get(0).(iec62443.ConfidenceScore)
}

// ValidateClassification mocks the ValidateClassification method
func (m *MockDeviceClassifier) ValidateClassification(classification iec62443.IndustrialDeviceClassification) iec62443.ValidationResult {
	args := m.Called(classification)
	return args.Get(0).(iec62443.ValidationResult)
}

// GetUncertaintyIndicators mocks the GetUncertaintyIndicators method
func (m *MockDeviceClassifier) GetUncertaintyIndicators(classification iec62443.IndustrialDeviceClassification) iec62443.UncertaintyIndicators {
	args := m.Called(classification)
	return args.Get(0).(iec62443.UncertaintyIndicators)
}

// MockDeviceRepository is a mock implementation of the DeviceRepository interface
type MockDeviceRepository struct {
	mock.Mock
}

// GetDevicesByType mocks the GetDevicesByType method
func (m *MockDeviceRepository) GetDevicesByType(deviceType model.IndustrialDeviceType) ([]model.Device, error) {
	args := m.Called(deviceType)
	return args.Get(0).([]model.Device), args.Error(1)
}

// UpdateDevice mocks the UpdateDevice method
func (m *MockDeviceRepository) UpdateDevice(device *model.Device) error {
	args := m.Called(device)
	return args.Error(0)
}

// Helper functions for creating test data

// CreateTestPLCDevice creates a test PLC device for testing
func CreateTestPLCDevice() model.Device {
	return model.Device{
		ID:          1,
		Address:     "192.168.1.10",
		AddressType: "IPv4",
		FirstSeen:   time.Now().Add(-24 * time.Hour),
		LastSeen:    time.Now(),
	}
}

// CreateTestHMIDevice creates a test HMI device for testing
func CreateTestHMIDevice() model.Device {
	return model.Device{
		ID:          2,
		Address:     "192.168.1.20",
		AddressType: "IPv4",
		FirstSeen:   time.Now().Add(-12 * time.Hour),
		LastSeen:    time.Now(),
	}
}

// CreateTestSCADADevice creates a test SCADA device for testing
func CreateTestSCADADevice() model.Device {
	return model.Device{
		ID:          3,
		Address:     "192.168.1.30",
		AddressType: "IPv4",
		FirstSeen:   time.Now().Add(-6 * time.Hour),
		LastSeen:    time.Now(),
	}
}

// CreateTestEtherNetIPProtocol creates test EtherNet/IP protocol info
func CreateTestEtherNetIPProtocol() iec62443.IndustrialProtocolInfo {
	return iec62443.IndustrialProtocolInfo{
		Protocol:  "EtherNetIP",
		Port:      44818,
		Direction: "bidirectional",
		DeviceIdentity: map[string]interface{}{
			"vendor_id":    123,
			"product_code": 456,
			"device_type":  "PLC",
		},
		SecurityInfo: map[string]interface{}{
			"security_enabled": false,
		},
		ServiceType: "explicit",
	}
}

// CreateTestOPCUAProtocol creates test OPC UA protocol info
func CreateTestOPCUAProtocol() iec62443.IndustrialProtocolInfo {
	return iec62443.IndustrialProtocolInfo{
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
	}
}

// CreateTestCommunicationPattern creates a test communication pattern
func CreateTestCommunicationPattern() model.CommunicationPattern {
	return model.CommunicationPattern{
		SourceDevice:      "192.168.1.10",
		DestinationDevice: "192.168.1.20",
		Protocol:          "EtherNetIP",
		Frequency:         1 * time.Second,
		DataVolume:        1024,
		PatternType:       "periodic",
		Criticality:       "high",
	}
}

// CreateTestIndustrialDeviceClassification creates a test device classification
func CreateTestIndustrialDeviceClassification() iec62443.IndustrialDeviceClassification {
	return iec62443.IndustrialDeviceClassification{
		DeviceType:    model.DeviceTypePLC,
		Role:          model.RoleController,
		Confidence:    0.85,
		Protocols:     []string{"EtherNetIP", "Modbus"},
		SecurityLevel: model.SecurityLevel2,
		LastUpdated:   time.Now(),
		Reasoning:     "Classified as PLC with controller role based on: industrial protocols detected (EtherNetIP, Modbus), producer-consumer communication pattern, high criticality communications",
	}
}
