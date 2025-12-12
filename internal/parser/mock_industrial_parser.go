package parser

import (
	"net"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/mock"
)

// MockIndustrialProtocolParser is a mock implementation of IndustrialProtocolParser for testing
type MockIndustrialProtocolParser struct {
	mock.Mock
}

// ParseIndustrialProtocols mocks the ParseIndustrialProtocols method
func (m *MockIndustrialProtocolParser) ParseIndustrialProtocols(packet gopacket.Packet) ([]model.IndustrialProtocolInfo, error) {
	args := m.Called(packet)
	return args.Get(0).([]model.IndustrialProtocolInfo), args.Error(1)
}

// DetectDeviceType mocks the DetectDeviceType method
func (m *MockIndustrialProtocolParser) DetectDeviceType(protocols []model.IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType {
	args := m.Called(protocols, flows)
	return args.Get(0).(model.IndustrialDeviceType)
}

// AnalyzeCommunicationPatterns mocks the AnalyzeCommunicationPatterns method
func (m *MockIndustrialProtocolParser) AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern {
	args := m.Called(flows)
	return args.Get(0).([]model.CommunicationPattern)
}

// CollectProtocolUsageStats mocks the CollectProtocolUsageStats method
func (m *MockIndustrialProtocolParser) CollectProtocolUsageStats(deviceID string, protocols []model.IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	args := m.Called(deviceID, protocols)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.ProtocolUsageStats), args.Error(1)
}

// NewMockIndustrialProtocolParser creates a new mock industrial protocol parser
func NewMockIndustrialProtocolParser() *MockIndustrialProtocolParser {
	return &MockIndustrialProtocolParser{}
}

// Helper methods for creating test data

// CreateTestIndustrialProtocolInfo creates a test model.IndustrialProtocolInfo for testing
func CreateTestIndustrialProtocolInfo(protocol string, port uint16) model.IndustrialProtocolInfo {
	return model.IndustrialProtocolInfo{
		Protocol:        protocol,
		Port:            port,
		Direction:       "bidirectional",
		Timestamp:       time.Now(),
		Confidence:      0.9,
		ServiceType:     "test_service",
		MessageType:     "test_message",
		IsRealTimeData:  false,
		IsDiscovery:     false,
		IsConfiguration: false,
		DeviceIdentity:  make(map[string]interface{}),
		SecurityInfo:    make(map[string]interface{}),
		AdditionalData:  make(map[string]interface{}),
	}
}

// CreateTestEtherNetIPInfo creates test EtherNet/IP protocol info
func CreateTestEtherNetIPInfo() model.IndustrialProtocolInfo {
	info := CreateTestIndustrialProtocolInfo("EtherNet/IP", 44818)
	info.ServiceType = "explicit_messaging"
	info.IsRealTimeData = true
	info.DeviceIdentity["vendor_id"] = uint16(1) // Allen-Bradley
	info.DeviceIdentity["product_code"] = uint16(150)
	info.DeviceIdentity["device_type"] = "PLC"
	return info
}

// CreateTestOPCUAInfo creates test OPC UA protocol info
func CreateTestOPCUAInfo() model.IndustrialProtocolInfo {
	info := CreateTestIndustrialProtocolInfo("OPC UA", 4840)
	info.ServiceType = "service_call"
	info.MessageType = "CreateSession"
	info.IsConfiguration = true
	info.SecurityInfo["security_policy"] = "Basic256Sha256"
	info.SecurityInfo["security_mode"] = "SignAndEncrypt"
	return info
}

// CreateTestModbusInfo creates test Modbus TCP protocol info
func CreateTestModbusInfo() model.IndustrialProtocolInfo {
	info := CreateTestIndustrialProtocolInfo("Modbus TCP", 502)
	info.ServiceType = "modbus_request"
	info.IsRealTimeData = true
	info.AdditionalData["function_code"] = uint8(3) // Read Holding Registers
	return info
}

// CreateTestCommunicationPattern creates a test communication pattern
func CreateTestCommunicationPattern(source, dest, protocol string) model.CommunicationPattern {
	return model.CommunicationPattern{
		SourceDevice:      source,
		DestinationDevice: dest,
		Protocol:          protocol,
		Frequency:         time.Second * 5,
		DataVolume:        1024,
		PatternType:       "periodic",
		Criticality:       "high",
	}
}

// CreateTestFlows creates test flows for device classification testing
func CreateTestFlows(sourceIP, destIP string, protocol string, packetCount int, byteCount int) []model.Flow {
	flow := model.Flow{
		SrcIP:         net.ParseIP(sourceIP),
		DstIP:         net.ParseIP(destIP),
		Protocol:      protocol,
		PacketCountOut: packetCount,
		ByteCountOut:  int64(byteCount),
		PacketCountIn: 0,
		ByteCountIn:   0,
		FirstSeen:     time.Now().Add(-time.Hour),
		LastSeen:      time.Now(),
	}

	return []model.Flow{flow}
}

// SetupMockIndustrialParserForPLC sets up mock expectations for PLC device classification
func SetupMockIndustrialParserForPLC(mockParser *MockIndustrialProtocolParser) {
	ethernetIPInfo := CreateTestEtherNetIPInfo()
	protocols := []model.IndustrialProtocolInfo{ethernetIPInfo}

	mockParser.On("ParseIndustrialProtocols", gopacket.Packet(nil)).Return(protocols, nil)
	mockParser.On("DetectDeviceType", protocols, mock.AnythingOfType("[]model.Flow")).Return(model.DeviceTypePLC)
	mockParser.On("AnalyzeCommunicationPatterns", mock.AnythingOfType("[]model.Flow")).Return([]model.CommunicationPattern{
		CreateTestCommunicationPattern("192.168.1.10", "192.168.1.100", "EtherNet/IP"),
	})
}

// SetupMockIndustrialParserForHMI sets up mock expectations for HMI device classification
func SetupMockIndustrialParserForHMI(mockParser *MockIndustrialProtocolParser) {
	opcuaInfo := CreateTestOPCUAInfo()
	protocols := []model.IndustrialProtocolInfo{opcuaInfo}

	mockParser.On("ParseIndustrialProtocols", gopacket.Packet(nil)).Return(protocols, nil)
	mockParser.On("DetectDeviceType", protocols, mock.AnythingOfType("[]model.Flow")).Return(model.DeviceTypeHMI)
	mockParser.On("AnalyzeCommunicationPatterns", mock.AnythingOfType("[]model.Flow")).Return([]model.CommunicationPattern{
		CreateTestCommunicationPattern("192.168.1.20", "192.168.1.100", "OPC UA"),
	})
}

// SetupMockIndustrialParserForIODevice sets up mock expectations for I/O device classification
func SetupMockIndustrialParserForIODevice(mockParser *MockIndustrialProtocolParser) {
	modbusInfo := CreateTestModbusInfo()
	protocols := []model.IndustrialProtocolInfo{modbusInfo}

	mockParser.On("ParseIndustrialProtocols", gopacket.Packet(nil)).Return(protocols, nil)
	mockParser.On("DetectDeviceType", protocols, mock.AnythingOfType("[]model.Flow")).Return(model.DeviceTypeIODevice)
	mockParser.On("AnalyzeCommunicationPatterns", mock.AnythingOfType("[]model.Flow")).Return([]model.CommunicationPattern{
		CreateTestCommunicationPattern("192.168.1.30", "192.168.1.100", "Modbus TCP"),
	})
}
