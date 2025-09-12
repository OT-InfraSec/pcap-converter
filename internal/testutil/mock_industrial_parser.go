package testutil

import (
	"github.com/google/gopacket"
	"github.com/stretchr/testify/mock"
)

// MockIndustrialProtocolParser is a mock implementation of IndustrialProtocolParser
type MockIndustrialProtocolParser struct {
	mock.Mock
}

func (m *MockIndustrialProtocolParser) ParseIndustrialProtocols(packet gopacket.Packet) (interface{}, error) {
	args := m.Called(packet)
	return args.Get(0), args.Error(1)
}

func (m *MockIndustrialProtocolParser) DetectDeviceType(protocols interface{}, flows interface{}) interface{} {
	args := m.Called(protocols, flows)
	return args.Get(0)
}

func (m *MockIndustrialProtocolParser) AnalyzeCommunicationPatterns(flows interface{}) interface{} {
	args := m.Called(flows)
	return args.Get(0)
}

func (m *MockIndustrialProtocolParser) CollectProtocolUsageStats(deviceID string, protocols interface{}) (interface{}, error) {
	args := m.Called(deviceID, protocols)
	return args.Get(0), args.Error(1)
}

func (m *MockIndustrialProtocolParser) SetErrorHandler(handler interface{}) {
	m.Called(handler)
}

func (m *MockIndustrialProtocolParser) GetErrorHandler() interface{} {
	args := m.Called()
	return args.Get(0)
}
