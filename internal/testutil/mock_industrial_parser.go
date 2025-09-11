package testutil

import (
	"github.com/InfraSecConsult/pcap-importer-go/internal/parser"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/mock"
)

// MockIndustrialProtocolParser is a mock implementation of IndustrialProtocolParser
type MockIndustrialProtocolParser struct {
	mock.Mock
}

func (m *MockIndustrialProtocolParser) ParseIndustrialProtocols(packet gopacket.Packet) ([]parser.IndustrialProtocolInfo, error) {
	args := m.Called(packet)
	return args.Get(0).([]parser.IndustrialProtocolInfo), args.Error(1)
}

func (m *MockIndustrialProtocolParser) DetectDeviceType(protocols []parser.IndustrialProtocolInfo, flows []model.Flow) model.IndustrialDeviceType {
	args := m.Called(protocols, flows)
	return args.Get(0).(model.IndustrialDeviceType)
}

func (m *MockIndustrialProtocolParser) AnalyzeCommunicationPatterns(flows []model.Flow) []model.CommunicationPattern {
	args := m.Called(flows)
	return args.Get(0).([]model.CommunicationPattern)
}

func (m *MockIndustrialProtocolParser) CollectProtocolUsageStats(deviceID string, protocols []parser.IndustrialProtocolInfo) (*model.ProtocolUsageStats, error) {
	args := m.Called(deviceID, protocols)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.ProtocolUsageStats), args.Error(1)
}
