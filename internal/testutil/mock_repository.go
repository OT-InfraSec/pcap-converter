package testutil

import (
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

type MockRepository struct {
	repository.Repository
	Packets               []*model.Packet
	Devices               []*model.Device
	Flows                 []*model.Flow
	DNSQueries            []*model.DNSQuery
	DeviceRelations       []*model.DeviceRelation
	ProtocolStats         []*model.ProtocolUsageStats
	CommunicationPatterns []*model.CommunicationPattern
	CommitCalled          bool
	CloseCalled           bool
}

func (m *MockRepository) AddPacket(packet *model.Packet) error {
	m.Packets = append(m.Packets, packet)
	return nil
}
func (m *MockRepository) AddDevice(device *model.Device) error {
	// Validiere das Device, bevor es hinzugefügt wird
	if err := device.Validate(); err != nil {
		return err
	}
	m.Devices = append(m.Devices, device)
	return nil
}
func (m *MockRepository) AddFlow(flow *model.Flow) error {
	// Validiere den Flow, bevor er hinzugefügt wird
	if err := flow.Validate(); err != nil {
		return err
	}
	m.Flows = append(m.Flows, flow)
	return nil
}
func (m *MockRepository) AddDNSQuery(query *model.DNSQuery) error {
	m.DNSQueries = append(m.DNSQueries, query)
	return nil
}
func (m *MockRepository) Commit() error {
	m.CommitCalled = true
	return nil
}
func (m *MockRepository) Close() error {
	m.CloseCalled = true
	return nil
}
func (m *MockRepository) AddDeviceRelation(relation *model.DeviceRelation) error {
	m.DeviceRelations = append(m.DeviceRelations, relation)
	return nil
}

func (m *MockRepository) GetDevices(filters map[string]interface{}) ([]*model.Device, error) {
	return m.Devices, nil
}

func (m *MockRepository) GetFlows(filters map[string]interface{}) ([]*model.Flow, error) {
	return m.Flows, nil
}

func (m *MockRepository) GetDNSQueries(eqFilters map[string]interface{}, likeFilters map[string]interface{}) ([]*model.DNSQuery, error) {
	return m.DNSQueries, nil
}

func (m *MockRepository) GetDeviceRelations(deviceID *int64) ([]*model.DeviceRelation, error) {
	return m.DeviceRelations, nil
}

func (m *MockRepository) GetDevice(address string) (*model.Device, error) {
	for _, device := range m.Devices {
		if device.Address == address {
			return device, nil
		}
	}
	return nil, nil
}

func (m *MockRepository) GetServices(filters map[string]interface{}) ([]*model.Service, error) {
	return []*model.Service{}, nil
}

func (m *MockRepository) UpsertDevice(device *model.Device) error {
	for i, d := range m.Devices {
		if d.Address == device.Address {
			m.Devices[i] = device
			return nil
		}
	}
	m.Devices = append(m.Devices, device)
	return nil
}

func (m *MockRepository) UpsertFlow(flow *model.Flow) error {
	for i, f := range m.Flows {
		if f.ID == flow.ID {
			m.Flows[i] = flow
			return nil
		}
	}
	m.Flows = append(m.Flows, flow)
	return nil
}

func (m *MockRepository) UpsertDNSQuery(query *model.DNSQuery) error {
	for i, q := range m.DNSQueries {
		if q.ID == query.ID {
			m.DNSQueries[i] = query
			return nil
		}
	}
	m.DNSQueries = append(m.DNSQueries, query)
	return nil
}

func (m *MockRepository) UpsertDeviceRelation(relation *model.DeviceRelation) error {
	for i, r := range m.DeviceRelations {
		if r.ID == relation.ID {
			m.DeviceRelations[i] = relation
			return nil
		}
	}
	m.DeviceRelations = append(m.DeviceRelations, relation)
	return nil
}

func (m *MockRepository) UpdateDevice(device *model.Device) error {
	for i, d := range m.Devices {
		if d.Address == device.Address {
			m.Devices[i] = device
			return nil
		}
	}
	return nil
}

func (m *MockRepository) UpsertPackets(packets []*model.Packet) error {
	for _, packet := range packets {
		found := false
		for i, p := range m.Packets {
			if p.ID == packet.ID {
				m.Packets[i] = packet
				found = true
				break
			}
		}
		if !found {
			m.Packets = append(m.Packets, packet)
		}
	}
	return nil
}

func (m *MockRepository) UpsertDevices(devices []*model.Device) error {
	for _, device := range devices {
		found := false
		for i, d := range m.Devices {
			if d.Address == device.Address {
				m.Devices[i] = device
				found = true
				break
			}
		}
		if !found {
			m.Devices = append(m.Devices, device)
		}
	}
	return nil
}

// Industrial device methods

func (m *MockRepository) SaveIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error {
	// Find the device and update its industrial info
	for _, device := range m.Devices {
		if device.Address == info.DeviceAddress {
			device.IndustrialInfo = info
			return nil
		}
	}
	return nil
}

func (m *MockRepository) GetIndustrialDeviceInfo(deviceAddress string) (*model.IndustrialDeviceInfo, error) {
	for _, device := range m.Devices {
		if device.Address == deviceAddress && device.IndustrialInfo != nil {
			return device.IndustrialInfo, nil
		}
	}
	return nil, nil
}

func (m *MockRepository) GetIndustrialDevicesByType(deviceType model.IndustrialDeviceType) ([]*model.IndustrialDeviceInfo, error) {
	var result []*model.IndustrialDeviceInfo
	for _, device := range m.Devices {
		if device.IndustrialInfo != nil && device.IndustrialInfo.DeviceType == deviceType {
			result = append(result, device.IndustrialInfo)
		}
	}
	return result, nil
}

func (m *MockRepository) UpdateIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error {
	return m.SaveIndustrialDeviceInfo(info)
}

func (m *MockRepository) UpsertIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error {
	return m.SaveIndustrialDeviceInfo(info)
}

func (m *MockRepository) DeleteIndustrialDeviceInfo(deviceAddress string) error {
	for _, device := range m.Devices {
		if device.Address == deviceAddress {
			device.IndustrialInfo = nil
			return nil
		}
	}
	return nil
}

func (m *MockRepository) SaveProtocolUsageStats(stats *model.ProtocolUsageStats) error {
	m.ProtocolStats = append(m.ProtocolStats, stats)
	return nil
}

func (m *MockRepository) GetProtocolUsageStats(deviceAddress string) ([]*model.ProtocolUsageStats, error) {
	var result []*model.ProtocolUsageStats
	for _, stats := range m.ProtocolStats {
		if stats.DeviceID == deviceAddress {
			result = append(result, stats)
		}
	}
	return result, nil
}

func (m *MockRepository) GetProtocolUsageStatsByProtocol(protocol string) ([]*model.ProtocolUsageStats, error) {
	var result []*model.ProtocolUsageStats
	for _, stats := range m.ProtocolStats {
		if stats.Protocol == protocol {
			result = append(result, stats)
		}
	}
	return result, nil
}

func (m *MockRepository) UpdateProtocolUsageStats(stats *model.ProtocolUsageStats) error {
	return m.SaveProtocolUsageStats(stats)
}

func (m *MockRepository) UpsertProtocolUsageStats(stats *model.ProtocolUsageStats) error {
	return m.SaveProtocolUsageStats(stats)
}

func (m *MockRepository) DeleteProtocolUsageStats(deviceAddress, protocol string) error {
	for i := len(m.ProtocolStats) - 1; i >= 0; i-- {
		stats := m.ProtocolStats[i]
		if stats.DeviceID == deviceAddress && stats.Protocol == protocol {
			m.ProtocolStats = append(m.ProtocolStats[:i], m.ProtocolStats[i+1:]...)
		}
	}
	return nil
}

func (m *MockRepository) SaveCommunicationPattern(pattern *model.CommunicationPattern) error {
	m.CommunicationPatterns = append(m.CommunicationPatterns, pattern)
	return nil
}

func (m *MockRepository) GetCommunicationPatterns(deviceAddress string) ([]*model.CommunicationPattern, error) {
	var result []*model.CommunicationPattern
	for _, pattern := range m.CommunicationPatterns {
		if pattern.SourceDevice == deviceAddress || pattern.DestinationDevice == deviceAddress {
			result = append(result, pattern)
		}
	}
	return result, nil
}

func (m *MockRepository) GetCommunicationPatternsByProtocol(protocol string) ([]*model.CommunicationPattern, error) {
	var result []*model.CommunicationPattern
	for _, pattern := range m.CommunicationPatterns {
		if pattern.Protocol == protocol {
			result = append(result, pattern)
		}
	}
	return result, nil
}

func (m *MockRepository) UpdateCommunicationPattern(pattern *model.CommunicationPattern) error {
	return m.SaveCommunicationPattern(pattern)
}

func (m *MockRepository) UpsertCommunicationPattern(pattern *model.CommunicationPattern) error {
	return m.SaveCommunicationPattern(pattern)
}

func (m *MockRepository) DeleteCommunicationPattern(sourceDeviceAddress, destinationDeviceAddress, protocol string) error {
	for i := len(m.CommunicationPatterns) - 1; i >= 0; i-- {
		pattern := m.CommunicationPatterns[i]
		if pattern.SourceDevice == sourceDeviceAddress &&
			pattern.DestinationDevice == destinationDeviceAddress &&
			pattern.Protocol == protocol {
			m.CommunicationPatterns = append(m.CommunicationPatterns[:i], m.CommunicationPatterns[i+1:]...)
		}
	}
	return nil
}

// Batch operations
func (m *MockRepository) SaveIndustrialDeviceInfos(infos []*model.IndustrialDeviceInfo) error {
	for _, info := range infos {
		if err := m.SaveIndustrialDeviceInfo(info); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockRepository) SaveProtocolUsageStatsMultiple(stats []*model.ProtocolUsageStats) error {
	for _, stat := range stats {
		if err := m.SaveProtocolUsageStats(stat); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockRepository) SaveCommunicationPatterns(patterns []*model.CommunicationPattern) error {
	for _, pattern := range patterns {
		if err := m.SaveCommunicationPattern(pattern); err != nil {
			return err
		}
	}
	return nil
}

// Helper methods for tests

func (m *MockRepository) GetSavedDevices() []*model.Device {
	return m.Devices
}

func (m *MockRepository) GetSavedProtocolStats() []*model.ProtocolUsageStats {
	return m.ProtocolStats
}

func (m *MockRepository) GetSavedCommunicationPatterns() []*model.CommunicationPattern {
	return m.CommunicationPatterns
}

// Additional methods to satisfy Repository interface

func (m *MockRepository) AllPackets() ([]*model.Packet, error) {
	return m.Packets, nil
}

func (m *MockRepository) AddPackets(packets []*model.Packet) error {
	m.Packets = append(m.Packets, packets...)
	return nil
}

func (m *MockRepository) UpdatePacket(packet *model.Packet) error {
	return m.AddPacket(packet)
}

func (m *MockRepository) UpsertPacket(packet *model.Packet) error {
	return m.AddPacket(packet)
}

func (m *MockRepository) AddDevices(devices []*model.Device) error {
	for _, device := range devices {
		if err := m.AddDevice(device); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockRepository) UpdateDeviceRelation(relation *model.DeviceRelation) error {
	return m.AddDeviceRelation(relation)
}

func (m *MockRepository) AddService(service *model.Service) error {
	// Mock implementation - services not tracked in this mock
	return nil
}

func (m *MockRepository) UpdateService(service *model.Service) error {
	return nil
}

func (m *MockRepository) UpsertService(service *model.Service) error {
	return nil
}

func (m *MockRepository) AddServices(services []*model.Service) error {
	return nil
}

func (m *MockRepository) UpsertServices(services []*model.Service) error {
	return nil
}

func (m *MockRepository) UpdateFlow(flow *model.Flow) error {
	return m.AddFlow(flow)
}

func (m *MockRepository) AddFlows(flows []*model.Flow) error {
	for _, flow := range flows {
		if err := m.AddFlow(flow); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockRepository) UpsertFlows(flows []*model.Flow) error {
	return m.AddFlows(flows)
}

func (m *MockRepository) UpdateDNSQuery(query *model.DNSQuery) error {
	return m.AddDNSQuery(query)
}

func (m *MockRepository) AddDNSQueries(queries []*model.DNSQuery) error {
	for _, query := range queries {
		if err := m.AddDNSQuery(query); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockRepository) UpsertDNSQueries(queries []*model.DNSQuery) error {
	return m.AddDNSQueries(queries)
}

func (m *MockRepository) AddSSDPQuery(ssdp *model.SSDPQuery) error {
	// Mock implementation - SSDP queries not tracked in this mock
	return nil
}

func (m *MockRepository) UpdateSSDPQuery(ssdp *model.SSDPQuery) error {
	return nil
}

func (m *MockRepository) UpsertSSDPQuery(ssdp *model.SSDPQuery) error {
	return nil
}

func (m *MockRepository) UpsertSSDPQueries(ssdps []*model.SSDPQuery) error {
	return nil
}
