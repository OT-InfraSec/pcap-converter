package dns

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

type mockRepo struct {
	dnsQueries []*model.DNSQuery
	packets    []*model.Packet
}

func (m *mockRepo) SaveIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetIndustrialDeviceInfo(deviceAddress string) (*model.IndustrialDeviceInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetIndustrialDevicesByType(deviceType model.IndustrialDeviceType) ([]*model.IndustrialDeviceInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) UpdateIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) UpsertIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) DeleteIndustrialDeviceInfo(deviceAddress string) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) SaveProtocolUsageStats(stats *model.ProtocolUsageStats) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetProtocolUsageStats(deviceAddress string) ([]*model.ProtocolUsageStats, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetProtocolUsageStatsByProtocol(protocol string) ([]*model.ProtocolUsageStats, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) UpdateProtocolUsageStats(stats *model.ProtocolUsageStats) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) UpsertProtocolUsageStats(stats *model.ProtocolUsageStats) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) DeleteProtocolUsageStats(deviceAddress, protocol string) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) SaveCommunicationPattern(pattern *model.CommunicationPattern) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetCommunicationPatterns(deviceAddress string) ([]*model.CommunicationPattern, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetCommunicationPatternsByProtocol(protocol string) ([]*model.CommunicationPattern, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) UpdateCommunicationPattern(pattern *model.CommunicationPattern) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) UpsertCommunicationPattern(pattern *model.CommunicationPattern) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) DeleteCommunicationPattern(sourceDeviceAddress, destinationDeviceAddress, protocol string) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) SaveIndustrialProtocolInfo(info *model.IndustrialProtocolInfo) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetIndustrialProtocolInfos(deviceAddress string) ([]*model.IndustrialProtocolInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetIndustrialProtocolInfosByProtocol(protocol string) ([]*model.IndustrialProtocolInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) DeleteIndustrialProtocolInfos(deviceAddress string) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) SaveIndustrialDeviceInfos(infos []*model.IndustrialDeviceInfo) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) SaveProtocolUsageStatsMultiple(stats []*model.ProtocolUsageStats) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) SaveCommunicationPatterns(patterns []*model.CommunicationPattern) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) SaveIndustrialProtocolInfos(infos []*model.IndustrialProtocolInfo) error {
	//TODO implement me
	panic("implement me")
}

// AddSSDPQuery implements repository.Repository.
func (m *mockRepo) AddSSDPQuery(ssdp *model.SSDPQuery) error {
	panic("unimplemented")
}

// GetDevices implements repository.Repository.
func (m *mockRepo) GetDevices(filters map[string]interface{}) ([]*model.Device, error) {
	panic("unimplemented")
}

// GetFlows implements repository.Repository.
func (m *mockRepo) GetFlows(filters map[string]interface{}) ([]*model.Flow, error) {
	panic("unimplemented")
}

// UpdateDNSQuery implements repository.Repository.
func (m *mockRepo) UpdateDNSQuery(query *model.DNSQuery) error {
	panic("unimplemented")
}

// UpdateDevice implements repository.Repository.
func (m *mockRepo) UpdateDevice(device *model.Device) error {
	panic("unimplemented")
}

// UpdateDeviceRelation implements repository.Repository.
func (m *mockRepo) UpdateDeviceRelation(relation *model.DeviceRelation) error {
	panic("unimplemented")
}

// UpdateFlow implements repository.Repository.
func (m *mockRepo) UpdateFlow(flow *model.Flow) error {
	panic("unimplemented")
}

// UpdatePacket implements repository.Repository.
func (m *mockRepo) UpdatePacket(packet *model.Packet) error {
	panic("unimplemented")
}

// UpdateSSDPQuery implements repository.Repository.
func (m *mockRepo) UpdateSSDPQuery(ssdp *model.SSDPQuery) error {
	panic("unimplemented")
}

// UpdateService implements repository.Repository.
func (m *mockRepo) UpdateService(service *model.Service) error {
	panic("unimplemented")
}

// UpsertDNSQueries implements repository.Repository.
func (m *mockRepo) UpsertDNSQueries(queries []*model.DNSQuery) error {
	panic("unimplemented")
}

// UpsertDNSQuery implements repository.Repository.
func (m *mockRepo) UpsertDNSQuery(query *model.DNSQuery) error {
	panic("unimplemented")
}

// UpsertDevice implements repository.Repository.
func (m *mockRepo) UpsertDevice(device *model.Device) error {
	panic("unimplemented")
}

// UpsertDeviceRelation implements repository.Repository.
func (m *mockRepo) UpsertDeviceRelation(relation *model.DeviceRelation) error {
	panic("unimplemented")
}

// UpsertDevices implements repository.Repository.
func (m *mockRepo) UpsertDevices(devices []*model.Device) error {
	panic("unimplemented")
}

// UpsertFlow implements repository.Repository.
func (m *mockRepo) UpsertFlow(flow *model.Flow) error {
	panic("unimplemented")
}

// UpsertFlows implements repository.Repository.
func (m *mockRepo) UpsertFlows(flows []*model.Flow) error {
	panic("unimplemented")
}

// UpsertPacket implements repository.Repository.
func (m *mockRepo) UpsertPacket(packet *model.Packet) error {
	panic("unimplemented")
}

// UpsertPackets implements repository.Repository.
func (m *mockRepo) UpsertPackets(packets []*model.Packet) error {
	panic("unimplemented")
}

// UpsertSSDPQueries implements repository.Repository.
func (m *mockRepo) UpsertSSDPQueries(ssdps []*model.SSDPQuery) error {
	panic("unimplemented")
}

// UpsertSSDPQuery implements repository.Repository.
func (m *mockRepo) UpsertSSDPQuery(ssdp *model.SSDPQuery) error {
	panic("unimplemented")
}

// UpsertService implements repository.Repository.
func (m *mockRepo) UpsertService(service *model.Service) error {
	panic("unimplemented")
}

// UpsertServices implements repository.Repository.
func (m *mockRepo) UpsertServices(services []*model.Service) error {
	panic("unimplemented")
}

func (m *mockRepo) AddPackets(packets []*model.Packet) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetDevice(address string) (*model.Device, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) AddDeviceRelation(relation *model.DeviceRelation) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetDeviceRelations(deviceID *int64) ([]*model.DeviceRelation, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) AddDevices(devices []*model.Device) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) AddService(service *model.Service) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetServices(filters map[string]interface{}) ([]*model.Service, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) AddServices(services []*model.Service) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) AddFlows(flows []*model.Flow) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) GetDNSQueries(eqFilters map[string]interface{}, likeFilters map[string]interface{}) ([]*model.DNSQuery, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) AddDNSQueries(queries []*model.DNSQuery) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockRepo) AddPacket(_ *model.Packet) error { return nil }
func (m *mockRepo) AddDevice(_ *model.Device) error { return nil }
func (m *mockRepo) AddFlow(_ *model.Flow) error     { return nil }
func (m *mockRepo) AddDNSQuery(q *model.DNSQuery) error {
	m.dnsQueries = append(m.dnsQueries, q)
	return nil
}
func (m *mockRepo) Commit() error                        { return nil }
func (m *mockRepo) Close() error                         { return nil }
func (m *mockRepo) AllPackets() ([]*model.Packet, error) { return m.packets, nil }

func TestDefaultDNSProcessor_Process(t *testing.T) {
	ts := time.Now()
	repo := &mockRepo{
		packets: []*model.Packet{
			{
				Timestamp: ts,
				Layers: map[string]interface{}{
					"dns": map[string]interface{}{
						"id":         1,
						"qr":         false,
						"questions":  1.0,
						"query_name": "example.com",
						"query_type": "A",
					},
					"ip": map[string]interface{}{
						"src_ip": "1.1.1.1",
						"dst_ip": "8.8.8.8",
					},
					"udp": map[string]interface{}{
						"src_port": "12345",
						"dst_port": "53",
					},
				},
			},
			{
				Timestamp: ts.Add(time.Second),
				Layers: map[string]interface{}{
					"dns": map[string]interface{}{
						"id":         1,
						"qr":         true,
						"questions":  1.0,
						"query_name": "example.com",
						"query_type": "A",
					},
					"ip": map[string]interface{}{
						"src_ip": "8.8.8.8",
						"dst_ip": "1.1.1.1",
					},
					"udp": map[string]interface{}{
						"src_port": "53",
						"dst_port": "12345",
					},
				},
			},
		},
	}

	processor := NewDefaultDNSProcessor()
	err := processor.Process(repo)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if len(repo.dnsQueries) != 1 {
		t.Errorf("expected 1 DNSQuery, got %d", len(repo.dnsQueries))
	}
	if repo.dnsQueries[0].QueryName != "example.com" {
		t.Errorf("expected QueryName 'example.com', got %s", repo.dnsQueries[0].QueryName)
	}
}
