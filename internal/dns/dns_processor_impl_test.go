package dns

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/model"
)

type mockRepo struct {
	dnsQueries []*model.DNSQuery
	packets    []*model.Packet
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

func (m *mockRepo) GetDNSQueries(filters map[string]interface{}) ([]*model.DNSQuery, error) {
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
