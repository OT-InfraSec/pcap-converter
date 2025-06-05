package dns

import (
	"testing"
	"time"

	"pcap-importer-golang/internal/model"
)

type mockRepo struct {
	dnsQueries []*model.DNSQuery
	packets    []*model.Packet
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
