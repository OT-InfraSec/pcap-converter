package testutil

import (
	"pcap-importer-golang/internal/model"
)

type MockRepository struct {
	Packets      []*model.Packet
	Devices      []*model.Device
	Flows        []*model.Flow
	DNSQueries   []*model.DNSQuery
	CommitCalled bool
	CloseCalled  bool
}

func (m *MockRepository) AddPacket(packet *model.Packet) error {
	m.Packets = append(m.Packets, packet)
	return nil
}
func (m *MockRepository) AddDevice(device *model.Device) error {
	m.Devices = append(m.Devices, device)
	return nil
}
func (m *MockRepository) AddFlow(flow *model.Flow) error {
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
