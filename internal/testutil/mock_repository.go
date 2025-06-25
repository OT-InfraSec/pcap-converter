package testutil

import (
	"github.com/InfraSecConsult/pcap-importer-go/internal/model"
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
)

type MockRepository struct {
	repository.Repository
	Packets         []*model.Packet
	Devices         []*model.Device
	Flows           []*model.Flow
	DNSQueries      []*model.DNSQuery
	DeviceRelations []*model.DeviceRelation
	CommitCalled    bool
	CloseCalled     bool
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
