package testutil

import (
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
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
