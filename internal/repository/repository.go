package repository

import "pcap-importer-golang/internal/model"

// Repository defines the contract for storing and retrieving packets, devices, flows, and DNS queries.
type Repository interface {
	// Packet operations
	AddPacket(packet *model.Packet) error
	AllPackets() ([]*model.Packet, error)

	// Device operations
	AddDevice(device *model.Device) error
	AddDeviceRelation(relation *model.DeviceRelation) error
	GetDeviceRelations(deviceID *int64) ([]*model.DeviceRelation, error)

	// Service operations
	AddService(service *model.Service) error
	GetServices(filters map[string]interface{}) ([]*model.Service, error)

	// Flow operations
	AddFlow(flow *model.Flow) error

	// DNS operations
	AddDNSQuery(query *model.DNSQuery) error
	GetDNSQueries(filters map[string]interface{}) ([]*model.DNSQuery, error)

	// Transaction operations
	Commit() error
	Close() error
}
