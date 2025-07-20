package repository

import (
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// Repository defines the contract for storing and retrieving packets, devices, flows, and DNS queries.
type Repository interface {
	// Packet operations
	AddPacket(packet *model.Packet) error
	AllPackets() ([]*model.Packet, error)
	// Batch packet operations for performance
	AddPackets(packets []*model.Packet) error
	// New Packet operations
	UpdatePacket(packet *model.Packet) error
	UpsertPacket(packet *model.Packet) error
	UpsertPackets(packets []*model.Packet) error

	// Device operations
	AddDevice(device *model.Device) error
	GetDevice(address string) (*model.Device, error)
	GetDevices(filters map[string]interface{}) ([]*model.Device, error)
	UpdateDevice(device *model.Device) error
	UpsertDevice(device *model.Device) error
	UpsertDevices(devices []*model.Device) error
	AddDeviceRelation(relation *model.DeviceRelation) error
	GetDeviceRelations(deviceID *int64) ([]*model.DeviceRelation, error)
	// Device Relation operations
	UpdateDeviceRelation(relation *model.DeviceRelation) error
	UpsertDeviceRelation(relation *model.DeviceRelation) error
	// Batch device operations for performance
	AddDevices(devices []*model.Device) error

	// Service operations
	AddService(service *model.Service) error
	GetServices(filters map[string]interface{}) ([]*model.Service, error)
	// New Service operations
	UpdateService(service *model.Service) error
	UpsertService(service *model.Service) error
	// Batch service operations for performance
	AddServices(services []*model.Service) error
	UpsertServices(services []*model.Service) error

	// Flow operations
	AddFlow(flow *model.Flow) error
	GetFlows(filters map[string]interface{}) ([]*model.Flow, error)
	// New Flow operations
	UpdateFlow(flow *model.Flow) error
	UpsertFlow(flow *model.Flow) error
	// Batch flow operations for performance
	AddFlows(flows []*model.Flow) error
	UpsertFlows(flows []*model.Flow) error

	// DNS operations
	AddDNSQuery(query *model.DNSQuery) error
	GetDNSQueries(eqFilters map[string]interface{}, likeFilters map[string]interface{}) ([]*model.DNSQuery, error)
	// New DNS operations
	UpdateDNSQuery(query *model.DNSQuery) error
	UpsertDNSQuery(query *model.DNSQuery) error
	// Batch DNS operations for performance
	AddDNSQueries(queries []*model.DNSQuery) error
	UpsertDNSQueries(queries []*model.DNSQuery) error

	// Transaction operations
	Commit() error
	Close() error
}
