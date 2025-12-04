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

	// SSDP operations
	AddSSDPQuery(ssdp *model.SSDPQuery) error
	//GetSSDPQueries(filters map[string]interface{}) ([]*model.SSDPQuery, error)
	// New SSDP operations
	UpdateSSDPQuery(ssdp *model.SSDPQuery) error
	UpsertSSDPQuery(ssdp *model.SSDPQuery) error
	// Batch SSDP operations for performance
	//AddSSDPQueries(ssdps []*model.SSDPQuery) error
	UpsertSSDPQueries(ssdps []*model.SSDPQuery) error

	// Industrial device operations
	SaveIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error
	GetIndustrialDeviceInfo(deviceAddress string) (*model.IndustrialDeviceInfo, error)
	GetIndustrialDevicesByType(deviceType model.IndustrialDeviceType) ([]*model.IndustrialDeviceInfo, error)
	UpdateIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error
	UpsertIndustrialDeviceInfo(info *model.IndustrialDeviceInfo) error
	DeleteIndustrialDeviceInfo(deviceAddress string) error

	// Protocol usage statistics operations
	SaveProtocolUsageStats(stats *model.ProtocolUsageStats) error
	GetProtocolUsageStats(deviceAddress string) ([]*model.ProtocolUsageStats, error)
	GetProtocolUsageStatsByProtocol(protocol string) ([]*model.ProtocolUsageStats, error)
	UpdateProtocolUsageStats(stats *model.ProtocolUsageStats) error
	UpsertProtocolUsageStats(stats *model.ProtocolUsageStats) error
	DeleteProtocolUsageStats(deviceAddress, protocol string) error

	// Communication pattern operations
	SaveCommunicationPattern(pattern *model.CommunicationPattern) error
	GetCommunicationPatterns(deviceAddress string) ([]*model.CommunicationPattern, error)
	GetCommunicationPatternsByProtocol(protocol string) ([]*model.CommunicationPattern, error)
	UpdateCommunicationPattern(pattern *model.CommunicationPattern) error
	UpsertCommunicationPattern(pattern *model.CommunicationPattern) error
	DeleteCommunicationPattern(sourceDeviceAddress, destinationDeviceAddress, protocol string) error

	// Industrial protocol info operations
	SaveIndustrialProtocolInfo(info *model.IndustrialProtocolInfo) error
	GetIndustrialProtocolInfos(deviceAddress string) ([]*model.IndustrialProtocolInfo, error)
	GetIndustrialProtocolInfosByProtocol(protocol string) ([]*model.IndustrialProtocolInfo, error)
	DeleteIndustrialProtocolInfos(deviceAddress string) error

	// Batch operations for industrial data
	SaveIndustrialDeviceInfos(infos []*model.IndustrialDeviceInfo) error
	SaveProtocolUsageStatsMultiple(stats []*model.ProtocolUsageStats) error
	SaveCommunicationPatterns(patterns []*model.CommunicationPattern) error
	SaveIndustrialProtocolInfos(infos []*model.IndustrialProtocolInfo) error

	// Key-value store operations
	// SetKeyValue stores a key-value pair, creating or updating the entry
	SetKeyValue(key, value string) error
	// GetKeyValue retrieves a value by key. Returns the value, whether it exists, and any error.
	GetKeyValue(key string) (value string, exists bool, err error)
	// DeleteKeyValue removes a key-value pair
	DeleteKeyValue(key string) error
	// GetAllKeyValues returns all key-value pairs
	GetAllKeyValues() (map[string]string, error)

	// Transaction operations
	Commit() error
	Close() error
}
