package repository

import "pcap-importer-golang/internal/model"

// Repository defines the contract for storing and retrieving packets, devices, flows, and DNS queries.
type Repository interface {
	AddPacket(packet *model.Packet) error
	AddDevice(device *model.Device) error
	AddFlow(flow *model.Flow) error
	AddDNSQuery(query *model.DNSQuery) error
	Commit() error
	Close() error
}
