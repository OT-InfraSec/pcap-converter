package model

import "time"

// Packet represents a network packet.
type Packet struct {
	ID        int64                  // Database ID (optional)
	Timestamp time.Time              // Packet timestamp
	Length    int                    // Packet length in bytes
	Layers    map[string]interface{} // Protocol layers and their fields
	Protocols []string               // List of protocol names
}

// Device represents a network device.
type Device struct {
	ID             int64
	Address        string
	AddressType    string
	FirstSeen      time.Time
	LastSeen       time.Time
	AddressSubType string
	AddressScope   string
}

// Flow represents a network flow between devices or services.
type Flow struct {
	ID                  int64
	Source              string
	Destination         string
	Protocol            string
	Packets             int
	Bytes               int
	FirstSeen           time.Time
	LastSeen            time.Time
	SourceDeviceID      *int64
	DestinationDeviceID *int64
	PacketRefs          []int64
	MinPacketSize       *int
	MaxPacketSize       *int
}

// DNSQuery represents a DNS transaction extracted from packets.
type DNSQuery struct {
	ID                int64
	QueryingDeviceID  *int64
	AnsweringDeviceID *int64
	QueryName         string
	QueryType         string
	QueryResult       map[string]interface{}
	Timestamp         time.Time
}
