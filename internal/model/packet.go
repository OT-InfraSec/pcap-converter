package model

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
)

var macAddressRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)

func isValidIPAddress(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil
}

func isValidMACAddress(address string) bool {
	return macAddressRegex.MatchString(address)
}

func isValidAddress(address, protocol string) bool {
	switch strings.ToUpper(protocol) {
	case "TCP", "UDP", "ICMP", "ICMPV6":
		return isValidIPAddress(address)
	case "ARP", "ETHERNET":
		return isValidMACAddress(address)
	case "DNS":
		// DNS kann sowohl IP als auch Hostnamen haben
		return isValidIPAddress(address) || strings.Contains(address, ".")
	default:
		// Bei unbekannten Protokollen: true zurückgeben
		return true
	}
}

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

func (d *Device) Validate() error {
	if d.Address == "" {
		return errors.New("address must not be empty")
	}
	if d.AddressType == "" {
		return errors.New("address type must not be empty")
	}
	if d.FirstSeen.IsZero() {
		return errors.New("first seen time must not be zero")
	}
	if d.LastSeen.IsZero() {
		return errors.New("last seen time must not be zero")
	}
	if d.LastSeen.Before(d.FirstSeen) {
		return errors.New("last seen time must not be before first seen time")
	}
	return nil
}

func (f *Flow) Validate() error {
	if f.Source == "" {
		return errors.New("source must not be empty")
	}
	if f.Destination == "" {
		return errors.New("destination must not be empty")
	}
	if f.Protocol == "" {
		return errors.New("protocol must not be empty")
	}
	if !isValidAddress(f.Source, f.Protocol) {
		return errors.New("invalid source address format for protocol " + f.Protocol)
	}
	if !isValidAddress(f.Destination, f.Protocol) {
		return errors.New("invalid destination address format for protocol " + f.Protocol)
	}
	if f.FirstSeen.IsZero() {
		return errors.New("first seen time must not be zero")
	}
	if f.LastSeen.IsZero() {
		return errors.New("last seen time must not be zero")
	}
	if f.LastSeen.Before(f.FirstSeen) {
		return errors.New("last seen time must not be before first seen time")
	}
	if f.Packets < 0 {
		return errors.New("packets count must not be negative")
	}
	if f.Bytes < 0 {
		return errors.New("bytes count must not be negative")
	}
	if f.MinPacketSize != nil && *f.MinPacketSize < 0 {
		return errors.New("minimum packet size must not be negative")
	}
	if f.MaxPacketSize != nil && *f.MaxPacketSize < 0 {
		return errors.New("maximum packet size must not be negative")
	}
	if f.MinPacketSize != nil && f.MaxPacketSize != nil && *f.MinPacketSize > *f.MaxPacketSize {
		return errors.New("minimum packet size must not be greater than maximum packet size")
	}
	return nil
}
