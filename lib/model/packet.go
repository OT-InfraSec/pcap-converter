package model

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var macAddressRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)

func IsValidIPAddress(address string) bool {
	// Remove additional annotations in parentheses
	if strings.Contains(address, "(") {
		return false
	}

	address, err := ExtractIPAddress(address)
	if err != nil || address == "" {
		return false
	}

	ip := net.ParseIP(address)
	return ip != nil
}

func ExtractIPAddress(address string) (string, error) {
	// Remove port part if present (e.g., 192.168.1.1:80 -> 192.168.1.1)
	if strings.Contains(address, ":") {
		// IPv6 addresses have multiple colons, check if (...)
		if strings.Count(address, ":") > 2 && strings.Contains(address, "]:") {
			// IPv6 with port: [2001:db8::1]:80
			parts := strings.Split(address, "]:")
			if len(parts) == 2 {
				ipv6 := strings.TrimPrefix(parts[0], "[")
				address = ipv6
			}
		} else if strings.Count(address, ":") == 1 {
			// IPv4 with port: 192.168.1.1:80
			parts := strings.Split(address, ":")
			address = parts[0]
		}
	}

	if net.ParseIP(address) != nil {
		return address, nil
	}
	return "", errors.New("invalid address format, no valid IP found")
}

func IsValidMACAddress(address string) bool {
	return macAddressRegex.MatchString(address)
}

func isValidAddress(address, protocol string) bool {
	switch strings.ToUpper(protocol) {
	case "TCP", "UDP", "ICMP", "ICMPV6":
		return IsValidIPAddressPlusPort(address)
	case "ETHERNET":
		return IsValidMACAddress(address)
	case "DNS":
		// DNS can have both IP and hostname
		return IsValidIPAddress(address) || strings.Contains(address, ".")
	case "IPV4", "IPV6", "IP":
		// For IPv4/IPv6 addresses, only check the IP address
		return IsValidIPAddress(address)
	case "ARP":
		return IsValidMACAddress(address) || IsValidIPAddress(address)
	default:
		// For unknown protocols: return true
		return true
	}
}

func IsValidIPAddressPlusPort(address string) bool {
	// For empty addresses
	if address == "" {
		return false
	}

	// Fail if annotation in parentheses is present
	if idx := strings.Index(address, "("); idx != -1 {
		return false
	}

	// Check for IPv6 with port: [IPv6]:Port
	if strings.Contains(address, "[") && strings.Contains(address, "]:") {
		parts := strings.Split(address, "]:")
		if len(parts) == 2 {
			ipv6 := strings.TrimPrefix(parts[0], "[")
			port := parts[1]

			// Validate IPv6 address
			if net.ParseIP(ipv6) == nil {
				return false
			}

			// Validate port (optional)
			if port != "" {
				portNum, err := strconv.Atoi(port)
				return err == nil && portNum > 0 && portNum < 65536
			}
			return true
		}
		return false
	}

	// Check for IPv4 with port: IPv4:Port
	parts := strings.Split(address, ":")
	if len(parts) > 1 {
		// More than one colon indicates IPv6 without brackets
		if len(parts) > 2 {
			// Could be an IPv6 address without brackets
			return net.ParseIP(address) != nil
		}

		// IPv4 with port
		ip := parts[0]
		port := parts[1]

		// Validate IPv4 address
		if net.ParseIP(ip) == nil {
			return false
		}

		// Validate port (optional)
		if port != "" {
			portNum, err := strconv.Atoi(port)
			return err == nil && portNum > 0 && portNum < 65536
		}
		return true
	}

	// Only IP address without port
	return net.ParseIP(address) != nil
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
	ID                int64
	Address           string
	AddressType       string
	FirstSeen         time.Time
	LastSeen          time.Time
	AddressSubType    string
	AddressScope      string // IPv4 or IPv6
	MACAddressSet     *MACAddressSet
	AdditionalData    string // JSON string for additional data
	IsOnlyDestination bool
}

// Service represents a network service.
type Service struct {
	ID        int64
	IP        string
	Port      int
	Protocol  string
	FirstSeen time.Time
	LastSeen  time.Time
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
	SourceDeviceID      int64
	DestinationDeviceID int64
	PacketRefs          []int64
	MinPacketSize       int
	MaxPacketSize       int
	SourcePorts         *Set
	DestinationPorts    *Set
}

// DeviceRelation represents a relationship between two devices.
type DeviceRelation struct {
	ID        int64
	DeviceID1 int64
	DeviceID2 int64
	Comment   string
}

// DNSQuery represents a DNS transaction extracted from packets.
type DNSQuery struct {
	ID                int64
	QueryingDeviceID  int64
	AnsweringDeviceID int64
	QueryName         string
	QueryType         string
	QueryResult       map[string]interface{}
	Timestamp         time.Time
}

type SSDPQuery struct {
	ID               int64
	QueryingDeviceID int64
	QueryType        string
	ST               string
	UserAgent        string
	Timestamp        time.Time
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

func (s *Service) Validate() error {
	if s.IP == "" {
		return errors.New("IP must not be empty")
	}
	if !IsValidIPAddress(s.IP) {
		return errors.New("invalid IP address format")
	}
	if s.Port < 0 || s.Port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	if s.Protocol == "" {
		return errors.New("protocol must not be empty")
	}
	if s.FirstSeen.IsZero() {
		return errors.New("first seen time must not be zero")
	}
	if s.LastSeen.IsZero() {
		return errors.New("last seen time must not be zero")
	}
	if s.LastSeen.Before(s.FirstSeen) {
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
	if f.MinPacketSize < 0 {
		return errors.New("minimum packet size must not be negative")
	}
	if f.MaxPacketSize < 0 {
		return errors.New("maximum packet size must not be negative")
	}
	if f.MinPacketSize > f.MaxPacketSize {
		return errors.New("minimum packet size must not be greater than maximum packet size")
	}
	return nil
}

func (dr *DeviceRelation) Validate() error {
	if dr.DeviceID1 == 0 {
		return errors.New("device ID 1 must not be zero")
	}
	if dr.DeviceID2 == 0 {
		return errors.New("device ID 2 must not be zero")
	}
	if dr.DeviceID1 == dr.DeviceID2 {
		return errors.New("device IDs must be different")
	}
	return nil
}

func (dq *DNSQuery) Validate() error {
	if dq.QueryingDeviceID == 0 {
		return errors.New("querying device ID must not be zero")
	}
	if dq.QueryName == "" {
		return errors.New("query name must not be empty")
	}
	if dq.QueryType == "" {
		return errors.New("query type must not be empty")
	}
	if dq.Timestamp.IsZero() {
		return errors.New("timestamp must not be zero")
	}
	return nil
}

func (ssdp *SSDPQuery) Validate() error {
	if ssdp.QueryingDeviceID == 0 {
		return errors.New("querying device ID must not be zero")
	}
	if ssdp.QueryType == "" {
		return errors.New("query type must not be empty")
	}
	if ssdp.ST == "" {
		return errors.New("ST (search target) must not be empty")
	}
	if ssdp.UserAgent == "" {
		return errors.New("user agent must not be empty")
	}
	return nil
}
