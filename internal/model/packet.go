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
	// Entferne Port-Teil, falls vorhanden (z.B. 192.168.1.1:80 -> 192.168.1.1)
	if strings.Contains(address, ":") {
		// IPv6-Adressen haben mehrere Doppelpunkte, prüfe daher ob (...)
		if strings.Count(address, ":") > 2 && strings.Contains(address, "]:") {
			// IPv6 mit Port: [2001:db8::1]:80
			parts := strings.Split(address, "]:")
			if len(parts) == 2 {
				ipv6 := strings.TrimPrefix(parts[0], "[")
				return net.ParseIP(ipv6) != nil
			}
		} else if strings.Count(address, ":") == 1 {
			// IPv4 mit Port: 192.168.1.1:80
			parts := strings.Split(address, ":")
			return net.ParseIP(parts[0]) != nil
		}
	}

	// Entferne zusätzliche Anmerkungen in Klammern
	if strings.Contains(address, "(") {
		return false
	}

	ip := net.ParseIP(address)
	return ip != nil
}

func IsValidMACAddress(address string) bool {
	return macAddressRegex.MatchString(address)
}

func isValidAddress(address, protocol string) bool {
	switch strings.ToUpper(protocol) {
	case "TCP", "UDP", "ICMP", "ICMPV6":
		return IsValidIPAddressPlusPort(address)
	case "ARP", "ETHERNET":
		return IsValidMACAddress(address)
	case "DNS":
		// DNS kann sowohl IP als auch Hostnamen haben
		return IsValidIPAddress(address) || strings.Contains(address, ".")
	case "IPV4", "IPV6", "IP":
		// Bei IPv4/IPv6-Adressen nur die IP-Adresse prüfen
		return IsValidIPAddress(address)
	default:
		// Bei unbekannten Protokollen: true zurückgeben
		return true
	}
}

func IsValidIPAddressPlusPort(address string) bool {
	// Für leere Adressen
	if address == "" {
		return false
	}

	// Fail if annotation in parentheses is present
	if idx := strings.Index(address, "("); idx != -1 {
		return false
	}

	// Prüfe auf IPv6 mit Port: [IPv6]:Port
	if strings.Contains(address, "[") && strings.Contains(address, "]:") {
		parts := strings.Split(address, "]:")
		if len(parts) == 2 {
			ipv6 := strings.TrimPrefix(parts[0], "[")
			port := parts[1]

			// Validiere IPv6-Adresse
			if net.ParseIP(ipv6) == nil {
				return false
			}

			// Validiere Port (optional)
			if port != "" {
				portNum, err := strconv.Atoi(port)
				return err == nil && portNum > 0 && portNum < 65536
			}
			return true
		}
		return false
	}

	// Prüfe auf IPv4 mit Port: IPv4:Port
	parts := strings.Split(address, ":")
	if len(parts) > 1 {
		// Mehr als ein Doppelpunkt deutet auf IPv6 ohne Klammern hin
		if len(parts) > 2 {
			// Könnte eine IPv6-Adresse ohne Klammern sein
			return net.ParseIP(address) != nil
		}

		// IPv4 mit Port
		ip := parts[0]
		port := parts[1]

		// Validiere IPv4-Adresse
		if net.ParseIP(ip) == nil {
			return false
		}

		// Validiere Port (optional)
		if port != "" {
			portNum, err := strconv.Atoi(port)
			return err == nil && portNum > 0 && portNum < 65536
		}
		return true
	}

	// Nur IP-Adresse ohne Port
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
