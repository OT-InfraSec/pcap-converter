package helper

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// GetAddressScope determines if an address is unicast, multicast, or broadcast
func GetAddressScope(address string, addressType string) string {
	if addressType == "MAC" {
		if address == "ff:ff:ff:ff:ff:ff" {
			return "broadcast"
		}
		// Check if MAC is multicast (first byte's least significant bit is 1)
		parts := strings.Split(address, ":")
		if len(parts) > 0 {
			firstByte, err := strconv.ParseInt(parts[0], 16, 8)
			if err == nil && firstByte&0x01 == 1 {
				return "multicast"
			}
		}
		return "unicast"
	} else if addressType == "IP" {
		ip := net.ParseIP(address)
		if ip == nil {
			return ""
		}
		if ip.IsMulticast() {
			return "multicast"
		}
		if ip.IsLoopback() {
			return "unicast"
		}
		if ip.IsLinkLocalMulticast() {
			return "multicast"
		}
		if ip.IsInterfaceLocalMulticast() {
			return "multicast"
		}
		if ip.IsGlobalUnicast() {
			return "unicast"
		}
		if ip.IsPrivate() {
			return "unicast"
		}
		if ip.Equal(net.IPv4bcast) {
			return "broadcast"
		}
		return "unicast"
	}
	return ""
}

func GetAddressScopeCombined(address string, macAddressSet *model.MACAddressSet) string {
	if macAddressSet.Contains("ff:ff:ff:ff:ff:ff") {
		return "broadcast"
	}
	return GetAddressScope(address, "IP")
}

// ParseAddress extracts IP and port from an address string. If port is missing, returns port 0.
// Supports IPv4, IPv6 ([::1]:80) and plain IP without port.
func ParseAddress(addr string) (string, uint16, error) {
	if addr == "" {
		return "", 0, errors.New("empty address")
	}

	// IPv6 with brackets [::1]:80
	if strings.HasPrefix(addr, "[") {
		// expect format [ipv6]:port
		parts := strings.Split(addr, "]:")
		if len(parts) == 2 {
			ip := strings.TrimPrefix(parts[0], "[")
			if net.ParseIP(ip) == nil {
				return "", 0, errors.New("invalid IPv6 address")
			}
			p, err := strconv.Atoi(parts[1])
			if err != nil {
				return ip, 0, nil // treat as missing port
			}
			return ip, uint16(p), nil
		}
	}

	// IPv4 or IPv6 without brackets or with single colon (ip:port)
	if strings.Count(addr, ":") == 1 {
		parts := strings.Split(addr, ":")
		ip := parts[0]
		portStr := parts[1]
		if net.ParseIP(ip) == nil {
			return "", 0, errors.New("invalid IP address")
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return ip, 0, nil
		}
		return ip, uint16(p), nil
	}

	// No port present or IPv6 without brackets
	if net.ParseIP(addr) != nil {
		return addr, 0, nil
	}

	// Try to strip a trailing annotation like (something)
	if idx := strings.Index(addr, "("); idx != -1 {
		candidate := strings.TrimSpace(addr[:idx])
		if net.ParseIP(candidate) != nil {
			return candidate, 0, nil
		}
	}

	return "", 0, errors.New("could not parse address")
}
