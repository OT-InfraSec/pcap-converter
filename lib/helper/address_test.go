package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAddressScope(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		addressType string
		expected    string
	}{
		// MAC address tests
		{
			name:        "MAC broadcast",
			address:     "ff:ff:ff:ff:ff:ff",
			addressType: "MAC",
			expected:    "broadcast",
		},
		{
			name:        "MAC multicast (odd first byte)",
			address:     "01:00:5e:00:00:01",
			addressType: "MAC",
			expected:    "multicast",
		},
		{
			name:        "MAC multicast (another odd first byte)",
			address:     "03:00:00:00:00:01",
			addressType: "MAC",
			expected:    "multicast",
		},
		{
			name:        "MAC unicast (even first byte)",
			address:     "00:11:22:33:44:55",
			addressType: "MAC",
			expected:    "unicast",
		},
		{
			name:        "MAC unicast (another even first byte)",
			address:     "a4:5e:60:c8:ab:cd",
			addressType: "MAC",
			expected:    "unicast",
		},
		{
			name:        "MAC malformed returns unicast",
			address:     "invalid",
			addressType: "MAC",
			expected:    "unicast",
		},

		// IPv4 tests
		{
			name:        "IPv4 broadcast",
			address:     "255.255.255.255",
			addressType: "IP",
			expected:    "broadcast",
		},
		{
			name:        "IPv4 multicast",
			address:     "224.0.0.1",
			addressType: "IP",
			expected:    "multicast",
		},
		{
			name:        "IPv4 multicast range",
			address:     "239.255.255.250",
			addressType: "IP",
			expected:    "multicast",
		},
		{
			name:        "IPv4 loopback",
			address:     "127.0.0.1",
			addressType: "IP",
			expected:    "unicast",
		},
		{
			name:        "IPv4 private",
			address:     "192.168.1.1",
			addressType: "IP",
			expected:    "unicast",
		},
		{
			name:        "IPv4 private 10.x",
			address:     "10.0.0.1",
			addressType: "IP",
			expected:    "unicast",
		},
		{
			name:        "IPv4 private 172.16.x",
			address:     "172.16.0.1",
			addressType: "IP",
			expected:    "unicast",
		},
		{
			name:        "IPv4 public",
			address:     "8.8.8.8",
			addressType: "IP",
			expected:    "unicast",
		},

		// IPv6 tests
		{
			name:        "IPv6 loopback",
			address:     "::1",
			addressType: "IP",
			expected:    "unicast",
		},
		{
			name:        "IPv6 multicast",
			address:     "ff02::1",
			addressType: "IP",
			expected:    "multicast",
		},
		{
			name:        "IPv6 link-local unicast",
			address:     "fe80::1",
			addressType: "IP",
			expected:    "unicast",
		},
		{
			name:        "IPv6 global unicast",
			address:     "2001:db8::1",
			addressType: "IP",
			expected:    "unicast",
		},
		{
			name:        "IPv6 interface-local multicast",
			address:     "ff01::1",
			addressType: "IP",
			expected:    "multicast",
		},

		// Error cases
		{
			name:        "invalid IP address",
			address:     "invalid",
			addressType: "IP",
			expected:    "",
		},
		{
			name:        "empty address",
			address:     "",
			addressType: "IP",
			expected:    "",
		},
		{
			name:        "unknown address type",
			address:     "192.168.1.1",
			addressType: "UNKNOWN",
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetAddressScope(tt.address, tt.addressType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name         string
		address      string
		expectedIP   string
		expectedPort uint16
		expectError  bool
	}{
		// IPv4 tests
		{
			name:         "IPv4 with port",
			address:      "192.168.1.1:8080",
			expectedIP:   "192.168.1.1",
			expectedPort: 8080,
			expectError:  false,
		},
		{
			name:         "IPv4 without port",
			address:      "192.168.1.1",
			expectedIP:   "192.168.1.1",
			expectedPort: 0,
			expectError:  false,
		},
		{
			name:         "IPv4 with port 80",
			address:      "10.0.0.1:80",
			expectedIP:   "10.0.0.1",
			expectedPort: 80,
			expectError:  false,
		},
		{
			name:         "IPv4 with high port",
			address:      "8.8.8.8:65535",
			expectedIP:   "8.8.8.8",
			expectedPort: 65535,
			expectError:  false,
		},

		// IPv6 tests
		{
			name:         "IPv6 with brackets and port",
			address:      "[::1]:8080",
			expectedIP:   "::1",
			expectedPort: 8080,
			expectError:  false,
		},
		{
			name:         "IPv6 with brackets and port 443",
			address:      "[2001:db8::1]:443",
			expectedIP:   "2001:db8::1",
			expectedPort: 443,
			expectError:  false,
		},
		{
			name:         "IPv6 without brackets",
			address:      "2001:db8::1",
			expectedIP:   "2001:db8::1",
			expectedPort: 0,
			expectError:  false,
		},
		{
			name:         "IPv6 loopback",
			address:      "::1",
			expectedIP:   "::1",
			expectedPort: 0,
			expectError:  false,
		},
		{
			name:         "IPv6 with invalid port in brackets",
			address:      "[::1]:invalid",
			expectedIP:   "::1",
			expectedPort: 0,
			expectError:  false,
		},

		// Edge cases with annotations
		{
			name:         "IPv4 with annotation",
			address:      "192.168.1.1 (server)",
			expectedIP:   "192.168.1.1",
			expectedPort: 0,
			expectError:  false,
		},
		{
			name:         "IPv4 with annotation no space",
			address:      "10.0.0.1(gateway)",
			expectedIP:   "10.0.0.1",
			expectedPort: 0,
			expectError:  false,
		},

		// Error cases
		{
			name:         "empty address",
			address:      "",
			expectedIP:   "",
			expectedPort: 0,
			expectError:  true,
		},
		{
			name:         "invalid IP with port",
			address:      "invalid:8080",
			expectedIP:   "",
			expectedPort: 0,
			expectError:  true,
		},
		{
			name:         "invalid IPv6 in brackets",
			address:      "[invalid]:8080",
			expectedIP:   "",
			expectedPort: 0,
			expectError:  true,
		},
		{
			name:         "completely invalid",
			address:      "not-an-address",
			expectedIP:   "",
			expectedPort: 0,
			expectError:  true,
		},
		{
			name:         "malformed brackets",
			address:      "[::1",
			expectedIP:   "",
			expectedPort: 0,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, err := ParseAddress(tt.address)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedIP, ip)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

func TestParseAddress_EdgeCases(t *testing.T) {
	t.Run("IPv4 with zero port", func(t *testing.T) {
		ip, port, err := ParseAddress("192.168.1.1:0")
		assert.NoError(t, err)
		assert.Equal(t, "192.168.1.1", ip)
		assert.Equal(t, uint16(0), port)
	})

	t.Run("IPv6 with zero port", func(t *testing.T) {
		ip, port, err := ParseAddress("[::1]:0")
		assert.NoError(t, err)
		assert.Equal(t, "::1", ip)
		assert.Equal(t, uint16(0), port)
	})

	t.Run("IPv6 full form", func(t *testing.T) {
		ip, port, err := ParseAddress("[2001:0db8:0000:0000:0000:0000:0000:0001]:8080")
		assert.NoError(t, err)
		assert.Equal(t, "2001:0db8:0000:0000:0000:0000:0000:0001", ip)
		assert.Equal(t, uint16(8080), port)
	})

	t.Run("IPv4-mapped IPv6", func(t *testing.T) {
		ip, port, err := ParseAddress("::ffff:192.168.1.1")
		assert.NoError(t, err)
		assert.Equal(t, "::ffff:192.168.1.1", ip)
		assert.Equal(t, uint16(0), port)
	})

	t.Run("link-local IPv6", func(t *testing.T) {
		ip, port, err := ParseAddress("fe80::1")
		assert.NoError(t, err)
		assert.Equal(t, "fe80::1", ip)
		assert.Equal(t, uint16(0), port)
	})
}

func TestGetAddressScope_EdgeCases(t *testing.T) {
	t.Run("MAC with uppercase - case sensitive check", func(t *testing.T) {
		// The function uses exact string match for broadcast, so uppercase is treated as unicast
		result := GetAddressScope("FF:FF:FF:FF:FF:FF", "MAC")
		assert.Equal(t, "unicast", result)
	})

	t.Run("MAC with lowercase", func(t *testing.T) {
		result := GetAddressScope("ff:ff:ff:ff:ff:ff", "MAC")
		assert.Equal(t, "broadcast", result)
	})

	t.Run("MAC multicast boundary", func(t *testing.T) {
		// 01 is the first multicast MAC
		result := GetAddressScope("01:00:00:00:00:00", "MAC")
		assert.Equal(t, "multicast", result)
	})

	t.Run("IPv4 all zeros", func(t *testing.T) {
		result := GetAddressScope("0.0.0.0", "IP")
		assert.Equal(t, "unicast", result)
	})

	t.Run("IPv6 all zeros", func(t *testing.T) {
		result := GetAddressScope("::", "IP")
		assert.Equal(t, "unicast", result)
	})

	t.Run("IPv6 multicast with different scopes", func(t *testing.T) {
		// Test different IPv6 multicast scope values
		tests := []string{
			"ff01::1", // Interface-local
			"ff02::1", // Link-local
			"ff05::1", // Site-local
			"ff08::1", // Organization-local
			"ff0e::1", // Global
		}
		for _, addr := range tests {
			result := GetAddressScope(addr, "IP")
			assert.Equal(t, "multicast", result, "Address %s should be multicast", addr)
		}
	})
}
