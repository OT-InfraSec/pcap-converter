package model

import "testing"

func TestIsValidIPAddressPlusPort(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    bool
	}{
		// Happy path tests
		{
			name:    "simple IPv4",
			address: "192.168.1.1",
			want:    true,
		},
		{
			name:    "IPv4 with port",
			address: "192.168.1.1:80",
			want:    true,
		},
		{
			name:    "simple IPv6",
			address: "2001:db8::1",
			want:    true,
		},
		{
			name:    "IPv6 with port",
			address: "[2001:db8::1]:80",
			want:    true,
		},
		{
			name:    "IPv4 with annotation",
			address: "192.168.1.1:80(http)",
			want:    false,
		},
		{
			name:    "IPv6 with annotation",
			address: "[2001:db8::1]:443(https)",
			want:    false,
		},

		// Bad path tests
		{
			name:    "empty address",
			address: "",
			want:    false,
		},
		{
			name:    "invalid IPv4",
			address: "300.168.1.1:80",
			want:    false,
		},
		{
			name:    "invalid IPv6",
			address: "[2001:zz8::1]:80",
			want:    false,
		},
		{
			name:    "malformed IPv6 brackets",
			address: "[2001:db8::1:80",
			want:    false,
		},
		{
			name:    "invalid port (too high)",
			address: "192.168.1.1:99999",
			want:    false,
		},

		// Exception tests
		{
			name:    "broadcast IPv4",
			address: "255.255.255.255",
			want:    true,
		},
		{
			name:    "loopback IPv4 with port",
			address: "127.0.0.1:22",
			want:    true,
		},
		{
			name:    "loopback IPv6",
			address: "::1",
			want:    true,
		},
		{
			name:    "IPv4-mapped IPv6 address",
			address: "::ffff:192.168.1.1",
			want:    true,
		},
		{
			name:    "IPv4 with named port in annotation",
			address: "192.168.1.1:22(ssh)",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidIPAddressPlusPort(tt.address)
			if got != tt.want {
				t.Errorf("isValidIPAddressPlusPort(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}
