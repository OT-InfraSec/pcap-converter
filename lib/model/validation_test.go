package model

import (
	"net"
	"testing"
	"time"
)

func TestDeviceValidation(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)

	tests := []struct {
		name    string
		device  Device
		wantErr bool
	}{
		{
			name: "happy path - valid device with MAC address",
			device: Device{
				Address:     "00:11:22:33:44:55",
				AddressType: "MAC",
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
		{
			name: "bad path - empty address",
			device: Device{
				Address:     "",
				AddressType: "MAC",
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true,
		},
		{
			name: "exception path - broadcast MAC address",
			device: Device{
				Address:     "ff:ff:ff:ff:ff:ff",
				AddressType: "MAC",
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.device.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Device.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFlowValidation(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)
	minSize := 64
	maxSize := 1500

	tests := []struct {
		name    string
		flow    Flow
		wantErr bool
	}{
		{
			name: "happy path - valid TCP flow with IP addresses",
			flow: Flow{
				SrcIP:         net.ParseIP("192.168.1.1"),
				DstIP:         net.ParseIP("192.168.1.2"),
				SrcPort:       1234,
				DstPort:       80,
				Protocol:      "TCP",
				PacketCount:   100,
				ByteCount:     int64(1500),
				FirstSeen:     now,
				LastSeen:      later,
				MinPacketSize: minSize,
				MaxPacketSize: maxSize,
			},
			wantErr: false,
		},
		{
			name: "happy path - valid TCP flow with IPv6 addresses",
			flow: Flow{
				SrcIP:       net.ParseIP("2001:db8::1"),
				DstIP:       net.ParseIP("2001:db8::2"),
				SrcPort:     1234,
				DstPort:     80,
				Protocol:    "TCP",
				PacketCount: 100,
				ByteCount:   int64(1500),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
		{
			name: "bad path - invalid IP address for TCP",
			flow: Flow{
				SrcIP:       net.ParseIP("invalid-ip"),
				DstIP:       net.ParseIP("192.168.1.2"),
				SrcPort:     0,
				DstPort:     80,
				Protocol:    "TCP",
				PacketCount: 100,
				ByteCount:   int64(1500),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true,
		},
		{
			name: "exception path - valid ARP flow with MAC addresses",
			flow: Flow{
				SrcIP:       net.ParseIP("192.168.1.10"),
				DstIP:       net.ParseIP("192.168.1.255"),
				Protocol:    "ARP",
				PacketCount: 1,
				ByteCount:   int64(64),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
		{
			name: "bad path - TCP flow with invalid src ip (simulate MAC)",
			flow: Flow{
				SrcIP:       nil,
				DstIP:       net.ParseIP("192.168.1.255"),
				Protocol:    "TCP",
				PacketCount: 1,
				ByteCount:   int64(64),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true,
		},
		{
			name: "happy path - valid DNS flow with hostname",
			flow: Flow{
				SrcIP:       net.ParseIP("192.168.1.1"),
				DstIP:       net.ParseIP("8.8.8.8"),
				SrcPort:     53,
				DstPort:     0,
				Protocol:    "DNS",
				PacketCount: 1,
				ByteCount:   int64(64),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
		{
			name: "bad path - ip addresses contain invalid characters",
			flow: Flow{
				SrcIP:       net.ParseIP("invalid-ip-address-format"),
				DstIP:       net.ParseIP("not@valid!ip"),
				Protocol:    "UDP",
				PacketCount: 1,
				ByteCount:   int64(64),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true,
		},
		{
			name: "bad path - ip addresses with annotations",
			flow: Flow{
				SrcIP:       net.ParseIP("fe80::bc63:ff16:c0cd:87d5:546(dhcpv6-client)"),
				DstIP:       net.ParseIP("10.60.143.255:1740(encore)"),
				Protocol:    "UDP",
				PacketCount: 1,
				ByteCount:   int64(64),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true, // Annotations are not allowed in IP addresses
		},
		{
			name: "happy path - special multicast addresses",
			flow: Flow{
				SrcIP:       net.ParseIP("192.168.1.1"),
				DstIP:       net.ParseIP("224.0.0.251"),
				SrcPort:     5353,
				DstPort:     5353,
				Protocol:    "UDP",
				PacketCount: 1,
				ByteCount:   int64(64),
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.flow.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Flow.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
