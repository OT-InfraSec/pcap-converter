package model

import (
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
			name: "happy path - valid TCP flow",
			flow: Flow{
				Source:        "192.168.1.1",
				Destination:   "192.168.1.2",
				Protocol:      "TCP",
				Packets:       100,
				Bytes:         1500,
				FirstSeen:     now,
				LastSeen:      later,
				MinPacketSize: &minSize,
				MaxPacketSize: &maxSize,
			},
			wantErr: false,
		},
		{
			name: "bad path - invalid IP address for TCP",
			flow: Flow{
				Source:      "invalid-ip",
				Destination: "192.168.1.2",
				Protocol:    "TCP",
				Packets:     100,
				Bytes:       1500,
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true,
		},
		{
			name: "exception path - valid ARP flow with MAC addresses",
			flow: Flow{
				Source:      "00:11:22:33:44:55",
				Destination: "ff:ff:ff:ff:ff:ff",
				Protocol:    "ARP",
				Packets:     1,
				Bytes:       64,
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
		{
			name: "bad path - TCP flow with MAC addresses",
			flow: Flow{
				Source:      "00:11:22:33:44:55",
				Destination: "ff:ff:ff:ff:ff:ff",
				Protocol:    "TCP",
				Packets:     1,
				Bytes:       64,
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true,
		},
		{
			name: "happy path - valid DNS flow with hostname",
			flow: Flow{
				Source:      "192.168.1.1",
				Destination: "dns.example.com",
				Protocol:    "DNS",
				Packets:     1,
				Bytes:       64,
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: false,
		},
		{
			name: "bad path - ip addresses contain additional characters",
			flow: Flow{
				Source:      "fe80::bc63:ff16:c0cd:87d5:546(dhcpv6-client)",
				Destination: "10.60.143.255:1740(encore)",
				Protocol:    "UDP",
				Packets:     1,
				Bytes:       64,
				FirstSeen:   now,
				LastSeen:    later,
			},
			wantErr: true,
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
