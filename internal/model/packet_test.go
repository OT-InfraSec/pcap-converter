package model

import (
	"testing"
	"time"
)

func TestPacketStruct(t *testing.T) {
	ts := time.Now()
	p := &Packet{
		ID:        1,
		Timestamp: ts,
		Length:    128,
		Layers:    map[string]interface{}{"eth": map[string]interface{}{"src": "00:11:22:33:44:55"}},
		Protocols: []string{"eth", "ip"},
	}
	if p.ID != 1 || p.Length != 128 || p.Protocols[0] != "eth" {
		t.Errorf("Packet struct fields not set correctly")
	}
}

func TestDeviceStruct(t *testing.T) {
	ts := time.Now()
	d := &Device{
		ID:             2,
		Address:        "192.168.1.1",
		AddressType:    "IPv4",
		FirstSeen:      ts,
		LastSeen:       ts,
		AddressSubType: "unicast",
		AddressScope:   "local",
	}
	if d.ID != 2 || d.Address != "192.168.1.1" || d.AddressType != "IPv4" {
		t.Errorf("Device struct fields not set correctly")
	}
}

func TestFlowStruct(t *testing.T) {
	ts := time.Now()
	id := int64(3)
	minSize := 60
	f := &Flow{
		ID:                  3,
		Source:              "192.168.1.1",
		Destination:         "192.168.1.2",
		Protocol:            "TCP",
		Packets:             10,
		Bytes:               1000,
		FirstSeen:           ts,
		LastSeen:            ts,
		SourceDeviceID:      &id,
		DestinationDeviceID: &id,
		PacketRefs:          []int64{1, 2, 3},
		MinPacketSize:       &minSize,
		MaxPacketSize:       &minSize,
	}
	if f.ID != 3 || f.Protocol != "TCP" || *f.SourceDeviceID != 3 {
		t.Errorf("Flow struct fields not set correctly")
	}
}

func TestDNSQueryStruct(t *testing.T) {
	ts := time.Now()
	id := int64(4)
	q := &DNSQuery{
		ID:                4,
		QueryingDeviceID:  id,
		AnsweringDeviceID: id,
		QueryName:         "example.com",
		QueryType:         "A",
		QueryResult:       map[string]interface{}{"a": "1.2.3.4"},
		Timestamp:         ts,
	}
	if q.ID != 4 || q.QueryName != "example.com" || q.QueryingDeviceID != 4 {
		t.Errorf("DNSQuery struct fields not set correctly")
	}
}
