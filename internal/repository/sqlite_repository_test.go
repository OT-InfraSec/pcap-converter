package repository

import (
	"pcap-importer-golang/internal/model"
	"testing"
	"time"
)

func TestSQLiteRepository_AddPacketAndAllPackets(t *testing.T) {
	repo, err := NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()

	ts := time.Now()
	pkt := &model.Packet{
		Timestamp: ts,
		Length:    100,
		Layers:    map[string]interface{}{"eth": map[string]interface{}{"src": "00:11:22:33:44:55"}},
		Protocols: []string{"eth"},
	}
	err = repo.AddPacket(pkt)
	if err != nil {
		t.Fatalf("AddPacket failed: %v", err)
	}

	packets, err := repo.AllPackets()
	if err != nil {
		t.Fatalf("AllPackets failed: %v", err)
	}
	if len(packets) != 1 {
		t.Errorf("expected 1 packet, got %d", len(packets))
	}
}

func TestSQLiteRepository_AddDevice(t *testing.T) {
	repo, err := NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()
	ts := time.Now()
	dev := &model.Device{
		Address:        "192.168.1.1",
		AddressType:    "IP",
		FirstSeen:      ts,
		LastSeen:       ts,
		AddressSubType: "unicast",
		AddressScope:   "local",
	}
	err = repo.AddDevice(dev)
	if err != nil {
		t.Fatalf("AddDevice failed: %v", err)
	}
}

func TestSQLiteRepository_AddFlow(t *testing.T) {
	repo, err := NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()
	ts := time.Now()
	flow := &model.Flow{
		Source:      "192.168.1.1:1234",
		Destination: "192.168.1.2:80",
		Protocol:    "TCP",
		Packets:     1,
		Bytes:       100,
		FirstSeen:   ts,
		LastSeen:    ts,
		PacketRefs:  []int64{1},
	}
	err = repo.AddFlow(flow)
	if err != nil {
		t.Fatalf("AddFlow failed: %v", err)
	}
}
