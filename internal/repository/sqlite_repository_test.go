package repository

import (
	"testing"
	"time"
	"net"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Create required devices first
	srcDevice := &model.Device{
		Address:           "192.168.1.1",
		AddressType:       "IPv4",
		FirstSeen:         ts,
		LastSeen:          ts,
		MACAddressSet:     model.NewMACAddressSet(),
		IsOnlyDestination: false,
	}
	err = repo.AddDevice(srcDevice)
	if err != nil {
		t.Fatalf("AddDevice failed: %v", err)
	}

	dstDevice := &model.Device{
		Address:           "192.168.1.2",
		AddressType:       "IPv4",
		FirstSeen:         ts,
		LastSeen:          ts,
		MACAddressSet:     model.NewMACAddressSet(),
		IsOnlyDestination: false,
	}
	err = repo.AddDevice(dstDevice)
	if err != nil {
		t.Fatalf("AddDevice failed: %v", err)
	}

	flow := &model.Flow{
		SrcIP:            net.ParseIP("192.168.1.1"),
		DstIP:            net.ParseIP("192.168.1.2"),
		SrcPort:          1234,
		DstPort:          80,
		Protocol:         "TCP",
		PacketCount:      1,
		ByteCount:        100,
		FirstSeen:        ts,
		LastSeen:         ts,
		PacketRefs:       []int64{1},
		SourcePorts:      model.NewSet(),
		DestinationPorts: model.NewSet(),
	}
	err = repo.AddFlow(flow)
	if err != nil {
		t.Fatalf("AddFlow failed: %v", err)
	}
}

func TestSQLiteRepository_BidirectionalFlowIntegration(t *testing.T) {
	repo, err := NewSQLiteRepository(":memory:")
	require.NoError(t, err)
	defer repo.Close()

	ts1 := time.Now()
	ts2 := ts1.Add(time.Second)

	// Create devices
	clientDevice := &model.Device{
		Address: "192.168.1.10", AddressType: "IPv4", FirstSeen: ts1, LastSeen: ts1,
		MACAddressSet: model.NewMACAddressSet(), IsOnlyDestination: false,
	}
	serverDevice := &model.Device{
		Address: "192.168.1.20", AddressType: "IPv4", FirstSeen: ts1, LastSeen: ts1,
		MACAddressSet: model.NewMACAddressSet(), IsOnlyDestination: false,
	}
	err = repo.AddDevice(clientDevice)
	require.NoError(t, err)
	err = repo.AddDevice(serverDevice)
	require.NoError(t, err)

	// Simulate HTTP request (client to server)
	requestFlow := &model.Flow{
		SrcIP: net.ParseIP("192.168.1.10"), DstIP: net.ParseIP("192.168.1.20"), SrcPort: 12345, DstPort: 80, Protocol: "HTTP",
		PacketCount: 1, ByteCount: 200, FirstSeen: ts1, LastSeen: ts1,
		PacketRefs: []int64{1}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	requestFlow.SourcePorts.Add("12345")
	requestFlow.DestinationPorts.Add("80")

	err = repo.UpsertFlow(requestFlow)
	require.NoError(t, err)

	// Simulate HTTP response (server to client)
	responseFlow := &model.Flow{
		SrcIP: net.ParseIP("192.168.1.20"), DstIP: net.ParseIP("192.168.1.10"), SrcPort: 80, DstPort: 12345, Protocol: "HTTP",
		PacketCount: 1, ByteCount: 1500, FirstSeen: ts2, LastSeen: ts2,
		PacketRefs: []int64{2}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	responseFlow.SourcePorts.Add("80")
	responseFlow.DestinationPorts.Add("12345")

	err = repo.UpsertFlow(responseFlow)
	require.NoError(t, err)

	// Verify single bidirectional flow was created
	flows, err := repo.GetFlows(nil)
	require.NoError(t, err)
	require.Len(t, flows, 1, "Should create exactly one bidirectional flow")

	flow := flows[0]

	// Verify canonical direction (client to server)
	assert.Equal(t, "192.168.1.10", flow.SrcIP.String())
	assert.Equal(t, 12345, flow.SrcPort)
	assert.Equal(t, "192.168.1.20", flow.DstIP.String())
	assert.Equal(t, 80, flow.DstPort)

	// Verify bidirectional statistics
	assert.Equal(t, 1, flow.PacketsClientToServer)
	assert.Equal(t, 1, flow.PacketsServerToClient)
	assert.Equal(t, int64(200), flow.BytesClientToServer)
	assert.Equal(t, int64(1500), flow.BytesServerToClient)

	// Verify totals
	assert.Equal(t, 2, flow.PacketCount)
	assert.Equal(t, int64(1700), flow.ByteCount)

	// Verify timestamps
	assert.True(t, flow.FirstSeen.Equal(ts1))
	assert.True(t, flow.LastSeen.Equal(ts2))

	// Verify packet references
	assert.Len(t, flow.PacketRefs, 2)
	assert.Contains(t, flow.PacketRefs, int64(1))
	assert.Contains(t, flow.PacketRefs, int64(2))
}

func TestSQLiteRepository_OPCUABidirectionalIntegration(t *testing.T) {
	repo, err := NewSQLiteRepository(":memory:")
	require.NoError(t, err)
	defer repo.Close()

	ts1 := time.Now()
	ts2 := ts1.Add(time.Second)

	// Create devices
	clientDevice := &model.Device{
		Address: "192.168.1.10", AddressType: "IPv4", FirstSeen: ts1, LastSeen: ts1,
		MACAddressSet: model.NewMACAddressSet(), IsOnlyDestination: false,
	}
	serverDevice := &model.Device{
		Address: "192.168.1.20", AddressType: "IPv4", FirstSeen: ts1, LastSeen: ts1,
		MACAddressSet: model.NewMACAddressSet(), IsOnlyDestination: false,
	}
	err = repo.AddDevice(clientDevice)
	require.NoError(t, err)
	err = repo.AddDevice(serverDevice)
	require.NoError(t, err)

	// Simulate OPC UA request (client to server)
	opcuaRequest := &model.Flow{
		SrcIP: net.ParseIP("192.168.1.10"), DstIP: net.ParseIP("192.168.1.20"), SrcPort: 49152, DstPort: 4840, Protocol: "OPC UA",
		PacketCount: 1, ByteCount: 100, FirstSeen: ts1, LastSeen: ts1,
		PacketRefs: []int64{1}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	opcuaRequest.SourcePorts.Add("49152")
	opcuaRequest.DestinationPorts.Add("4840")

	err = repo.UpsertFlow(opcuaRequest)
	require.NoError(t, err)

	// Simulate OPC UA response (server to client)
	opcuaResponse := &model.Flow{
		SrcIP: net.ParseIP("192.168.1.20"), DstIP: net.ParseIP("192.168.1.10"), SrcPort: 4840, DstPort: 49152, Protocol: "OPC UA",
		PacketCount: 1, ByteCount: 200, FirstSeen: ts2, LastSeen: ts2,
		PacketRefs: []int64{2}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	opcuaResponse.SourcePorts.Add("4840")
	opcuaResponse.DestinationPorts.Add("49152")

	err = repo.UpsertFlow(opcuaResponse)
	require.NoError(t, err)

	// Verify single bidirectional flow was created
	flows, err := repo.GetFlows(nil)
	require.NoError(t, err)
	require.Len(t, flows, 1, "Should create exactly one bidirectional OPC UA flow")

	flow := flows[0]

	// Verify canonical direction (client to server)
	assert.Equal(t, "192.168.1.10", flow.SrcIP.String())
	assert.Equal(t, 49152, flow.SrcPort)
	assert.Equal(t, "192.168.1.20", flow.DstIP.String())
	assert.Equal(t, 4840, flow.DstPort)

	// Verify bidirectional statistics
	assert.Equal(t, 1, flow.PacketsClientToServer)
	assert.Equal(t, 1, flow.PacketsServerToClient)
	assert.Equal(t, int64(100), flow.BytesClientToServer)
	assert.Equal(t, int64(200), flow.BytesServerToClient)

	// Verify protocol
	assert.Equal(t, "OPC UA", flow.Protocol)
}
