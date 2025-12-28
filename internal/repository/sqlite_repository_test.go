package repository

import (
	"net"
	"testing"
	"time"

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

	packets, err := repo.AllPackets("")
	if err != nil {
		t.Fatalf("AllPackets failed: %v", err)
	}
	if len(packets) != 1 {
		t.Errorf("expected 1 packet, got %d", len(packets))
	}
}

func TestSQLiteRepository_PacketFieldsStored(t *testing.T) {
	repo, err := NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()

	ts := time.Now()
	pkt := &model.Packet{
		Timestamp:   ts,
		Length:      100,
		Flags:       "SYN,ACK",
		PayloadHash: "deadbeef",
		TTL:         64,
		CaptureFile: "test.pcap",
		Layers:      map[string]interface{}{"eth": map[string]interface{}{"src": "00:11:22:33:44:55"}},
		Protocols:   []string{"eth"},
	}
	err = repo.AddPacket(pkt)
	if err != nil {
		t.Fatalf("AddPacket failed: %v", err)
	}

	packets, err := repo.AllPackets("")
	if err != nil {
		t.Fatalf("AllPackets failed: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	p := packets[0]
	if p.Flags != "SYN,ACK" || p.PayloadHash != "deadbeef" || p.TTL != 64 || p.CaptureFile != "test.pcap" {
		t.Errorf("packet fields not stored/retrieved correctly: %+v", p)
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
		PacketCountOut:   1,
		ByteCountOut:     100,
		PacketCountIn:    0,
		ByteCountIn:      0,
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
	defer func(repo *SQLiteRepository) {
		err := repo.Close()
		if err != nil {
			t.Fatalf("failed to close repo: %v", err)
		}
	}(repo)

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
		PacketCountOut: 1, ByteCountOut: 200, PacketCountIn: 0, ByteCountIn: 0, FirstSeen: ts1, LastSeen: ts1,
		PacketRefs: []int64{1}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	requestFlow.SourcePorts.Add("12345")
	requestFlow.DestinationPorts.Add("80")

	err = repo.UpsertFlow(requestFlow)
	require.NoError(t, err)

	// Simulate HTTP response (server to client)
	responseFlow := &model.Flow{
		SrcIP: net.ParseIP("192.168.1.20"), DstIP: net.ParseIP("192.168.1.10"), SrcPort: 80, DstPort: 12345, Protocol: "HTTP",
		PacketCountOut: 1, ByteCountOut: 1500, PacketCountIn: 0, ByteCountIn: 0, FirstSeen: ts2, LastSeen: ts2,
		PacketRefs: []int64{2}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	responseFlow.SourcePorts.Add("80")
	responseFlow.DestinationPorts.Add("12345")

	err = repo.UpsertFlow(responseFlow)
	require.NoError(t, err)

	// Verify single bidirectional flow was created
	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	require.Len(t, flows, 1, "Should create exactly one bidirectional flow")

	flow := flows[0]

	// Verify canonical direction (client to server)
	assert.Equal(t, "192.168.1.10", flow.SrcIP.String())
	assert.Equal(t, 12345, flow.SrcPort)
	assert.Equal(t, "192.168.1.20", flow.DstIP.String())
	assert.Equal(t, 80, flow.DstPort)

	// Verify directional totals
	assert.Equal(t, 1, flow.PacketCountOut)
	assert.Equal(t, int64(200), flow.ByteCountOut)
	assert.Equal(t, 1, flow.PacketCountIn)
	assert.Equal(t, int64(1500), flow.ByteCountIn)

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
		PacketCountOut: 1, ByteCountOut: 100, PacketCountIn: 0, ByteCountIn: 0, FirstSeen: ts1, LastSeen: ts1,
		PacketRefs: []int64{1}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	opcuaRequest.SourcePorts.Add("49152")
	opcuaRequest.DestinationPorts.Add("4840")

	err = repo.UpsertFlow(opcuaRequest)
	require.NoError(t, err)

	// Simulate OPC UA response (server to client)
	opcuaResponse := &model.Flow{
		SrcIP: net.ParseIP("192.168.1.20"), DstIP: net.ParseIP("192.168.1.10"), SrcPort: 4840, DstPort: 49152, Protocol: "OPC UA",
		PacketCountOut: 1, ByteCountOut: 200, PacketCountIn: 0, ByteCountIn: 0, FirstSeen: ts2, LastSeen: ts2,
		PacketRefs: []int64{2}, SourcePorts: model.NewSet(), DestinationPorts: model.NewSet(),
	}
	opcuaResponse.SourcePorts.Add("4840")
	opcuaResponse.DestinationPorts.Add("49152")

	err = repo.UpsertFlow(opcuaResponse)
	require.NoError(t, err)

	// Verify single bidirectional flow was created
	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	require.Len(t, flows, 1, "Should create exactly one bidirectional OPC UA flow")

	flow := flows[0]

	// Verify canonical direction (client to server)
	assert.Equal(t, "192.168.1.10", flow.SrcIP.String())
	assert.Equal(t, 49152, flow.SrcPort)
	assert.Equal(t, "192.168.1.20", flow.DstIP.String())
	assert.Equal(t, 4840, flow.DstPort)

	// Verify protocol
	assert.Equal(t, "OPC UA", flow.Protocol)
}

func TestSQLiteRepository_LinkPacketsToFlows(t *testing.T) {
	repo, err := NewSQLiteRepository(":memory:")
	require.NoError(t, err)
	defer repo.Close()

	tenantID := "test-tenant"

	// Create test devices
	device1 := &model.Device{
		TenantID:       tenantID,
		Address:        "192.168.1.10",
		AddressType:    "IP",
		AddressSubType: "IPv4",
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
		MACAddressSet:  model.NewMACAddressSet(),
	}
	device2 := &model.Device{
		TenantID:       tenantID,
		Address:        "192.168.1.20",
		AddressType:    "IP",
		AddressSubType: "IPv4",
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
		MACAddressSet:  model.NewMACAddressSet(),
	}
	require.NoError(t, repo.UpsertDevice(device1))
	require.NoError(t, repo.UpsertDevice(device2))

	// Create flow (will get database ID assigned)
	flow := &model.Flow{
		TenantID:         tenantID,
		SrcIP:            net.ParseIP("192.168.1.10"),
		DstIP:            net.ParseIP("192.168.1.20"),
		SrcPort:          12345,
		DstPort:          80,
		Protocol:         "tcp",
		PacketCountOut:   1,
		ByteCountOut:     100,
		PacketCountIn:    0,
		ByteCountIn:      0,
		FirstSeen:        time.Now(),
		LastSeen:         time.Now(),
		PacketRefs:       []int64{},
		SourcePorts:      model.NewSet(),
		DestinationPorts: model.NewSet(),
	}
	flow.SourcePorts.Add("12345")
	flow.DestinationPorts.Add("80")
	require.NoError(t, repo.AddFlow(flow))
	require.NotZero(t, flow.ID, "Flow should have database ID assigned")

	// Create packets without flow_id (simulating the bug)
	packet1 := &model.Packet{
		TenantID:  tenantID,
		FlowID:    0, // Not linked yet
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.10"),
		DstIP:     net.ParseIP("192.168.1.20"),
		SrcPort:   12345,
		DstPort:   80,
		Protocol:  "tcp",
		Length:    100,
		Layers:    map[string]interface{}{},
		Protocols: []string{"tcp"},
	}
	packet2 := &model.Packet{
		TenantID:  tenantID,
		FlowID:    0, // Not linked yet (reverse direction)
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.20"),
		DstIP:     net.ParseIP("192.168.1.10"),
		SrcPort:   80,
		DstPort:   12345,
		Protocol:  "tcp",
		Length:    200,
		Layers:    map[string]interface{}{},
		Protocols: []string{"tcp"},
	}
	// Packet from different tenant - should not be linked
	packet3 := &model.Packet{
		TenantID:  "other-tenant",
		FlowID:    0,
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.10"),
		DstIP:     net.ParseIP("192.168.1.20"),
		SrcPort:   12345,
		DstPort:   80,
		Protocol:  "tcp",
		Length:    150,
		Layers:    map[string]interface{}{},
		Protocols: []string{"tcp"},
	}

	require.NoError(t, repo.UpsertPacket(packet1))
	require.NoError(t, repo.UpsertPacket(packet2))
	require.NoError(t, repo.UpsertPacket(packet3))

	// Verify packets don't have flow_id initially
	packets, err := repo.AllPackets(tenantID)
	require.NoError(t, err)
	require.Len(t, packets, 2)
	assert.Zero(t, packets[0].FlowID, "Packet should not have flow_id before linking")
	assert.Zero(t, packets[1].FlowID, "Packet should not have flow_id before linking")

	// Debug: Check flow details
	flows, err := repo.GetFlows(tenantID, nil)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	t.Logf("Flow: ID=%d, Src=%s:%d, Dst=%s:%d, Proto=%s",
		flows[0].ID, flows[0].SrcIP, flows[0].SrcPort, flows[0].DstIP, flows[0].DstPort, flows[0].Protocol)
	for i, pkt := range packets {
		t.Logf("Packet %d: Src=%s:%d, Dst=%s:%d, Proto=%s, FlowID=%d",
			i, pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Protocol, pkt.FlowID)
	}

	// Link packets to flows
	linkedCount, err := repo.LinkPacketsToFlows(tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), linkedCount, "Should link 2 packets (forward and reverse)")

	// Verify packets now have flow_id
	packets, err = repo.AllPackets(tenantID)
	require.NoError(t, err)
	require.Len(t, packets, 2)

	for _, pkt := range packets {
		assert.Equal(t, flow.ID, pkt.FlowID, "Packet should be linked to flow")
	}

	// Verify packet from other tenant was not linked
	otherPackets, err := repo.AllPackets("other-tenant")
	require.NoError(t, err)
	require.Len(t, otherPackets, 1)
	assert.Zero(t, otherPackets[0].FlowID, "Packet from other tenant should not be linked")

	// Test idempotency - running again should link 0 packets
	linkedCount, err = repo.LinkPacketsToFlows(tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), linkedCount, "Should link 0 packets on second run (all already linked)")
}
