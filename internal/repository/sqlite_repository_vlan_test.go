package repository

import (
	"database/sql"
	"net"
	"path/filepath"
	"testing"
	"time"

	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newVLANTestRepo(t *testing.T) *SQLiteRepository {
	t.Helper()
	repo, err := NewSQLiteRepositoryWithCanonicalizer(filepath.Join(t.TempDir(), "vlan.sqlite"), helper.NewFlowCanonicalizer())
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func vlanPtr(v int) *int { return &v }

func TestSQLiteRepository_SetsSchemaVersion(t *testing.T) {
	repo := newVLANTestRepo(t)

	var version int
	require.NoError(t, repo.db.QueryRow("PRAGMA user_version").Scan(&version))
	assert.Equal(t, schemaVersion, version)
}

func TestSQLiteRepository_RejectsOutdatedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.sqlite")
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE packets (id INTEGER PRIMARY KEY, layers TEXT)`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = NewSQLiteRepositoryWithCanonicalizer(path, helper.NewFlowCanonicalizer())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "re-import")
}

func TestSQLiteRepository_PacketVLANRoundTrip(t *testing.T) {
	repo := newVLANTestRepo(t)
	ts := time.Now()
	mk := func(outer, inner *int) *model.Packet {
		return &model.Packet{Timestamp: ts, Length: 60, Layers: map[string]interface{}{}, VlanID: outer, VlanInnerID: inner}
	}
	// AddPackets and UpsertPackets share the same columns; cover both
	require.NoError(t, repo.AddPackets([]*model.Packet{mk(nil, nil), mk(vlanPtr(10), nil)}))
	require.NoError(t, repo.UpsertPackets([]*model.Packet{mk(vlanPtr(10), vlanPtr(200))}))

	packets, err := repo.AllPackets("")
	require.NoError(t, err)
	require.Len(t, packets, 3)

	assert.Nil(t, packets[0].VlanID, "untagged must be NULL, not 1")
	assert.Nil(t, packets[0].VlanInnerID)
	require.NotNil(t, packets[1].VlanID)
	assert.Equal(t, 10, *packets[1].VlanID)
	assert.Nil(t, packets[1].VlanInnerID)
	require.NotNil(t, packets[2].VlanInnerID)
	assert.Equal(t, 200, *packets[2].VlanInnerID)
}

func TestSQLiteRepository_DeviceVLANSetRoundTrip(t *testing.T) {
	repo := newVLANTestRepo(t)
	set := model.NewVLANSet()
	set.Add(nil, nil)
	set.Add(vlanPtr(10), nil)
	set.Add(vlanPtr(10), vlanPtr(20))

	dev := &model.Device{
		TenantID: "t", Address: "10.0.0.1", AddressType: "IP", AddressScope: "IPv4",
		FirstSeen: time.Now(), LastSeen: time.Now(),
		MACAddressSet: model.NewMACAddressSet(), ProtocolList: model.NewSet(), DNSNames: model.NewSet(),
		VLANSet: set,
	}
	require.NoError(t, repo.UpsertDevices([]*model.Device{dev}))

	got, err := repo.GetDevices("t", nil)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "untagged,10,10.20", got[0].VLANSet.ToString())

	// A second upsert replaces the set (the device manager holds the full set)
	dev.VLANSet.Add(vlanPtr(30), nil)
	require.NoError(t, repo.UpsertDevices([]*model.Device{dev}))
	devices, err := repo.GetDevices("t", nil)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, "untagged,10,10.20,30", devices[0].VLANSet.ToString())
}

func TestSQLiteRepository_FlowsSplitByVLAN(t *testing.T) {
	repo := newVLANTestRepo(t)
	require.NoError(t, repo.UpsertDevices([]*model.Device{
		vlanTestDevice("10.0.0.1"), vlanTestDevice("10.0.0.2"),
	}))

	mk := func(outer *int) *model.Flow {
		return &model.Flow{
			TenantID: "t", SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
			SrcPort: 40000, DstPort: 80, Protocol: "tcp",
			PacketCountOut: 1, ByteCountOut: 60, FirstSeen: time.Now(), LastSeen: time.Now(),
			MinPacketSize: 60, MaxPacketSize: 60, PacketRefs: []int64{1},
			SourcePorts: model.SetFromSlice([]string{"40000"}), DestinationPorts: model.SetFromSlice([]string{"80"}),
			VlanID: outer,
		}
	}
	// Same 5-tuple in untagged, VLAN 10 and VLAN 20, plus a repeat in VLAN 10 that must merge
	require.NoError(t, repo.UpsertFlows([]*model.Flow{mk(nil), mk(vlanPtr(10)), mk(vlanPtr(20)), mk(vlanPtr(10))}))

	flows, err := repo.GetFlows("t", nil)
	require.NoError(t, err)
	require.Len(t, flows, 3)

	byVLAN := map[string]*model.Flow{}
	for _, f := range flows {
		byVLAN[model.VLANToken(f.VlanID, f.VlanInnerID)] = f
	}
	assert.Equal(t, 1, byVLAN["untagged"].PacketCountOut)
	assert.Equal(t, 2, byVLAN["10"].PacketCountOut, "same VLAN merges")
	assert.Equal(t, 1, byVLAN["20"].PacketCountOut)
}

func TestSQLiteRepository_LinkPacketsToFlowsRespectsVLAN(t *testing.T) {
	repo := newVLANTestRepo(t)
	require.NoError(t, repo.UpsertDevices([]*model.Device{
		vlanTestDevice("10.0.0.1"), vlanTestDevice("10.0.0.2"),
	}))
	flow := &model.Flow{
		TenantID: "t", SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: 40000, DstPort: 80, Protocol: "tcp", PacketCountOut: 1,
		FirstSeen: time.Now(), LastSeen: time.Now(), MinPacketSize: 60, MaxPacketSize: 60,
		SourcePorts: model.SetFromSlice([]string{"40000"}), DestinationPorts: model.SetFromSlice([]string{"80"}),
		VlanID: vlanPtr(10),
	}
	require.NoError(t, repo.AddFlow(flow))

	pkt := func(outer *int) *model.Packet {
		return &model.Packet{
			TenantID: "t", Timestamp: time.Now(), Length: 60, Protocol: "tcp", Layers: map[string]interface{}{},
			SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: 80, VlanID: outer,
		}
	}
	// UpsertPackets is the parser's path; AddPackets does not store the protocol column
	require.NoError(t, repo.UpsertPackets([]*model.Packet{pkt(vlanPtr(10)), pkt(vlanPtr(20)), pkt(nil)}))

	linked, err := repo.LinkPacketsToFlows("t")
	require.NoError(t, err)
	assert.EqualValues(t, 1, linked, "only the VLAN 10 packet belongs to the VLAN 10 flow")
}

func vlanTestDevice(addr string) *model.Device {
	return &model.Device{
		TenantID: "t", Address: addr, AddressType: "IP", AddressScope: "IPv4",
		FirstSeen: time.Now(), LastSeen: time.Now(),
		MACAddressSet: model.NewMACAddressSet(), ProtocolList: model.NewSet(), DNSNames: model.NewSet(),
		VLANSet: model.NewVLANSet(),
	}
}
