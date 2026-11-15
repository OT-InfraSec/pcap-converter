package repository

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func flagTestDevice(addr string, external bool, protocols ...string) *model.Device {
	return &model.Device{
		TenantID: "t", Address: addr, AddressType: "IP", AddressScope: "unicast",
		FirstSeen: time.Now(), LastSeen: time.Now(), IsExternal: external,
		MACAddressSet: model.NewMACAddressSet(), DNSNames: model.NewSet(),
		ProtocolList: model.SetFromSlice(protocols), VLANSet: model.NewVLANSet(),
	}
}

func readDeviceFlags(t *testing.T, repo *SQLiteRepository, addr string) (external *bool, protocols string) {
	t.Helper()
	var ext *bool
	var proto *string
	require.NoError(t, repo.db.QueryRow(`SELECT is_external, protocol_list FROM devices WHERE address = ?`, addr).Scan(&ext, &proto))
	if proto != nil {
		protocols = *proto
	}
	return ext, protocols
}

func TestSQLiteRepository_UpsertDevicesPersistsIsExternal(t *testing.T) {
	repo := newVLANTestRepo(t)
	require.NoError(t, repo.UpsertDevices([]*model.Device{flagTestDevice("8.8.8.8", true), flagTestDevice("10.0.0.1", false)}))

	ext, _ := readDeviceFlags(t, repo, "8.8.8.8")
	require.NotNil(t, ext)
	assert.True(t, *ext)
	ext, _ = readDeviceFlags(t, repo, "10.0.0.1")
	require.NotNil(t, ext, "false must be stored, not NULL")
	assert.False(t, *ext)

	// The update path writes it too (repairs rows imported before the column was set).
	_, err := repo.db.Exec(`UPDATE devices SET is_external = NULL`)
	require.NoError(t, err)
	require.NoError(t, repo.UpsertDevices([]*model.Device{flagTestDevice("8.8.8.8", true), flagTestDevice("10.0.0.1", false)}))
	ext, _ = readDeviceFlags(t, repo, "8.8.8.8")
	require.NotNil(t, ext)
	assert.True(t, *ext)
}

func TestSQLiteRepository_UpsertDevicesMergesProtocolList(t *testing.T) {
	repo := newVLANTestRepo(t)
	require.NoError(t, repo.UpsertDevices([]*model.Device{flagTestDevice("10.0.0.1", false, "dns(UDP)", "tls")}))
	require.NoError(t, repo.UpsertDevices([]*model.Device{flagTestDevice("10.0.0.1", false, "dns(TCP)", "tls")}))

	_, protocols := readDeviceFlags(t, repo, "10.0.0.1")
	assert.JSONEq(t, `["dns(TCP)","dns(UDP)","tls"]`, protocols)

	got, err := repo.GetDevice("t", "10.0.0.1")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"dns(UDP)", "dns(TCP)", "tls"}, got.ProtocolList.List())
}

func TestSQLiteRepository_UpdateDevicePersistsFlags(t *testing.T) {
	repo := newVLANTestRepo(t)
	require.NoError(t, repo.UpsertDevice(flagTestDevice("8.8.8.8", true, "tls")))
	dev := flagTestDevice("8.8.8.8", true, "tls", "http")
	require.NoError(t, repo.UpsertDevice(dev))

	ext, protocols := readDeviceFlags(t, repo, "8.8.8.8")
	require.NotNil(t, ext)
	assert.True(t, *ext)
	assert.JSONEq(t, `["http","tls"]`, protocols)
}
