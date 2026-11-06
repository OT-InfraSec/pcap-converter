package repository

import (
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A device value without VLAN information (for example a bare DNS or flow
// endpoint device) must not erase the VLANs already stored for the address.

func TestSQLiteRepository_UpsertDeviceKeepsStoredVLANs(t *testing.T) {
	repo := newVLANTestRepo(t)

	withVLAN := vlanTestDevice("10.0.0.1")
	withVLAN.VLANSet.Add(vlanPtr(10), nil)
	require.NoError(t, repo.UpsertDevice(withVLAN))

	bare := vlanTestDevice("10.0.0.1")
	require.NoError(t, repo.UpsertDevice(bare))

	got, err := repo.GetDevice("t", "10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, "10", got.VLANSet.ToString())
}

func TestSQLiteRepository_UpsertDeviceUnionsStoredVLANs(t *testing.T) {
	repo := newVLANTestRepo(t)

	first := vlanTestDevice("10.0.0.1")
	first.VLANSet.Add(vlanPtr(10), nil)
	require.NoError(t, repo.UpsertDevice(first))

	second := vlanTestDevice("10.0.0.1")
	second.VLANSet.Add(vlanPtr(20), nil)
	require.NoError(t, repo.UpsertDevice(second))

	got, err := repo.GetDevice("t", "10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, "10,20", got.VLANSet.ToString())
}

func TestSQLiteRepository_UpsertDevicesKeepsStoredVLANs(t *testing.T) {
	repo := newVLANTestRepo(t)

	withVLAN := vlanTestDevice("10.0.0.1")
	withVLAN.VLANSet.Add(vlanPtr(10), nil)
	require.NoError(t, repo.UpsertDevices([]*model.Device{withVLAN}))

	bare := vlanTestDevice("10.0.0.1")
	require.NoError(t, repo.UpsertDevices([]*model.Device{bare}))

	got, err := repo.GetDevice("t", "10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, "10", got.VLANSet.ToString())
}

func TestSQLiteRepository_UpsertDevicesUnionsStoredVLANs(t *testing.T) {
	repo := newVLANTestRepo(t)

	first := vlanTestDevice("10.0.0.1")
	first.VLANSet.Add(vlanPtr(10), nil)
	require.NoError(t, repo.UpsertDevices([]*model.Device{first}))

	second := vlanTestDevice("10.0.0.1")
	second.VLANSet.Add(vlanPtr(20), nil)
	require.NoError(t, repo.UpsertDevices([]*model.Device{second}))

	got, err := repo.GetDevice("t", "10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, "10,20", got.VLANSet.ToString())
}
