package parser

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vlanFrame serializes a TCP frame carrying the given VLAN tags (outermost first).
// 0 entries are valid tags (priority-only, VID 0); no entries means untagged.
func vlanFrame(t *testing.T, tags ...uint16) []byte {
	t.Helper()
	ip := &layers.IPv4{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, Protocol: layers.IPProtocolTCP, TTL: 64, Version: 4, IHL: 5}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 80, ACK: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	eth := &layers.Ethernet{
		SrcMAC: []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	stack := []gopacket.SerializableLayer{eth}
	for i, id := range tags {
		next := layers.EthernetTypeIPv4
		if i < len(tags)-1 {
			next = layers.EthernetTypeDot1Q
		}
		if i == 0 {
			// QinQ uses the 802.1ad ethertype for the outer tag
			if len(tags) > 1 {
				eth.EthernetType = layers.EthernetTypeQinQ
			} else {
				eth.EthernetType = layers.EthernetTypeDot1Q
			}
		}
		stack = append(stack, &layers.Dot1Q{VLANIdentifier: id, Type: next})
	}
	stack = append(stack, ip, tcp, gopacket.Payload([]byte("hello")))

	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, stack...))
	return buf.Bytes()
}

func TestExtractVLANTag(t *testing.T) {
	tests := []struct {
		name         string
		tags         []uint16
		outer, inner *int
	}{
		{"untagged", nil, nil, nil},
		{"single tag", []uint16{10}, vlanPtr(10), nil},
		{"qinq", []uint16{10, 200}, vlanPtr(10), vlanPtr(200)},
		{"priority-only tag is untagged", []uint16{0}, nil, nil},
		{"vid 1 stays vid 1", []uint16{1}, vlanPtr(1), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := gopacket.NewPacket(vlanFrame(t, tt.tags...), layers.LayerTypeEthernet, gopacket.Default)
			got := extractVLANTag(pkt)
			assert.Equal(t, tt.outer, got.Outer)
			assert.Equal(t, tt.inner, got.Inner)
		})
	}
}

func vlanPtr(v int) *int { return &v }

func writeVLANPCAP(t *testing.T, frames [][]byte) string {
	t.Helper()
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	require.NoError(t, w.WriteFileHeader(65536, layers.LinkTypeEthernet))
	for i, f := range frames {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond), Length: len(f), CaptureLength: len(f),
		}, f))
	}
	path := filepath.Join(t.TempDir(), "vlan.pcap")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
	return path
}

// TestIntegration_VLANEndToEnd imports one 5-tuple seen untagged, in VLAN 10, 20 and QinQ 10/200
// and checks packets, flows, devices and the schema marker as the visualizer will read them.
func TestIntegration_VLANEndToEnd(t *testing.T) {
	frames := [][]byte{
		vlanFrame(t),
		vlanFrame(t, 10),
		vlanFrame(t, 10),
		vlanFrame(t, 20),
		vlanFrame(t, 10, 200),
		vlanFrame(t, 0), // priority-only: counts as untagged
	}
	pcap := writeVLANPCAP(t, frames)

	repo, err := repository.NewSQLiteRepositoryWithCanonicalizer(filepath.Join(t.TempDir(), "out.sqlite"), helper.NewFlowCanonicalizer())
	require.NoError(t, err)
	defer repo.Close()

	require.NoError(t, NewGopacketParser(pcap, repo, "t").ParseFile())

	packets, err := repo.AllPackets("t")
	require.NoError(t, err)
	require.Len(t, packets, len(frames))
	tokens := map[string]int{}
	for _, p := range packets {
		tokens[model.VLANToken(p.VlanID, p.VlanInnerID)]++
	}
	assert.Equal(t, map[string]int{"untagged": 2, "10": 2, "20": 1, "10.200": 1}, tokens)

	flows, err := repo.GetFlows("t", nil)
	require.NoError(t, err)
	flowPackets := map[string]int{}
	for _, f := range flows {
		flowPackets[model.VLANToken(f.VlanID, f.VlanInnerID)] = f.PacketCountOut
	}
	assert.Equal(t, map[string]int{"untagged": 2, "10": 2, "20": 1, "10.200": 1}, flowPackets,
		"same 5-tuple in different VLANs must be separate flows")

	devices, err := repo.GetDevices("t", nil)
	require.NoError(t, err)
	require.Len(t, devices, 2, "a device seen in several VLANs stays one row")
	for _, d := range devices {
		assert.Equal(t, "untagged,10,10.200,20", d.VLANSet.ToString())
	}
}

// TestIntegration_UntaggedCaptureHasNoVLANs makes sure an untagged-only capture never stores a VLAN ID.
func TestIntegration_UntaggedCaptureHasNoVLANs(t *testing.T) {
	pcap := writeVLANPCAP(t, [][]byte{vlanFrame(t), vlanFrame(t)})

	repo, err := repository.NewSQLiteRepositoryWithCanonicalizer(filepath.Join(t.TempDir(), "out.sqlite"), helper.NewFlowCanonicalizer())
	require.NoError(t, err)
	defer repo.Close()
	require.NoError(t, NewGopacketParser(pcap, repo, "t").ParseFile())

	packets, err := repo.AllPackets("t")
	require.NoError(t, err)
	require.Len(t, packets, 2, "no packet may be lost")
	for _, p := range packets {
		assert.Nil(t, p.VlanID)
		assert.Nil(t, p.VlanInnerID)
	}
}
