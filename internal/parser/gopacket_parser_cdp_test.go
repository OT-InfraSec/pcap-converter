package parser

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tlv(typ uint16, value []byte) []byte {
	out := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(out[0:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(value)))
	return append(out, value...)
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// cdpAddressTLV encodes IPv4 addresses as NLPID entries (RFC-less but what Cisco sends).
func cdpAddressValue(ips ...string) []byte {
	out := u32(uint32(len(ips)))
	for _, s := range ips {
		ip := net.ParseIP(s).To4()
		out = append(out, 1, 1, 0xcc)
		out = append(out, u16(4)...)
		out = append(out, ip...)
	}
	return out
}

func cdpPrefixValue(prefixes ...string) []byte {
	var out []byte
	for _, s := range prefixes {
		ip, n, _ := net.ParseCIDR(s)
		ones, _ := n.Mask.Size()
		out = append(out, ip.To4()...)
		out = append(out, byte(ones))
	}
	return out
}

func cdpHelloValue(mgmtVLAN uint16) []byte {
	v := make([]byte, 32)
	copy(v[0:3], []byte{0x00, 0x00, 0x0c})
	binary.BigEndian.PutUint16(v[30:32], mgmtVLAN)
	return v
}

// cdpFrame builds an 802.3 + LLC/SNAP (OUI 00000c, PID 0x2000) CDP frame; vlan < 0 = untagged.
func cdpFrame(src net.HardwareAddr, vlan int, tlvs ...[]byte) []byte {
	cdp := []byte{2, 180, 0, 0}
	for _, t := range tlvs {
		cdp = append(cdp, t...)
	}
	llc := append([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}, cdp...)

	frame := append([]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}, src...)
	if vlan >= 0 {
		frame = append(frame, 0x81, 0x00)
		frame = append(frame, u16(uint16(vlan))...)
	}
	frame = append(frame, u16(uint16(len(llc)))...)
	return append(frame, llc...)
}

func fullCDPFrame(src net.HardwareAddr, vlan int, native uint16) []byte {
	return cdpFrame(src, vlan,
		tlv(0x0001, []byte("sw1.example")),
		tlv(0x0002, cdpAddressValue("10.0.0.1", "10.0.0.5")),
		tlv(0x0003, []byte("GigabitEthernet1/0/1")),
		tlv(0x0004, u32(0x01|0x08)), // router + switch
		tlv(0x0005, []byte("IOS 16.9")),
		tlv(0x0006, []byte("cisco WS-C3850")),
		tlv(0x0007, cdpPrefixValue("10.0.1.0/24", "10.0.2.0/24")),
		tlv(0x0008, cdpHelloValue(99)),
		tlv(0x000a, u16(native)),
		tlv(0x0014, []byte("sw1")),
		tlv(0x0016, cdpAddressValue("10.0.0.2")),
	)
}

var cdpSrcMAC = net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}

func cdpNeighbors(t *testing.T, repo repository.Repository) []*model.CDPNeighbor {
	t.Helper()
	got, err := repo.GetCDPNeighbors("t", nil)
	require.NoError(t, err)
	return got
}

func TestIntegration_CDPNeighborEndToEnd(t *testing.T) {
	repo := importFrames(t, [][]byte{
		fullCDPFrame(cdpSrcMAC, -1, 10),
		fullCDPFrame(cdpSrcMAC, -1, 10), // repeat: one row
	})

	got := cdpNeighbors(t, repo)
	require.Len(t, got, 1)
	n := got[0]
	assert.Equal(t, "00:aa:bb:cc:dd:01", n.SrcMAC)
	assert.Equal(t, "GigabitEthernet1/0/1", n.PortID)
	assert.Nil(t, n.VlanID, "untagged must be NULL")
	assert.Equal(t, "sw1.example", n.DeviceID)
	assert.Equal(t, "cisco WS-C3850", n.Platform)
	assert.Equal(t, "IOS 16.9", n.SoftwareVersion)
	assert.Equal(t, "sw1", n.SysName)
	assert.Equal(t, "router,switch", n.Capabilities)
	assert.Equal(t, "10.0.0.1,10.0.0.5", n.Addresses)
	assert.Equal(t, "10.0.0.2", n.MgmtAddresses)
	require.NotNil(t, n.NativeVLAN)
	assert.Equal(t, 10, *n.NativeVLAN)
	require.NotNil(t, n.ManagementVLAN)
	assert.Equal(t, 99, *n.ManagementVLAN)
	assert.False(t, n.FirstSeen.After(n.LastSeen))
	assert.True(t, n.LastSeen.After(n.FirstSeen), "repeat widens the range")

	assert.Equal(t, map[subnetKey]bool{
		{"10.0.1.0/24", "untagged", "cdp", "advertised"}: true,
		{"10.0.2.0/24", "untagged", "cdp", "advertised"}: true,
	}, subnetKeys(t, repo))
}

func TestIntegration_CDPTaggedChangedValueAndPorts(t *testing.T) {
	otherPort := net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x02}
	repo := importFrames(t, [][]byte{
		fullCDPFrame(cdpSrcMAC, 30, 10),
		fullCDPFrame(cdpSrcMAC, 30, 20),   // native VLAN reconfigured
		fullCDPFrame(otherPort, 30, 10),   // other interface
		fullCDPFrame(cdpSrcMAC, -1, 4095), // untagged; invalid native VLAN
	})

	got := cdpNeighbors(t, repo)
	require.Len(t, got, 4)
	var tagged, nullNative int
	for _, n := range got {
		if n.VlanID != nil {
			assert.Equal(t, 30, *n.VlanID)
			tagged++
		}
		if n.NativeVLAN == nil {
			nullNative++
		}
	}
	assert.Equal(t, 3, tagged)
	assert.Equal(t, 1, nullNative, "4095 is stored as NULL")

	// prefixes are per VLAN of the frame
	assert.Equal(t, map[subnetKey]bool{
		{"10.0.1.0/24", "30", "cdp", "advertised"}:       true,
		{"10.0.2.0/24", "30", "cdp", "advertised"}:       true,
		{"10.0.1.0/24", "untagged", "cdp", "advertised"}: true,
		{"10.0.2.0/24", "untagged", "cdp", "advertised"}: true,
	}, subnetKeys(t, repo))
}

func TestIntegration_CDPSkipsAnonymousAndMalformed(t *testing.T) {
	truncated := fullCDPFrame(cdpSrcMAC, -1, 10)
	truncated = truncated[:len(truncated)-6] // last TLV cut short
	// A prefix length above 32 makes gopacket's CDP decoder panic. Tagged frames are decoded by
	// cdpInfoFromPacket with recovery on, so this one is skipped. The untagged variant would
	// crash ParseFile (SkipDecodeRecovery) and is therefore not tested here.
	badPrefix := cdpFrame(cdpSrcMAC, 40,
		tlv(0x0001, []byte("sw")),
		tlv(0x0007, []byte{10, 0, 0, 0, 200}),
	)
	repo := importFrames(t, [][]byte{
		cdpFrame(cdpSrcMAC, -1, tlv(0x0006, []byte("platform only"))), // no device ID, no address
		truncated,
		badPrefix,
	})

	assert.Empty(t, cdpNeighbors(t, repo))
	assert.Empty(t, subnetKeys(t, repo))
}

func TestIntegration_NoCDPNoRows(t *testing.T) {
	repo := importFrames(t, [][]byte{vlanFrame(t), vlanFrame(t, 10)})
	assert.Empty(t, cdpNeighbors(t, repo))
}

func TestIntegration_CDPInQinQUsesOuterVLAN(t *testing.T) {
	tagged := fullCDPFrame(cdpSrcMAC, 40, 10)
	// dst(6) src(6) | 8100 0028 | len ...  ->  dst src | 88a8 0064 | 8100 0028 | len ...
	qinq := append([]byte{}, tagged[:12]...)
	qinq = append(qinq, 0x88, 0xa8, 0x00, 100)
	qinq = append(qinq, tagged[12:]...)

	repo := importFrames(t, [][]byte{qinq})
	got := cdpNeighbors(t, repo)
	require.Len(t, got, 1)
	require.NotNil(t, got[0].VlanID)
	assert.Equal(t, 100, *got[0].VlanID)
}
