package parser

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writePCAP serialises packets to a classic pcap file.
func writePCAP(t *testing.T, packets []gopacket.Packet) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enip.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	base := time.Unix(1700000000, 0)
	for i, p := range packets {
		data := p.Data()
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(data), Length: len(data),
		}, data))
	}
	return path
}

// An EtherNet/IP TCP connection is one flow: the handshake and ACK segments
// carry no payload but belong to the same flow as the messages.
func TestEtherNetIPConnectionIsOneFlow(t *testing.T) {
	dir := t.TempDir()
	repo, err := repository.NewSQLiteRepository(filepath.Join(dir, "db.sqlite"))
	require.NoError(t, err)

	cli := func(flags layers.TCP, payload []byte) gopacket.Packet {
		flags.SrcPort, flags.DstPort = 50000, 44818
		return buildTransportPacket(t, &flags, nil, payload)
	}
	// Server replies come from the other address; buildTransportPacket fixes
	// the addresses, so replies in the same direction still exercise the label.
	regSession := enipEncap(0x65, 4, []byte{1, 0, 0, 0})
	pkts := []gopacket.Packet{
		cli(layers.TCP{SYN: true}, nil),
		cli(layers.TCP{ACK: true}, nil),
		cli(layers.TCP{ACK: true, PSH: true}, regSession),
		cli(layers.TCP{ACK: true}, nil),
		cli(layers.TCP{ACK: true, PSH: true}, enipEncap(0x63, 0, nil)),
		cli(layers.TCP{ACK: true, FIN: true}, nil),
	}
	pcap := writePCAP(t, pkts)

	require.NoError(t, NewGopacketParser(pcap, repo, "").ParseFile())

	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	require.Len(t, flows, 1, "handshake, data and teardown must not split into several flows")
	assert.Equal(t, "EtherNet/IP(TCP)", flows[0].Protocol)
	assert.Equal(t, 6, flows[0].PacketCountOut+flows[0].PacketCountIn)
}

// Implicit I/O on UDP 2222 is labelled EtherNet/IP; Suricata does not do this.
func TestEtherNetIPImplicitIOFlow(t *testing.T) {
	repo, err := repository.NewSQLiteRepository(filepath.Join(t.TempDir(), "db.sqlite"))
	require.NoError(t, err)

	implicit := []byte{0x02, 0x00, 0x02, 0x80, 0x08, 0x00, 0x05, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb1, 0x00, 0x02, 0x00, 0x01, 0x00}
	var pkts []gopacket.Packet
	for i := 0; i < 5; i++ {
		pkts = append(pkts, buildTransportPacket(t, nil, &layers.UDP{SrcPort: 2222, DstPort: 2222}, implicit))
	}
	require.NoError(t, NewGopacketParser(writePCAP(t, pkts), repo, "").ParseFile())

	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, "EtherNet/IP(UDP)", flows[0].Protocol)
}

// Non-ENIP traffic on the ENIP port is not labelled EtherNet/IP.
func TestGarbageOnEtherNetIPPortIsNotLabelled(t *testing.T) {
	repo, err := repository.NewSQLiteRepository(filepath.Join(t.TempDir(), "db.sqlite"))
	require.NoError(t, err)

	pkts := []gopacket.Packet{
		buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, ACK: true, PSH: true}, nil,
			[]byte("GET /index.html HTTP/1.1\r\nHost: plc\r\n\r\n")),
		buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, ACK: true}, nil, nil),
	}
	require.NoError(t, NewGopacketParser(writePCAP(t, pkts), repo, "").ParseFile())

	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	for _, f := range flows {
		assert.NotContains(t, f.Protocol, "EtherNet/IP", "flow %+v", f)
	}
}
