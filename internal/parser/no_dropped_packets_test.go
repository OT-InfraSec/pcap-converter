package parser

import (
	"database/sql"
	"net"
	"path/filepath"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/mattn/go-sqlite3"
)

// countRows counts the rows of a table in a finished import.
func countRows(t *testing.T, path, table string) int {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	defer db.Close()
	var n int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
	return n
}

func storedPackets(t *testing.T, path string) int { return countRows(t, path, "packets") }

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

var (
	hostMAC   = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	otherMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	bcastMAC  = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroMAC   = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	hostIP    = net.IP{192, 168, 1, 10}
	otherIP   = net.IP{192, 168, 1, 20}
	publicIP  = net.IP{8, 8, 4, 4}
	resolver  = net.IP{192, 168, 1, 1}
	resolvMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x53}
)

func arpPacket(t *testing.T, op uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) gopacket.Packet {
	ethDst := bcastMAC
	if op == layers.ARPReply {
		ethDst = dstMAC
	}
	return serialize(t,
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: ethDst, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
			Operation: op, SourceHwAddress: srcMAC, SourceProtAddress: srcIP, DstHwAddress: dstMAC, DstProtAddress: dstIP})
}

func dnsPacket(t *testing.T, response bool, rcode layers.DNSResponseCode, answers bool) gopacket.Packet {
	d := &layers.DNS{ID: 7, QR: response, RD: true, OpCode: layers.DNSOpCodeQuery, ResponseCode: rcode,
		Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	srcIP, dstIP, srcMAC, dstMAC := hostIP, resolver, hostMAC, resolvMAC
	srcPort, dstPort := layers.UDPPort(50000), layers.UDPPort(53)
	if response {
		srcIP, dstIP, srcMAC, dstMAC = dstIP, srcIP, dstMAC, srcMAC
		srcPort, dstPort = dstPort, srcPort
		d.QDCount = 1
		if answers {
			d.Answers = []layers.DNSResourceRecord{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.IP{93, 184, 216, 34}}}
			d.ANCount = 1
		}
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	return serialize(t, &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}, ip, udp, d)
}

func icmpUnreachable(t *testing.T) gopacket.Packet {
	return serialize(t,
		&layers.Ethernet{SrcMAC: resolvMAC, DstMAC: hostMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: resolver, DstIP: hostIP},
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort)},
		gopacket.Payload(make([]byte, 28)))
}

// Every packet in the capture ends up in the packets table. ARP requests, DNS
// queries, DNS errors and ICMP destination-unreachable used to be skipped.
func TestNoPacketIsDropped(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "db.sqlite")
	repo, err := repository.NewSQLiteRepository(dbPath)
	require.NoError(t, err)

	pkts := []gopacket.Packet{
		arpPacket(t, layers.ARPRequest, hostMAC, hostIP, zeroMAC, publicIP),             // request for an address that never answers
		arpPacket(t, layers.ARPRequest, hostMAC, hostIP, zeroMAC, publicIP),             // repeated
		arpPacket(t, layers.ARPRequest, otherMAC, net.IP{0, 0, 0, 0}, zeroMAC, otherIP), // ARP probe, sender 0.0.0.0
		arpPacket(t, layers.ARPRequest, hostMAC, hostIP, zeroMAC, resolver),             // request that gets answered
		arpPacket(t, layers.ARPReply, resolvMAC, resolver, hostMAC, hostIP),             // the answer
		dnsPacket(t, false, layers.DNSResponseCodeNoErr, false),                         // query
		dnsPacket(t, true, layers.DNSResponseCodeNXDomain, false),                       // error response
		dnsPacket(t, true, layers.DNSResponseCodeNoErr, false),                          // empty response
		dnsPacket(t, true, layers.DNSResponseCodeNoErr, true),                           // answered response
		icmpUnreachable(t),
	}
	pcap := writePCAP(t, pkts)
	require.NoError(t, NewGopacketParser(pcap, repo, "").ParseFile())

	// 1. All packets stored.
	assert.Equal(t, len(pkts), storedPackets(t, dbPath), "every packet read must be stored")

	// 2. Devices: the senders exist. The unanswered public target and the
	// probe's 0.0.0.0 are not devices.
	devices, err := repo.GetDevices("", nil)
	require.NoError(t, err)
	addrs := map[string]bool{}
	for _, d := range devices {
		addrs[d.Address] = true
	}
	assert.True(t, addrs[hostIP.String()], "ARP sender is a device")
	assert.True(t, addrs[resolver.String()], "answering host is a device")
	assert.False(t, addrs[publicIP.String()], "an ARP request target that never answered is not a device")
	assert.False(t, addrs["0.0.0.0"], "an ARP probe sender is not a device")
	for _, d := range devices {
		assert.NotContains(t, d.MACAddressSet.ToString(), "00:00:00:00:00:00", "device %s has the all-zero MAC", d.Address)
	}

	// 3. Flows: no flow to the unanswered target; the DNS flow holds the queries.
	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	var dnsPackets int
	for _, f := range flows {
		assert.NotEqual(t, publicIP.String(), f.DstIP.String(), "no flow to an unanswered ARP target")
		if f.Protocol == "dns" {
			dnsPackets += f.PacketCountOut + f.PacketCountIn
		}
	}
	assert.Equal(t, 4, dnsPackets, "query, NXDOMAIN, empty and answered response are all in the DNS flow")

	// 4. dns_queries keeps its meaning: only the answered response is recorded.
	// (Counted in SQL: GetDNSQueries cannot scan query_result into its map.)
	assert.Equal(t, 1, countRows(t, dbPath, "dns_queries"))
}

// An unanswered ARP request alone still produces a stored packet and a device
// for its sender, but no flow.
func TestARPRequestAloneIsStored(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "db.sqlite")
	repo, err := repository.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	pcap := writePCAP(t, []gopacket.Packet{arpPacket(t, layers.ARPRequest, hostMAC, hostIP, zeroMAC, publicIP)})
	require.NoError(t, NewGopacketParser(pcap, repo, "").ParseFile())

	assert.Equal(t, 1, storedPackets(t, dbPath))
	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	assert.Empty(t, flows)
	devices, err := repo.GetDevices("", nil)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, hostIP.String(), devices[0].Address)
}
