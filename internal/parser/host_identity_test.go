package parser

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/hostid"
	"github.com/InfraSecConsult/pcap-importer-go/lib/hostid/hostidtest"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ethTCP(t *testing.T, srcMAC, dstMAC string, srcIP, dstIP net.IP, sport, dport uint16, seq uint32, payload []byte) gopacket.Packet {
	t.Helper()
	sm, err := net.ParseMAC(srcMAC)
	require.NoError(t, err)
	dm, err := net.ParseMAC(dstMAC)
	require.NoError(t, err)
	eth := &layers.Ethernet{SrcMAC: sm, DstMAC: dm, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Seq: seq, ACK: true, PSH: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func deviceData(t *testing.T, d *model.Device, key string) map[string]interface{} {
	t.Helper()
	var all map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(d.AdditionalData), &all))
	m, _ := all[key].(map[string]interface{})
	return m
}

// NetBIOS name service and SMB negotiation identify the hosts, and their flows
// are labelled by content.
func TestNetBIOSAndSMBIdentifyHosts(t *testing.T) {
	repo, err := repository.NewSQLiteRepository(filepath.Join(t.TempDir(), "db.sqlite"))
	require.NoError(t, err)

	const cMAC, sMAC = "00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:09"
	cli, srv := net.IPv4(10, 20, 0, 7), net.IPv4(10, 20, 0, 9)
	bcast := net.IPv4(10, 20, 0, 255)
	const day = 864000000000
	sys := uint64(133800000000000000)
	var guid [16]byte
	copy(guid[:], []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8})

	udp := func(srcMAC string, src, dst net.IP, sport, dport uint16, payload []byte) gopacket.Packet {
		return ethUDP(t, srcMAC, "ff:ff:ff:ff:ff:ff", src, dst, sport, dport, gopacket.Payload(payload))
	}
	var seqC, seqS uint32 = 1000, 5000
	toSrv := func(port uint16, payload []byte) gopacket.Packet {
		p := ethTCP(t, cMAC, sMAC, cli, srv, 50001, port, seqC, payload)
		seqC += uint32(len(payload))
		return p
	}
	toCli := func(port uint16, payload []byte) gopacket.Packet {
		p := ethTCP(t, sMAC, cMAC, srv, cli, port, 50001, seqS, payload)
		seqS += uint32(len(payload))
		return p
	}
	pkts := []gopacket.Packet{
		// NetBIOS name service: the client registers its names, the server answers a node status query.
		udp(cMAC, cli, bcast, 137, 137, hostidtest.NBNSRegistration("HMI01", 0x00, false, cli)),
		udp(cMAC, cli, bcast, 137, 137, hostidtest.NBNSRegistration("PLANT", 0x00, true, cli)),
		ethUDP(t, sMAC, cMAC, srv, cli, 137, 137, gopacket.Payload(hostidtest.NBSTATResponse(
			[]hostidtest.NBName{{Name: "FILESRV"}, {Name: "PLANT", Group: true}, {Name: "FILESRV", Suffix: 0x20}}, [6]byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x09}))),
		// SMB 2/3 on 445.
		toSrv(445, hostidtest.SMB2NegotiateRequest(false, guid, 0x0202, 0x0210, 0x0311)),
		toCli(445, hostidtest.SMB2NegotiateResponse(0x0311, true, guid, sys, sys-5*day)),
		toCli(445, hostidtest.SMB2SessionSetup(true, hostidtest.NTLMChallenge("FILESRV", "PLANT", "filesrv.plant.example", "plant.example", 10, 0, 17763))),
		toSrv(445, hostidtest.SMB2SessionSetup(false, hostidtest.NTLMAuthenticate("PLANT", "operator", "HMI01", 10, 0, 19045))),
		// SMB behind the NetBIOS session service on 139.
		toSrv(139, hostidtest.SessionRequest("FILESRV", 0x20, "HMI01", 0x00)),
	}
	require.NoError(t, NewGopacketParser(writePCAP(t, pkts), repo, "").ParseFile())

	devs, err := repo.GetDevices("", nil)
	require.NoError(t, err)
	byIP := map[string]*model.Device{}
	for _, d := range devs {
		byIP[d.Address] = d
	}

	c, s := byIP["10.20.0.7"], byIP["10.20.0.9"]
	require.NotNil(t, c)
	require.NotNil(t, s)

	nb := deviceData(t, c, "netbios")
	assert.Equal(t, "HMI01", c.Hostname, "the NetBIOS computer name names the host when nothing else does")
	assert.Equal(t, []interface{}{"HMI01<00>", "PLANT<00> G"}, nb["names"])
	assert.Equal(t, "PLANT", nb["workgroup"])
	assert.Equal(t, "HMI01<00>", nb["session_calling_name"])

	sn := deviceData(t, s, "netbios")
	assert.Equal(t, "00:1a:2b:3c:4d:09", sn["mac"])
	assert.Equal(t, "FILESRV", sn["computer_name"])

	smb := deviceData(t, s, "smb")
	assert.Equal(t, "3.1.1", smb["dialect"])
	assert.Equal(t, true, smb["signing_required"])
	assert.Equal(t, "12345678-9abc-def0-0102-030405060708", smb["server_guid"])
	assert.EqualValues(t, 5*86400, smb["uptime_seconds"])
	assert.Equal(t, "FILESRV", smb["netbios_computer"])
	assert.Equal(t, "plant.example", smb["dns_domain"])
	assert.Equal(t, "10.0.17763", smb["windows_version"])
	assert.Contains(t, s.AdditionalData, `"dnsNames":["filesrv.plant.example"]`)
	assert.Equal(t, "FILESRV", s.Hostname)

	csmb := deviceData(t, c, "smb")
	assert.Equal(t, []interface{}{"2.0.2", "2.1", "3.1.1"}, csmb["offered_dialects"])
	assert.Equal(t, "PLANT", csmb["domain"])
	assert.Equal(t, "HMI01", csmb["workstation"])
	assert.Equal(t, "10.0.19045", csmb["windows_version"])
	assert.NotContains(t, c.AdditionalData, "operator", "user names are not stored")

	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	labels := map[string]int{}
	for _, f := range flows {
		labels[f.Protocol]++
	}
	assert.Positive(t, labels["nbns"], "labels %v", labels)
	assert.Positive(t, labels["smb"], "labels %v", labels)
}

func TestDisabledIdentityProtocolsCollectNothing(t *testing.T) {
	repo, err := repository.NewSQLiteRepository(filepath.Join(t.TempDir(), "db.sqlite"))
	require.NoError(t, err)
	cli := net.IPv4(10, 20, 0, 7)
	pkt := ethUDP(t, "00:1a:2b:3c:4d:5e", "ff:ff:ff:ff:ff:ff", cli, net.IPv4(10, 20, 0, 255), 137, 137,
		gopacket.Payload(hostidtest.NBNSRegistration("HMI01", 0x00, false, cli)))
	p := NewGopacketParser(writePCAP(t, []gopacket.Packet{pkt}), repo, "")
	cfg := DefaultIndustrialParserConfig()
	require.NoError(t, cfg.DisableProtocols([]string{"nbns"}))
	p.SetIndustrialConfig(cfg)
	require.NoError(t, p.ParseFile())

	devs, err := repo.GetDevices("", nil)
	require.NoError(t, err)
	for _, d := range devs {
		assert.NotContains(t, d.AdditionalData, "netbios")
		assert.Empty(t, d.Hostname)
	}
	flows, _ := repo.GetFlows("", nil)
	for _, f := range flows {
		assert.NotEqual(t, "nbns", f.Protocol)
	}
}

func TestObserveNBNSIgnoresEmptyNamesAndBoundsTheList(t *testing.T) {
	s := newHostEvidenceStore()
	names := []hostid.NBName{{Name: "", IP: "10.0.0.1"}}
	for i := 0; i < maxNetBIOSNamesPerHost+10; i++ {
		names = append(names, hostid.NBName{Name: fmt.Sprintf("HOST%03d", i), IP: "10.0.0.1"})
	}
	s.observeNBNS("10.0.0.9", hostid.NBNSMessage{Names: names})
	h := s.identity["10.0.0.1"]
	require.NotNil(t, h)
	assert.Len(t, h.netbios, maxNetBIOSNamesPerHost)
	assert.NotContains(t, h.netbios, "<00>", "the empty name must not be kept")
	assert.Nil(t, s.identity["10.0.0.9"], "a message without status describes no sender")
}
