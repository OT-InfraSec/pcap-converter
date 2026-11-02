package parser

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func opt(t layers.DHCPOpt, data ...byte) layers.DHCPOption {
	return layers.DHCPOption{Type: t, Length: uint8(len(data)), Data: data}
}

func dhcpPacket(op layers.DHCPOp, ciaddr, yiaddr net.IP, options ...layers.DHCPOption) *layers.DHCPv4 {
	return &layers.DHCPv4{
		Operation: op, HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: net.HardwareAddr{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
		ClientIP:     ciaddr, YourClientIP: yiaddr, Options: options,
	}
}

func TestDHCPv4ClientEvidence(t *testing.T) {
	zero := net.IPv4zero
	t.Run("a request says what the client is", func(t *testing.T) {
		d := dhcpPacket(layers.DHCPOpRequest, zero, zero,
			opt(layers.DHCPOptHostname, []byte("plc-line3\x00")...),
			opt(layers.DHCPOptClassID, []byte("MSFT 5.0")...),
			opt(layers.DHCPOptParamsRequest, 1, 3, 6, 15, 119),
			opt(layers.DHCPOptRequestIP, 10, 20, 0, 7),
		)
		e, ok := dhcpv4ClientEvidence(d)
		require.True(t, ok)
		assert.Equal(t, dhcpClientEvidence{
			MAC: "00:1a:2b:3c:4d:5e", IP: "10.20.0.7", Hostname: "plc-line3",
			VendorClass: "MSFT 5.0", ParamList: "1,3,6,15,119",
		}, e)
	})
	t.Run("ciaddr wins over the requested address", func(t *testing.T) {
		d := dhcpPacket(layers.DHCPOpRequest, net.IPv4(10, 20, 0, 9), zero, opt(layers.DHCPOptRequestIP, 10, 20, 0, 7))
		e, _ := dhcpv4ClientEvidence(d)
		assert.Equal(t, "10.20.0.9", e.IP)
	})
	t.Run("a reply gives the binding and lease, not the server's options", func(t *testing.T) {
		d := dhcpPacket(layers.DHCPOpReply, zero, net.IPv4(10, 20, 0, 7),
			opt(layers.DHCPOptLeaseTime, 0, 0, 0x0e, 0x10),
			opt(layers.DHCPOptHostname, []byte("dhcp-server")...),
			opt(layers.DHCPOptClassID, []byte("server-class")...),
		)
		e, ok := dhcpv4ClientEvidence(d)
		require.True(t, ok)
		assert.Equal(t, dhcpClientEvidence{MAC: "00:1a:2b:3c:4d:5e", IP: "10.20.0.7", LeaseSeconds: 3600}, e)
	})
	t.Run("unusable addresses are not evidence", func(t *testing.T) {
		for _, ip := range []net.IP{net.IPv4zero, net.IPv4bcast, net.IPv4(224, 0, 0, 1)} {
			e, _ := dhcpv4ClientEvidence(dhcpPacket(layers.DHCPOpReply, zero, ip))
			assert.Equal(t, "", e.IP, ip.String())
		}
	})
	t.Run("hostile strings are dropped whole", func(t *testing.T) {
		long := make([]byte, 256)
		for i := range long {
			long[i] = 'a'
		}
		d := dhcpPacket(layers.DHCPOpRequest, zero, zero,
			opt(layers.DHCPOptHostname, 'a', 0x07, 'b'), // control byte
			opt(layers.DHCPOptClassID, 0xff, 0xfe),      // not ASCII
		)
		e, _ := dhcpv4ClientEvidence(d)
		assert.Equal(t, "", e.Hostname)
		assert.Equal(t, "", e.VendorClass)
		assert.Equal(t, "", cleanHostString(long, maxHostString))
		assert.Equal(t, "", cleanHostString([]byte("\x00\x00"), maxHostString))
	})
	t.Run("no hardware address, no evidence", func(t *testing.T) {
		d := dhcpPacket(layers.DHCPOpRequest, zero, zero)
		d.ClientHWAddr = nil
		_, ok := dhcpv4ClientEvidence(d)
		assert.False(t, ok)
		_, ok = dhcpv4ClientEvidence(nil)
		assert.False(t, ok)
	})
	t.Run("short option data does not panic", func(t *testing.T) {
		d := dhcpPacket(layers.DHCPOpReply, zero, zero, opt(layers.DHCPOptLeaseTime, 1, 2), opt(layers.DHCPOptRequestIP, 1))
		_, ok := dhcpv4ClientEvidence(d)
		assert.True(t, ok)
		d.Operation = layers.DHCPOpRequest
		e, _ := dhcpv4ClientEvidence(d)
		assert.Equal(t, "", e.IP)
	})
}

func TestClientFQDN(t *testing.T) {
	wire := []byte{0x04, 0, 0, 3, 'p', 'l', 'c', 5, 'p', 'l', 'a', 'n', 't', 0} // E flag: DNS wire format
	assert.Equal(t, "plc.plant", clientFQDN(wire))
	ascii := append([]byte{0x00, 0, 0}, []byte("plc.plant.example")...)
	assert.Equal(t, "plc.plant.example", clientFQDN(ascii))

	for name, b := range map[string][]byte{
		"too short":          {0x04, 0},
		"label overruns":     {0x04, 0, 0, 9, 'a'},
		"compression":        {0x04, 0, 0, 0xc0, 0x0c},
		"control in a label": {0x04, 0, 0, 2, 'a', 0x01, 0},
	} {
		assert.Equal(t, "", clientFQDN(b), name)
	}
}

func llmnrMessage(t *testing.T, d layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}))
	return buf.Bytes()
}

func TestLLMNRResponses(t *testing.T) {
	answer := func(name string, ip net.IP) layers.DNSResourceRecord {
		typ := layers.DNSTypeA
		if ip.To4() == nil {
			typ = layers.DNSTypeAAAA
		}
		return layers.DNSResourceRecord{Name: []byte(name), Type: typ, Class: layers.DNSClassIN, TTL: 30, IP: ip}
	}
	question := layers.DNSQuestion{Name: []byte("hmi01"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}

	t.Run("a response names the owner of an address", func(t *testing.T) {
		msg := llmnrMessage(t, layers.DNS{QR: true, Questions: []layers.DNSQuestion{question},
			Answers: []layers.DNSResourceRecord{answer("hmi01", net.IPv4(10, 20, 0, 5)), answer("hmi01", net.ParseIP("fe80::1"))}})
		assert.Equal(t, []llmnrHost{{"hmi01", "10.20.0.5"}, {"hmi01", "fe80::1"}}, llmnrResponses(msg))
	})
	t.Run("a query yields nothing", func(t *testing.T) {
		// Even a query that carries an answer record says nothing about who owns the name.
		msg := llmnrMessage(t, layers.DNS{QR: false, Questions: []layers.DNSQuestion{question},
			Answers: []layers.DNSResourceRecord{answer("hmi01", net.IPv4(10, 20, 0, 5))}})
		assert.Empty(t, llmnrResponses(msg))
	})
	t.Run("an error response yields nothing", func(t *testing.T) {
		msg := llmnrMessage(t, layers.DNS{QR: true, ResponseCode: layers.DNSResponseCodeNXDomain, Questions: []layers.DNSQuestion{question}})
		assert.Empty(t, llmnrResponses(msg))
	})
	t.Run("an unusable address or name is skipped", func(t *testing.T) {
		msg := llmnrMessage(t, layers.DNS{QR: true, Answers: []layers.DNSResourceRecord{
			answer("hmi01", net.IPv4zero), answer("hmi01", net.IPv4(224, 0, 0, 252)), answer("bad\x07name", net.IPv4(10, 0, 0, 1))}})
		assert.Empty(t, llmnrResponses(msg))
	})
	t.Run("garbage does not panic", func(t *testing.T) {
		for _, b := range [][]byte{nil, {1, 2, 3}, make([]byte, 12), {0, 0, 0x80, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0xc0, 0x0c}} {
			assert.NotPanics(t, func() { llmnrResponses(b) })
		}
	})
}

func ethUDP(t *testing.T, srcMAC, dstMAC string, srcIP, dstIP net.IP, sport, dport uint16, payload gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	sm, err := net.ParseMAC(srcMAC)
	require.NoError(t, err)
	dm, err := net.ParseMAC(dstMAC)
	require.NoError(t, err)
	eth := &layers.Ethernet{SrcMAC: sm, DstMAC: dm, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, payload))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// DHCP and LLMNR evidence reaches the saved devices, and LLMNR traffic is
// labelled as its own protocol.
func TestHostEvidenceReachesDevices(t *testing.T) {
	repo, err := repository.NewSQLiteRepository(filepath.Join(t.TempDir(), "db.sqlite"))
	require.NoError(t, err)

	const clientMAC, serverMAC, otherMAC = "00:1a:2b:3c:4d:5e", "00:00:00:00:00:01", "00:1a:2b:3c:4d:09"
	client, server, other := net.IPv4(10, 20, 0, 7), net.IPv4(10, 20, 0, 1), net.IPv4(10, 20, 0, 9)
	hw, _ := net.ParseMAC(clientMAC)
	dhcpOf := func(op layers.DHCPOp, yi net.IP, o ...layers.DHCPOption) *layers.DHCPv4 {
		return &layers.DHCPv4{Operation: op, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, ClientHWAddr: hw, YourClientIP: yi, Options: o}
	}
	request := dhcpOf(layers.DHCPOpRequest, net.IPv4zero,
		opt(layers.DHCPOptMessageType, byte(layers.DHCPMsgTypeRequest)),
		opt(layers.DHCPOptHostname, []byte("plc-line3")...),
		opt(layers.DHCPOptClassID, []byte("MSFT 5.0")...),
		opt(layers.DHCPOptParamsRequest, 1, 3, 6, 15),
		opt(layers.DHCPOptRequestIP, 10, 20, 0, 7))
	ack := dhcpOf(layers.DHCPOpReply, client,
		opt(layers.DHCPOptMessageType, byte(layers.DHCPMsgTypeAck)),
		opt(layers.DHCPOptLeaseTime, 0, 0, 0x0e, 0x10))

	bcast := "ff:ff:ff:ff:ff:ff"
	llmnrMcast := "01:00:5e:00:00:fc"
	hmi := layers.DNSQuestion{Name: []byte("hmi01"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	pkts := []gopacket.Packet{
		ethUDP(t, clientMAC, bcast, net.IPv4zero, net.IPv4bcast, 68, 67, request),
		ethUDP(t, serverMAC, bcast, server, net.IPv4bcast, 67, 68, ack),
		// The client talks as 10.20.0.7, so a device with that address exists.
		ethUDP(t, clientMAC, serverMAC, client, server, 40000, 40001, gopacket.Payload("x")),
		ethUDP(t, clientMAC, llmnrMcast, client, net.IPv4(224, 0, 0, 252), 50000, 5355, &layers.DNS{ID: 1, Questions: []layers.DNSQuestion{hmi}}),
		ethUDP(t, otherMAC, clientMAC, other, client, 5355, 50000, &layers.DNS{ID: 1, QR: true, Questions: []layers.DNSQuestion{hmi},
			Answers: []layers.DNSResourceRecord{{Name: []byte("hmi01"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 30, IP: other}}}),
	}
	require.NoError(t, NewGopacketParser(writePCAP(t, pkts), repo, "").ParseFile())

	devs, err := repo.GetDevices("", nil)
	require.NoError(t, err)
	byIP := map[string]*model.Device{}
	for _, d := range devs {
		byIP[d.Address] = d
	}

	c := byIP["10.20.0.7"]
	require.NotNil(t, c, "client device")
	assert.Equal(t, "plc-line3", c.Hostname)
	var data map[string]map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(c.AdditionalData), &data))
	assert.Equal(t, map[string]interface{}{
		"mac": clientMAC, "hostname": "plc-line3", "vendor_class": "MSFT 5.0",
		"param_request_list": "1,3,6,15", "lease_seconds": float64(3600),
	}, data["dhcp"])

	o := byIP["10.20.0.9"]
	require.NotNil(t, o, "LLMNR responder device")
	assert.Contains(t, o.AdditionalData, `"dnsNames":["hmi01"]`)
	assert.Empty(t, o.Hostname, "an LLMNR name is a DNS name, not a DHCP hostname")

	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	var llmnr, dhcp int
	for _, f := range flows {
		switch f.Protocol {
		case "llmnr":
			llmnr++
		case "dhcpv4":
			dhcp++
		}
	}
	assert.Equal(t, 2, llmnr, "the query and the response are LLMNR flows")
	assert.Positive(t, dhcp)
}
