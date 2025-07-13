package parser

import (
	"bytes"
	"github.com/InfraSecConsult/pcap-importer-go/internal/testutil"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestGopacketParser_ParseFile_Empty(t *testing.T) {
	// Create an empty pcap file
	fname := "test_empty.pcap"
	f, err := os.Create(fname)
	if err != nil {
		t.Fatalf("failed to create temp pcap: %v", err)
	}
	f.Close()
	defer os.Remove(fname)

	parser := NewGopacketParser(fname)
	repo := &testutil.MockRepository{}
	err = parser.ParseFile(repo)
	if err == nil {
		t.Logf("ParseFile returned no error for empty file (expected for empty input)")
	}
}

func TestGopacketParser_ParseFile_ARP_ICMP(t *testing.T) {
	// Create a buffer with a single ARP and a single ICMP packet
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	// ARP packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1,
		SourceHwAddress:   []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SourceProtAddress: []byte{192, 168, 1, 1},
		DstHwAddress:      []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		DstProtAddress:    []byte{192, 168, 1, 2},
	}
	buf1 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf1, gopacket.SerializeOptions{}, eth, arp)
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(buf1.Bytes()), CaptureLength: len(buf1.Bytes())}, buf1.Bytes())

	// ICMP packet
	eth2 := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
	}
	buf2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf2, gopacket.SerializeOptions{}, eth2, ip, icmp)
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(buf2.Bytes()), CaptureLength: len(buf2.Bytes())}, buf2.Bytes())

	fname := "test_arp_icmp.pcap"
	file, err := os.Create(fname)
	if err != nil {
		t.Fatalf("failed to create temp pcap: %v", err)
	}
	file.Write(buf.Bytes())
	file.Close()
	defer os.Remove(fname)

	parser := NewGopacketParser(fname)
	repo := &testutil.MockRepository{}
	err = parser.ParseFile(repo)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	// No assertion here: this test ensures no panic and successful parsing of ARP/ICMP
}

func TestGopacketParser_ParseFile_TCP_UDP(t *testing.T) {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	// TCP packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{192, 168, 1, 20},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1,
		ACK:     0,
		SYN:     true,
	}
	buf1 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf1, gopacket.SerializeOptions{}, eth, ip, tcp)
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(buf1.Bytes()), CaptureLength: len(buf1.Bytes())}, buf1.Bytes())

	// UDP packet
	eth2 := &layers.Ethernet{
		SrcMAC:       []byte{0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
		DstMAC:       []byte{0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip2 := &layers.IPv4{
		SrcIP:    []byte{10, 1, 1, 1},
		DstIP:    []byte{10, 1, 1, 2},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 53,
		DstPort: 5353,
	}
	udp.SetNetworkLayerForChecksum(ip2)
	buf2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf2, gopacket.SerializeOptions{}, eth2, ip2, udp)
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(buf2.Bytes()), CaptureLength: len(buf2.Bytes())}, buf2.Bytes())

	fname := "test_tcp_udp.pcap"
	file, err := os.Create(fname)
	if err != nil {
		t.Fatalf("failed to create temp pcap: %v", err)
	}
	file.Write(buf.Bytes())
	file.Close()
	defer os.Remove(fname)

	parser := NewGopacketParser(fname)
	repo := &testutil.MockRepository{}
	err = parser.ParseFile(repo)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
}

func TestGopacketParser_ParseFile_DNS(t *testing.T) {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		DstMAC:       []byte{0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{8, 8, 8, 8},
		DstIP:    []byte{192, 168, 1, 100},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 53,
		DstPort: 12345,
	}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		QR:     true,
		OpCode: layers.DNSOpCodeQuery,
		AA:     true,
		RD:     true,
		RA:     true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
		ANCount: 1,
		Answers: []layers.DNSResourceRecord{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			IP:    []byte{93, 184, 216, 34},
		}},
	}
	buf1 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf1, gopacket.SerializeOptions{}, eth, ip, udp, dns)
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(buf1.Bytes()), CaptureLength: len(buf1.Bytes())}, buf1.Bytes())

	fname := "test_dns.pcap"
	file, err := os.Create(fname)
	if err != nil {
		t.Fatalf("failed to create temp pcap: %v", err)
	}
	file.Write(buf.Bytes())
	file.Close()
	defer os.Remove(fname)

	parser := NewGopacketParser(fname)
	repo := &testutil.MockRepository{}
	err = parser.ParseFile(repo)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
}

func TestGopacketParser_ParseFile_ErrorHandling(t *testing.T) {
	parser := NewGopacketParser("nonexistent.pcap")
	repo := &testutil.MockRepository{}
	err := parser.ParseFile(repo)
	if err == nil {
		t.Errorf("expected error for nonexistent file, got nil")
	}
}
