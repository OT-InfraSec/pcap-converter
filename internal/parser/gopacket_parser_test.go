package parser

import (
	"bytes"
	"os"
	"pcap-importer-golang/internal/testutil"
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
