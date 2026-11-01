package parser

import (
	"fmt"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func tcpPkt(t *testing.T, src, dst uint16, payload []byte, syn bool) (label func(l *connectionLabeler) string) {
	pkt := buildTransportPacket(t, &layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst), SYN: syn, ACK: !syn}, nil, payload)
	// The client is 10.0.0.1 and uses the high port; a packet from the lower
	// port is the server's reply, so the addresses swap with the ports.
	srcIP, dstIP := "10.0.0.1", "10.0.0.2"
	if src < dst {
		srcIP, dstIP = dstIP, srcIP
	}
	return func(l *connectionLabeler) string { return l.Label(pkt, srcIP, dstIP, model.VLANTag{}) }
}

func TestConnectionLabeler_TCP(t *testing.T) {
	const enipTCP = "EtherNet/IP(TCP)"
	list := enipEncap(0x63, 0, nil)

	t.Run("handshake on the port keeps the label, so the connection is one flow", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		assert.Equal(t, enipTCP, tcpPkt(t, 50000, 44818, nil, true)(l))
		assert.Equal(t, enipTCP, tcpPkt(t, 44818, 50000, nil, true)(l))
		assert.Equal(t, enipTCP, tcpPkt(t, 50000, 44818, list, false)(l))
		assert.Equal(t, enipTCP, tcpPkt(t, 50000, 44818, nil, false)(l), "ACK after recognition")
	})

	t.Run("mid-message segment after recognition keeps the label", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		tcpPkt(t, 50000, 44818, list, false)(l)
		// Not a message start: without reassembly this looks like garbage.
		assert.Equal(t, enipTCP, tcpPkt(t, 50000, 44818, []byte("continuation of a long message....."), false)(l))
	})

	t.Run("payload that is not ENIP vetoes the hint, permanently", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		assert.Equal(t, enipTCP, tcpPkt(t, 50000, 44818, nil, true)(l), "before any payload the hint applies")
		assert.Equal(t, "", tcpPkt(t, 50000, 44818, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n.."), false)(l))
		assert.Equal(t, "", tcpPkt(t, 44818, 50000, nil, false)(l), "veto sticks for later empty segments")
		// A later valid-looking message still wins: recognition is evidence.
		assert.Equal(t, enipTCP, tcpPkt(t, 50000, 44818, list, false)(l))
	})

	t.Run("content on another port labels from recognition on", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		assert.Equal(t, "", tcpPkt(t, 50000, 50001, nil, true)(l))
		assert.Equal(t, enipTCP, tcpPkt(t, 50000, 50001, list, false)(l))
		assert.Equal(t, enipTCP, tcpPkt(t, 50001, 50000, nil, false)(l))
	})

	t.Run("unrelated traffic creates no state", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		for i := 0; i < 50; i++ {
			assert.Equal(t, "", tcpPkt(t, uint16(40000+i), 80, []byte("GET / HTTP/1.1\r\n\r\n"), false)(l))
		}
		assert.Empty(t, l.conns)
	})

	t.Run("connections are independent", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		tcpPkt(t, 50000, 44818, []byte("not enip, but long enough to be checked"), false)(l)
		assert.Equal(t, enipTCP, tcpPkt(t, 50001, 44818, nil, true)(l), "other connection is not vetoed")
	})

	t.Run("VLAN separates identical endpoint pairs", func(t *testing.T) {
		l := newConnectionLabeler(detect.Default())
		one, two := 10, 20
		a := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, ACK: true}, nil, []byte("garbage that is long enough"))
		b := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, SYN: true}, nil, nil)
		assert.Equal(t, "", l.Label(a, "10.0.0.1", "10.0.0.2", model.VLANTag{Outer: &one}))
		assert.Equal(t, enipTCP, l.Label(b, "10.0.0.1", "10.0.0.2", model.VLANTag{Outer: &two}))
	})
}

func TestConnectionLabeler_UDPImplicitIO(t *testing.T) {
	implicit := []byte{0x02, 0x00, 0x02, 0x80, 0x08, 0x00, 0x05, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb1, 0x00, 0x02, 0x00, 0x01, 0x00}
	l := newConnectionLabeler(detect.Default())
	pkt := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 2222, DstPort: 2222}, implicit)
	assert.Equal(t, "EtherNet/IP(UDP)", l.Label(pkt, "10.0.0.1", "10.0.0.2", model.VLANTag{}))
	junk := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 2222, DstPort: 2222}, []byte("not cip at all"))
	l2 := newConnectionLabeler(detect.Default())
	assert.Equal(t, "", l2.Label(junk, "10.0.0.1", "10.0.0.2", model.VLANTag{}))
}

func TestConnectionLabeler_Cap(t *testing.T) {
	l := newConnectionLabeler(detect.Default())
	for i := 0; i < maxTrackedConnections; i++ {
		l.conns[fmt.Sprintf("filler-%d", i)] = &connState{}
	}
	before := len(l.conns)
	pkt := buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 44818, SYN: true}, nil, nil)
	assert.Equal(t, "EtherNet/IP(TCP)", l.Label(pkt, "10.0.0.1", "10.0.0.2", model.VLANTag{}), "still labelled per packet")
	assert.Equal(t, before, len(l.conns), "no growth past the cap")
}

func TestConnectionLabeler_S7Plus(t *testing.T) {
	d := []byte{0x31, 0, 0, 0x04, 0xbb, 0, 0, 0, 5, 0, 0, 0, 9, 0x34, 0}
	pdu := append(append([]byte{0x72, 1, 0, byte(len(d))}, d...), 0x72, 1, 0, 0)
	frame := append([]byte{3, 0, 0, byte(7 + len(pdu)), 2, 0xf0, 0x80}, pdu...)

	l := newConnectionLabeler(detect.Default())
	assert.Equal(t, "s7commplus", tcpPkt(t, 50000, 102, frame, false)(l))
	assert.Equal(t, "s7commplus", tcpPkt(t, 50000, 102, nil, false)(l), "label sticks")

	// Classic S7comm on the same port is still s7.
	s7 := []byte{3, 0, 0, 25, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 0xf0, 0, 0, 1, 0, 1, 1, 0xe0}
	l2 := newConnectionLabeler(detect.Default())
	assert.Equal(t, "s7", tcpPkt(t, 50001, 102, s7, false)(l2))
}
