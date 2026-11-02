// Package dumpcap is what the *_dump tools in scripts/ have in common: open a
// classic pcap given on the command line, walk its packets, and build the
// connection key and TCP segment the importer's trackers take.
package dumpcap

import (
	"fmt"
	"io"
	"os"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ForEachPacket calls fn for every packet of the pcap named by the only
// command-line argument, with the packet's 1-based number. It exits with
// status 2 on a wrong usage and 1 on an I/O error. tool is the command name
// for the usage line.
func ForEachPacket(tool string, fn func(n int, pkt gopacket.Packet)) {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s capture.pcap\n", tool)
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fail(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		fail(err)
	}
	for n := 1; ; n++ {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			return
		}
		if err != nil {
			fail(err)
		}
		fn(n, gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// Key identifies a connection the same way for both directions: the client
// endpoint first. request is true for a packet sent to the server.
func Key(src string, sport layers.TCPPort, dst string, dport layers.TCPPort, request bool) string {
	if request {
		return fmt.Sprintf("%s:%d|%s:%d", src, sport, dst, dport)
	}
	return fmt.Sprintf("%s:%d|%s:%d", dst, dport, src, sport)
}

// Segment is the part of a TCP layer a tracker needs.
func Segment(tcp *layers.TCP) detect.TCPSegment {
	return detect.TCPSegment{Seq: tcp.Seq, SYN: tcp.SYN, FIN: tcp.FIN, RST: tcp.RST, ACK: tcp.ACK, Payload: tcp.Payload}
}
