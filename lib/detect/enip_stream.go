package detect

import "github.com/InfraSecConsult/pcap-importer-go/lib/tcpseq"

// ENIPTracker turns the TCP payloads of connections into EtherNet/IP
// encapsulation messages, the way ModbusTracker does for Modbus.
//
// A connection becomes known when a payload starts with a message the strict
// probe (ProbeENIPEncapsulation) recognises. From then on every message is
// framed by the length field alone, so any command is decoded and a message
// split across segments is held until it is complete. Segments are ordered by
// TCP sequence number (package tcpseq). When bytes were lost for good, the
// half message is dropped and, as in Suricata, the next data must pass the
// probe again before parsing resumes.
//
// State is kept only for recognised connections (and a short unrecognised
// start on the ENIP port), and for at most the configured number of them.
type ENIPTracker struct {
	max   int
	conns map[string]*enipConn
}

type enipConn struct {
	recognized bool
	needProbe  [2]bool // after a gap, per direction: [0] server to client, [1] client to server
	partial    [2][]byte
	streams    [2]tcpseq.Stream
	fin        [2]bool
}

// enipMaxPDU is the largest message: the header and a 16-bit length.
const enipMaxPDU = ENIPHeaderLen + 0xffff

// NewENIPTracker returns a tracker with the default connection limit.
func NewENIPTracker() *ENIPTracker { return NewENIPTrackerLimit(defaultModbusTrackerLimit) }

// NewENIPTrackerLimit returns a tracker that keeps state for at most max connections.
func NewENIPTrackerLimit(max int) *ENIPTracker {
	return &ENIPTracker{max: max, conns: make(map[string]*enipConn)}
}

// Len is the number of connections with state.
func (t *ENIPTracker) Len() int { return len(t.conns) }

// Known reports whether the connection has been recognised as EtherNet/IP.
func (t *ENIPTracker) Known(key string) bool {
	c := t.conns[key]
	return c != nil && c.recognized
}

// FeedTCP adds a TCP segment and returns the messages it completes. key must be
// the same for both directions; toServer is true for client to server; hint
// says the connection uses the EtherNet/IP port, which allows a first segment
// shorter than a header to be kept until the rest arrives.
func (t *ENIPTracker) FeedTCP(key string, toServer bool, seg TCPSegment, hint bool) []ENIPMessage {
	dir := 0
	if toServer {
		dir = 1
	}
	if seg.RST || (seg.SYN && !seg.ACK) {
		delete(t.conns, key)
		if seg.RST {
			return nil
		}
	}
	payload := seg.Payload
	c := t.conns[key]
	if c != nil {
		data, gap := c.streams[dir].Push(seg.Seq, seg.SYN, payload)
		if gap {
			c.partial[dir] = nil
			c.needProbe[dir] = true
		}
		payload = data
	}
	var out []ENIPMessage
	if len(payload) > 0 {
		out = t.feed(key, dir, payload, hint)
	}
	if c == nil {
		if c = t.conns[key]; c != nil {
			c.streams[dir].Push(seg.Seq, seg.SYN, seg.Payload)
		}
	}
	if seg.FIN && c != nil {
		c.fin[dir] = true
		if c.fin[0] && c.fin[1] {
			delete(t.conns, key)
		}
	}
	return out
}

func (t *ENIPTracker) feed(key string, dir int, payload []byte, hint bool) []ENIPMessage {
	c := t.conns[key]
	buf := payload
	if c != nil && len(c.partial[dir]) > 0 {
		buf = append(append(make([]byte, 0, len(c.partial[dir])+len(payload)), c.partial[dir]...), payload...)
	}
	if len(buf) == 0 {
		return nil
	}
	recognized := c != nil && c.recognized
	probeFirst := !recognized || (c != nil && c.needProbe[dir])
	if probeFirst {
		switch ProbeENIPEncapsulation(buf) {
		case Incomplete:
			if hint {
				t.keep(key, &c, dir, buf, recognized)
			}
			return nil
		case Unrecognized:
			if c != nil {
				c.partial[dir] = nil
			}
			return nil
		}
		recognized = true
		if c != nil {
			c.needProbe[dir] = false
		}
	}

	var out []ENIPMessage
	for len(buf) > 0 {
		m, n, ok := DecodeENIP(buf)
		if !ok {
			break
		}
		out = append(out, m)
		buf = buf[n:]
	}
	t.keep(key, &c, dir, buf, recognized)
	return out
}

func (t *ENIPTracker) keep(key string, c **enipConn, dir int, rest []byte, recognized bool) {
	if *c == nil {
		if !recognized && len(rest) == 0 {
			return
		}
		if len(t.conns) >= t.max {
			return
		}
		*c = &enipConn{}
		t.conns[key] = *c
	}
	if recognized {
		(*c).recognized = true
	}
	if len(rest) == 0 || len(rest) > enipMaxPDU {
		(*c).partial[dir] = nil
		return
	}
	(*c).partial[dir] = append([]byte(nil), rest...)
}

// DecodeENIPDatagram decodes the message in a UDP datagram. A datagram stands
// alone, so the strict probe decides; bytes after the message are ignored. It
// returns false for anything that is not a complete encapsulation message.
func DecodeENIPDatagram(b []byte) (ENIPMessage, bool) {
	if ProbeENIPEncapsulation(b) != Recognized {
		return ENIPMessage{}, false
	}
	m, _, ok := DecodeENIP(b)
	return m, ok
}
