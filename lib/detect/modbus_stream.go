package detect

import "github.com/InfraSecConsult/pcap-importer-go/lib/tcpseq"

// ModbusTracker turns the TCP payloads of connections into Modbus messages.
//
// A connection becomes known as Modbus when a payload starts with a valid ADU
// header (the same test as the probe). From then on frames are decoded
// leniently, so a bad protocol id or length is an event and not silence, and
// a message split across segments is held until it is complete. The bytes of a
// partial message are kept per connection and direction (at most one ADU, 260
// bytes). Segments are taken in the order they arrive: retransmitted or
// reordered segments are not recognised, that needs real TCP reassembly.
// Before a connection is known, only a payload that is a valid ADU counts, so
// other traffic on the same port leaves no state.
//
// The set of connections is bounded. Past the limit new connections are
// decoded without state: a frame is recognised only if it is valid and nothing
// is carried to the next segment.
type ModbusTracker struct {
	max   int
	conns map[string]*modbusConn
}

type modbusConn struct {
	recognized bool
	// partial holds the unfinished bytes per direction: [0] server to client,
	// [1] client to server.
	partial [2][]byte
	// streams order the segments of each direction, see FeedTCP.
	streams [2]tcpseq.Stream
	fin     [2]bool
}

const defaultModbusTrackerLimit = 200_000

// NewModbusTracker returns a tracker with the default connection limit.
func NewModbusTracker() *ModbusTracker { return NewModbusTrackerLimit(defaultModbusTrackerLimit) }

// NewModbusTrackerLimit returns a tracker that keeps state for at most max
// connections.
func NewModbusTrackerLimit(max int) *ModbusTracker {
	return &ModbusTracker{max: max, conns: make(map[string]*modbusConn)}
}

// Len is the number of connections with state.
func (t *ModbusTracker) Len() int { return len(t.conns) }

// Known reports whether payload on the connection has been recognised as Modbus.
func (t *ModbusTracker) Known(key string) bool {
	c := t.conns[key]
	return c != nil && c.recognized
}

// TCPSegment is what the tracker needs of a TCP segment.
type TCPSegment struct {
	Seq                uint32
	SYN, FIN, RST, ACK bool
	Payload            []byte
}

// FeedTCP is Feed for a TCP segment with its sequence number and flags. Bytes
// seen before (retransmissions, overlaps) are dropped, segments that arrive
// early are held until the gap closes (see package tcpseq), and RST, a closing
// FIN exchange or a new SYN on the same ports end the connection's state. A
// connection first seen mid-stream is taken as it comes.
func (t *ModbusTracker) FeedTCP(key string, toServer bool, seg TCPSegment, hint bool) []ModbusMessage {
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
			c.partial[dir] = nil // the rest of a half message is lost
		}
		payload = data
	}
	var out []ModbusMessage
	if len(payload) > 0 {
		out = t.Feed(key, toServer, payload, hint)
	}
	if c == nil {
		// Feed may have just recognised the connection: fix the position.
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

// Feed adds the payload of one TCP segment and returns the messages it
// completes. key identifies the connection and must be the same for both
// directions. toServer is true for client to server. hint says the connection
// uses the Modbus port, which allows a first segment shorter than a header to
// be kept until the rest arrives.
func (t *ModbusTracker) Feed(key string, toServer bool, payload []byte, hint bool) []ModbusMessage {
	dir := 0
	if toServer {
		dir = 1
	}
	c := t.conns[key]
	buf := payload
	if c != nil && len(c.partial[dir]) > 0 {
		buf = append(append(make([]byte, 0, len(c.partial[dir])+len(payload)), c.partial[dir]...), payload...)
	}
	if len(buf) == 0 {
		return nil
	}

	recognized := c != nil && c.recognized
	if !recognized {
		if len(buf) < ModbusMBAPLen+1 {
			if hint {
				t.keep(key, &c, dir, buf, false)
			}
			return nil
		}
		if _, ok := ModbusADUSize(buf); !ok {
			if c != nil {
				c.partial[dir] = nil
			}
			return nil
		}
		recognized = true
	}

	var out []ModbusMessage
	for len(buf) > 0 {
		size, complete := modbusFrameSize(buf)
		if !complete {
			break
		}
		m, ok := DecodeModbusADU(buf[:size], toServer)
		if !ok {
			break
		}
		out = append(out, m)
		buf = buf[size:]
	}
	t.keep(key, &c, dir, buf, recognized)
	return out
}

// keep stores the unfinished bytes of a direction and the recognised flag. A
// connection with nothing to remember is not given an entry.
func (t *ModbusTracker) keep(key string, c **modbusConn, dir int, rest []byte, recognized bool) {
	if *c == nil {
		if !recognized && len(rest) == 0 {
			return
		}
		if len(t.conns) >= t.max {
			return
		}
		*c = &modbusConn{}
		t.conns[key] = *c
	}
	if recognized {
		(*c).recognized = true
	}
	if len(rest) == 0 || len(rest) > ModbusMaxADULen {
		(*c).partial[dir] = nil
		return
	}
	(*c).partial[dir] = append([]byte(nil), rest...)
}
