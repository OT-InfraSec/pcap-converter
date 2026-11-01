package detect

import "github.com/InfraSecConsult/pcap-importer-go/lib/tcpseq"

// S7Tracker turns the TCP payloads of connections into S7comm messages, as
// ModbusTracker and ENIPTracker do for their protocols: segments are ordered by
// sequence number (package tcpseq), frames are cut by the TPKT length, and a
// frame split across segments is held until complete.
//
// A connection becomes known when a payload is an S7 PDU (ProbeS7), or, on the
// ISO-TSAP port, a COTP connection request or confirmation: port 102 has other
// users, so those frames are returned (they carry the rack and slot) but the
// message has no S7 PDU until a data TPDU shows the S7 protocol id. The rack and
// slot of the last connection request are attached to the later S7 messages of
// the connection. Segmented COTP data (no EOT bit) is joined into one PDU.
//
// An invalid TPKT header, or bytes lost for good, drops the half frame and the
// direction must show a valid start again before parsing resumes.
type S7Tracker struct {
	max   int
	conns map[string]*s7Conn
}

type s7Conn struct {
	recognized bool
	needProbe  [2]bool
	partial    [2][]byte
	frags      [2][]S7Frame // COTP data fragments waiting for the EOT frame
	fragBytes  [2]int
	streams    [2]tcpseq.Stream
	fin        [2]bool
	rack, slot int
	haveRack   bool
	sawS7      bool // an S7 PDU was seen: the connection is S7, not only ISO-TSAP
}

const (
	maxS7Frags     = 64
	maxS7FragBytes = 256 * 1024
)

// NewS7Tracker returns a tracker with the default connection limit.
func NewS7Tracker() *S7Tracker { return NewS7TrackerLimit(defaultModbusTrackerLimit) }

// NewS7TrackerLimit returns a tracker that keeps state for at most max connections.
func NewS7TrackerLimit(max int) *S7Tracker {
	return &S7Tracker{max: max, conns: make(map[string]*s7Conn)}
}

// Len is the number of connections with state.
func (t *S7Tracker) Len() int { return len(t.conns) }

// Known reports whether the connection has been recognised as ISO-on-TCP with S7.
func (t *S7Tracker) Known(key string) bool {
	c := t.conns[key]
	return c != nil && c.recognized
}

// SawS7 reports whether an S7 PDU has been seen on the connection, which tells
// an S7 connection from a bare ISO-TSAP one (a connection request alone).
func (t *S7Tracker) SawS7(key string) bool {
	c := t.conns[key]
	return c != nil && c.sawS7
}

// FeedTCP adds a TCP segment and returns the messages it completes. key must be
// the same for both directions; toServer is true for client to server; hint
// says the connection uses port 102.
func (t *S7Tracker) FeedTCP(key string, toServer bool, seg TCPSegment, hint bool) []S7Message {
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
			c.partial[dir], c.frags[dir], c.fragBytes[dir] = nil, nil, 0
			c.needProbe[dir] = true
		}
		payload = data
	}
	var out []S7Message
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

// startsConnection reports whether buf may begin an ISO-on-TCP connection that
// is worth following: an S7 PDU, or on port 102 a COTP connection frame.
func startsS7(buf []byte, hint bool) Result {
	switch ProbeS7(buf) {
	case Recognized:
		return Recognized
	case Unrecognized:
		return Unrecognized
	}
	if !hint {
		return Unrecognized
	}
	if f, _, ok := ParseS7Frame(buf); ok && (f.COTPType == cotpCR || f.COTPType == cotpCC) && len(f.Events) == 0 {
		return Recognized
	}
	return Incomplete
}

func (t *S7Tracker) feed(key string, dir int, payload []byte, hint bool) []S7Message {
	c := t.conns[key]
	buf := payload
	if c != nil && len(c.partial[dir]) > 0 {
		buf = append(append(make([]byte, 0, len(c.partial[dir])+len(payload)), c.partial[dir]...), payload...)
	}
	if len(buf) == 0 {
		return nil
	}
	recognized := c != nil && c.recognized
	if !recognized || (c != nil && c.needProbe[dir]) {
		switch startsS7(buf, hint) {
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
	if c == nil {
		t.keep(key, &c, dir, nil, true) // create the entry so rack, slot and fragments have a home
	}

	var out []S7Message
	for len(buf) > 0 {
		if size := S7FrameSize(buf); size < 0 {
			// Not TPKT: the stream is out of step.
			buf = nil
			if c != nil {
				c.needProbe[dir] = true
				c.frags[dir], c.fragBytes[dir] = nil, 0
			}
			break
		}
		f, n, ok := ParseS7Frame(buf)
		if !ok {
			break
		}
		buf = buf[n:]
		if m, done := t.frame(c, dir, f); done {
			out = append(out, m)
		}
	}
	t.keep(key, &c, dir, buf, recognized)
	return out
}

// frame handles one parsed frame: it joins COTP data fragments and returns the
// message when one is complete.
func (t *S7Tracker) frame(c *s7Conn, dir int, f S7Frame) (S7Message, bool) {
	if c == nil { // over the connection limit: no fragments, no rack and slot
		if f.COTPType == cotpDT && !f.EOT {
			return S7Message{}, false
		}
		return MessageFromFrames([]S7Frame{f}), true
	}
	if f.COTPType == cotpDT && !f.EOT && len(f.Events) == 0 {
		if len(c.frags[dir]) >= maxS7Frags || c.fragBytes[dir]+len(f.Payload) > maxS7FragBytes {
			c.frags[dir], c.fragBytes[dir] = nil, 0
			return S7Message{}, false
		}
		c.frags[dir] = append(c.frags[dir], f)
		c.fragBytes[dir] += len(f.Payload)
		return S7Message{}, false
	}
	frames := append(c.frags[dir], f)
	if f.COTPType != cotpDT {
		frames = []S7Frame{f} // a connection frame cuts off pending data
	}
	c.frags[dir], c.fragBytes[dir] = nil, 0
	m := MessageFromFrames(frames)
	if m.HasS7 {
		c.sawS7 = true
	}
	switch {
	case m.Rack >= 0 && (f.COTPType == cotpCR || f.COTPType == cotpCC):
		c.rack, c.slot, c.haveRack = m.Rack, m.Slot, true
	case m.HasS7 && m.Rack < 0 && c.haveRack:
		m.Rack, m.Slot = c.rack, c.slot
	}
	return m, true
}

func (t *S7Tracker) keep(key string, c **s7Conn, dir int, rest []byte, recognized bool) {
	if *c == nil {
		if !recognized && len(rest) == 0 {
			return
		}
		if len(t.conns) >= t.max {
			return
		}
		*c = &s7Conn{}
		t.conns[key] = *c
	}
	if recognized {
		(*c).recognized = true
	}
	if len(rest) == 0 || len(rest) > 0xffff {
		(*c).partial[dir] = nil
		return
	}
	(*c).partial[dir] = append([]byte(nil), rest...)
}
