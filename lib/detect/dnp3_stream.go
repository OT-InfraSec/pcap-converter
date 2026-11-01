package detect

// DNP3Tracker turns the payloads of DNP3 connections into link frames and
// application fragments, as the Modbus, ENIP and S7 trackers do for their
// protocols. Frames are cut by the link length field; segments are ordered by
// TCP sequence number (package tcpseq); the transport segments of one
// application fragment (FIR to FIN, sequence numbers counting modulo 64) are
// joined per direction, and the fragment is decoded when the FIN segment
// arrives.
//
// A connection becomes known when a payload starts with the link start bytes
// and a valid length (ProbeDNP3). Bytes that do not start a frame, or bytes
// lost for good, drop the half frame and the pending fragment; the direction
// must show a frame start again before parsing resumes.
type DNP3Tracker struct {
	tcpTracker[*dnp3Conn, DNP3Message]
}

type dnp3Reasm struct {
	active  bool
	seq     byte
	data    []byte
	tooLong bool
}

type dnp3Conn struct {
	tcpConn
	reasm [2]dnp3Reasm
}

func (c *dnp3Conn) resetPending(dir int) { c.reasm[dir] = dnp3Reasm{} }

// NewDNP3Tracker returns a tracker with the default connection limit.
func NewDNP3Tracker() *DNP3Tracker { return NewDNP3TrackerLimit(defaultTrackerLimit) }

// NewDNP3TrackerLimit returns a tracker that keeps state for at most max connections.
func NewDNP3TrackerLimit(max int) *DNP3Tracker {
	return &DNP3Tracker{newTCPTracker[*dnp3Conn, DNP3Message](max, dnp3MaxFrame, func() *dnp3Conn { return &dnp3Conn{} })}
}

// FeedTCP adds a TCP segment and returns the messages it completes. key must be
// the same for both directions; toServer is true for client to server; hint
// says the connection uses the DNP3 port, which lets a first segment shorter
// than a frame header be kept until the rest arrives.
func (t *DNP3Tracker) FeedTCP(key string, toServer bool, seg TCPSegment, hint bool) []DNP3Message {
	return t.feedTCP(key, toServer, seg, hint, t.feed)
}

// DecodeDNP3Datagram decodes the link frames of a UDP datagram. A datagram stands
// alone: the probe decides, fragments are joined only within it, and bytes that
// are not a whole frame are ignored.
func DecodeDNP3Datagram(b []byte) []DNP3Message {
	if ProbeDNP3(b) != Recognized {
		return nil
	}
	var c dnp3Conn
	var out []DNP3Message
	for len(b) > 0 {
		f, n, ok := ParseDNP3Frame(b)
		if !ok {
			break
		}
		b = b[n:]
		if f.Invalid {
			out = append(out, DNP3Message{Frame: f, Events: f.Events})
			continue
		}
		out = append(out, c.frame(f, 0))
	}
	return out
}

func (t *DNP3Tracker) feed(key string, dir int, payload []byte, hint bool) []DNP3Message {
	c := t.conns[key]
	buf := payload
	if c != nil {
		buf = pending(&c.tcpConn, dir, payload)
	}
	if len(buf) == 0 {
		return nil
	}
	recognized := c != nil && c.recognized
	if !recognized || (c != nil && c.needProbe[dir]) {
		switch ProbeDNP3(buf) {
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
		t.keep(key, &c, dir, nil, true)
	}

	var out []DNP3Message
	for len(buf) > 0 {
		size := DNP3FrameSize(buf)
		if size < 0 && len(buf) >= 3 && buf[0] == dnp3Start0 && buf[1] == dnp3Start1 {
			// A frame start with a length that cannot hold the link header:
			// event, then skip to the next possible start.
			out = append(out, DNP3Message{Frame: DNP3Frame{Length: buf[2]}, Events: []string{DNP3EventLenTooSmall}})
			buf = buf[DNP3Resync(buf):]
			continue
		}
		if size < 0 {
			// Not a frame start: the stream is out of step.
			buf = nil
			if c != nil {
				c.needProbe[dir] = true
				c.reasm[dir] = dnp3Reasm{}
			}
			break
		}
		f, n, ok := ParseDNP3Frame(buf)
		if !ok {
			break
		}
		buf = buf[n:]
		if f.Invalid {
			out = append(out, DNP3Message{Frame: f, Events: f.Events})
			continue
		}
		if c != nil {
			out = append(out, c.frame(f, dir))
		} else {
			var tmp dnp3Conn
			out = append(out, tmp.frame(f, dir))
		}
	}
	t.keep(key, &c, dir, buf, recognized)
	return out
}

// frame handles one link frame: it adds the transport segment to the pending
// fragment of the direction and decodes the fragment when it is complete.
func (c *dnp3Conn) frame(f DNP3Frame, dir int) DNP3Message {
	m := DNP3Message{Frame: f, LinkName: DNP3LinkFunctionName(f.Primary(), f.LinkFunction()), Events: append([]string(nil), f.Events...)}
	// Only user data frames carry transport segments.
	if !f.Primary() || (f.LinkFunction() != 3 && f.LinkFunction() != 4) || len(f.UserData) == 0 {
		return m
	}
	th := f.UserData[0]
	m.HasTransport = true
	m.FIN, m.FIR, m.TransportSeq = th&0x80 != 0, th&0x40 != 0, th&0x3f
	seg := f.UserData[1:]
	r := &c.reasm[dir]
	switch {
	case m.FIR:
		*r = dnp3Reasm{active: true, seq: m.TransportSeq}
	case !r.active || m.TransportSeq != (r.seq+1)&0x3f:
		// A segment without its start, or out of order: the fragment is lost.
		*r = dnp3Reasm{}
		m.Events = append(m.Events, DNP3EventMalformed)
		return m
	default:
		r.seq = m.TransportSeq
	}
	if !r.tooLong {
		if len(r.data)+len(seg) > dnp3MaxFragment {
			r.tooLong = true
			r.data = nil
			m.Events = append(m.Events, DNP3EventTooLongReass)
		} else {
			r.data = append(r.data, seg...)
		}
	}
	if m.FIN {
		if !r.tooLong {
			m.App = decodeDNP3App(r.data, f.FromMaster())
			m.Events = append(m.Events, m.App.Events...)
		}
		*r = dnp3Reasm{}
	}
	return m
}
