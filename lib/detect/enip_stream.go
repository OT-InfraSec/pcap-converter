package detect

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
	tcpTracker[*enipConn, ENIPMessage]
}

type enipConn struct{ tcpConn }

// enipMaxPDU is the largest message: the header and a 16-bit length.
const enipMaxPDU = ENIPHeaderLen + 0xffff

// NewENIPTracker returns a tracker with the default connection limit.
func NewENIPTracker() *ENIPTracker { return NewENIPTrackerLimit(defaultMaxConnections) }

// NewENIPTrackerLimit returns a tracker that keeps state for at most max connections.
func NewENIPTrackerLimit(max int) *ENIPTracker {
	t := &ENIPTracker{}
	t.tcpTracker = newTCPTracker(max, enipMaxPDU, func() *enipConn { return &enipConn{} }, t.feed)
	return t
}

func (t *ENIPTracker) feed(key string, dir streamDir, payload []byte, hint bool) []ENIPMessage {
	c := t.conns[key]
	buf := payload
	if c != nil {
		buf = pending(&c.tcpConn, dir, payload)
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
