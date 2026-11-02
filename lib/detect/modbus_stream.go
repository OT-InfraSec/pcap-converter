package detect

// ModbusTracker turns the TCP payloads of connections into Modbus messages.
//
// A connection becomes known as Modbus when a payload starts with a valid ADU
// header (the same test as the probe). From then on frames are decoded
// leniently, so a bad protocol id or length is an event and not silence, and
// a message split across segments is held until it is complete. The bytes of a
// partial message are kept per connection and direction (at most one ADU, 260
// bytes). FeedTCP orders segments by sequence number (package tcpseq), so
// retransmitted or reordered segments are handled; after bytes are lost for good
// the direction must show a valid ADU again before decoding resumes.
// Before a connection is known, only a payload that is a valid ADU counts, so
// other traffic on the same port leaves no state.
//
// The set of connections is bounded. Past the limit new connections are
// decoded without state: a frame is recognised only if it is valid and nothing
// is carried to the next segment.
type ModbusTracker struct {
	tcpTracker[*modbusConn, ModbusMessage]
}

type modbusConn struct{ tcpConn }

// NewModbusTracker returns a tracker with the default connection limit.
func NewModbusTracker() *ModbusTracker { return NewModbusTrackerLimit(defaultMaxConnections) }

// NewModbusTrackerLimit returns a tracker that keeps state for at most max
// connections.
func NewModbusTrackerLimit(max int) *ModbusTracker {
	t := &ModbusTracker{}
	t.tcpTracker = newTCPTracker(max, ModbusMaxADULen, func() *modbusConn { return &modbusConn{} }, t.feed)
	return t
}

// Feed adds the payload of one TCP segment and returns the messages it
// completes. key identifies the connection and must be the same for both
// directions. toServer is true for client to server. hint says the connection
// uses the Modbus port, which allows a first segment shorter than a header to
// be kept until the rest arrives.
func (t *ModbusTracker) Feed(key string, toServer bool, payload []byte, hint bool) []ModbusMessage {
	return t.feed(key, direction(toServer), payload, hint)
}

func (t *ModbusTracker) feed(key string, dir streamDir, payload []byte, hint bool) []ModbusMessage {
	toServer := dir == dirToServer
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
		if len(buf) < ModbusMBAPLen+1 {
			if hint {
				t.keep(key, &c, dir, buf, recognized)
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
		if c != nil {
			c.needProbe[dir] = false
		}
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
