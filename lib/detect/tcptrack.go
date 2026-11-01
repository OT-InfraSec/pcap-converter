package detect

import "github.com/InfraSecConsult/pcap-importer-go/lib/tcpseq"

// The stream trackers (Modbus, EtherNet/IP, S7comm, DNP3) share how they follow
// a TCP connection: segments are ordered by sequence number, RST, a closing FIN
// exchange or a new SYN end the state, the number of connections is bounded,
// and the unfinished bytes of a frame wait for the next segment. That lives
// here once; each protocol keeps only its framing and decoding.

// defaultTrackerLimit bounds the connections a tracker keeps state for.
const defaultTrackerLimit = 200_000

// TCPSegment is what a tracker needs of a TCP segment.
type TCPSegment struct {
	Seq                uint32
	SYN, FIN, RST, ACK bool
	Payload            []byte
}

// Directions index the per-direction state: server to client and client to server.
const (
	dirToClient = 0
	dirToServer = 1
)

func direction(toServer bool) int {
	if toServer {
		return dirToServer
	}
	return dirToClient
}

// tcpConn is the state every tracked connection has. A protocol's connection
// type embeds it and adds what only it needs.
type tcpConn struct {
	recognized bool
	// needProbe is set per direction after bytes were lost for good: the next
	// data must pass the protocol's probe again before parsing resumes.
	needProbe [2]bool
	// partial holds the unfinished bytes of a frame per direction.
	partial [2][]byte
	streams [2]tcpseq.Stream
	fin     [2]bool
}

func (c *tcpConn) tcp() *tcpConn { return c }

// resetPending drops protocol state that cannot survive lost bytes (pending
// fragments and the like). The default has none; a protocol connection that
// has some defines its own.
func (c *tcpConn) resetPending(dir int) {}

// connState is what the tracker needs of a protocol's connection type.
type connState interface {
	tcp() *tcpConn
	resetPending(dir int)
}

// tcpTracker holds the connections of one protocol's tracker. C is the
// protocol's connection type (a pointer), M its message type.
type tcpTracker[C connState, M any] struct {
	max        int
	maxPartial int // longest unfinished frame worth keeping
	conns      map[string]C
	newConn    func() C
}

func newTCPTracker[C connState, M any](max, maxPartial int, newConn func() C) tcpTracker[C, M] {
	return tcpTracker[C, M]{max: max, maxPartial: maxPartial, conns: make(map[string]C), newConn: newConn}
}

// Len is the number of connections with state.
func (t *tcpTracker[C, M]) Len() int { return len(t.conns) }

// Known reports whether the connection has been recognised as the protocol.
func (t *tcpTracker[C, M]) Known(key string) bool {
	c, ok := t.conns[key]
	return ok && c.tcp().recognized
}

// feedTCP orders the segment, hands the new in-order bytes to feed and keeps
// the connection's lifetime. Bytes seen before (retransmissions, overlaps) are
// dropped, segments that arrive early are held until the gap closes (package
// tcpseq), and a connection first seen mid-stream is taken as it comes. When
// bytes were lost for good the half frame is dropped and the direction must
// pass the probe again. feed gets the direction (dirToServer or dirToClient).
func (t *tcpTracker[C, M]) feedTCP(key string, toServer bool, seg TCPSegment, hint bool,
	feed func(key string, dir int, payload []byte, hint bool) []M) []M {
	dir := direction(toServer)
	if seg.RST || (seg.SYN && !seg.ACK) {
		delete(t.conns, key)
		if seg.RST {
			return nil
		}
	}
	payload := seg.Payload
	c, have := t.conns[key]
	if have {
		data, gap := c.tcp().streams[dir].Push(seg.Seq, seg.SYN, payload)
		if gap {
			c.tcp().partial[dir] = nil
			c.tcp().needProbe[dir] = true
			c.resetPending(dir)
		}
		payload = data
	}
	var out []M
	if len(payload) > 0 {
		out = feed(key, dir, payload, hint)
	}
	if !have {
		// The feed may have just recognised the connection: fix the position.
		if c, have = t.conns[key]; have {
			c.tcp().streams[dir].Push(seg.Seq, seg.SYN, seg.Payload)
		}
	}
	if seg.FIN && have {
		c.tcp().fin[dir] = true
		if c.tcp().fin[0] && c.tcp().fin[1] {
			delete(t.conns, key)
		}
	}
	return out
}

// pending returns the unfinished bytes of the direction joined with payload.
func pending(c *tcpConn, dir int, payload []byte) []byte {
	if c == nil || len(c.partial[dir]) == 0 {
		return payload
	}
	return append(append(make([]byte, 0, len(c.partial[dir])+len(payload)), c.partial[dir]...), payload...)
}

// keep stores the unfinished bytes of a direction and the recognised flag. *c
// is the connection if the feed has one; keep creates it when there is
// something to remember and the limit allows, and sets *c. A connection with
// nothing to remember is not given an entry.
func (t *tcpTracker[C, M]) keep(key string, c *C, dir int, rest []byte, recognized bool) {
	cur, ok := t.conns[key]
	if !ok {
		if !recognized && len(rest) == 0 {
			return
		}
		if len(t.conns) >= t.max {
			return
		}
		cur = t.newConn()
		t.conns[key] = cur
		*c = cur
	}
	tc := cur.tcp()
	if recognized {
		tc.recognized = true
	}
	if len(rest) == 0 || len(rest) > t.maxPartial {
		tc.partial[dir] = nil
		return
	}
	tc.partial[dir] = append([]byte(nil), rest...)
}
