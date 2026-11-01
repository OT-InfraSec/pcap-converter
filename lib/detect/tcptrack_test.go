package detect

import "testing"

// toyConn counts how often the tracker told it that bytes were lost.
type toyConn struct {
	tcpConn
	resets int
}

func (c *toyConn) resetPending(dir int) { c.resets++ }

func newToyTracker(max int) tcpTracker[*toyConn, string] {
	return newTCPTracker[*toyConn, string](max, 8, func() *toyConn { return &toyConn{} })
}

// feedToy is a protocol feed: every payload is a message, and a connection is
// recognised by its first payload.
func feedToy(t *tcpTracker[*toyConn, string]) func(string, int, []byte, bool) []string {
	return func(key string, dir int, p []byte, hint bool) []string {
		c := t.conns[key]
		t.keep(key, &c, dir, nil, true)
		return []string{string(p)}
	}
}

func TestTCPTrackerCore(t *testing.T) {
	seg := func(seq uint32, p string, f ...func(*TCPSegment)) TCPSegment {
		s := TCPSegment{Seq: seq, ACK: true, Payload: []byte(p)}
		for _, fn := range f {
			fn(&s)
		}
		return s
	}
	t.Run("order, retransmission, early segment", func(t *testing.T) {
		tr := newToyTracker(10)
		f := feedToy(&tr)
		if got := tr.feedTCP("k", true, seg(1, "ab"), true, f); len(got) != 1 {
			t.Fatal(got)
		}
		if got := tr.feedTCP("k", true, seg(1, "ab"), true, f); len(got) != 0 {
			t.Errorf("retransmission delivered: %v", got)
		}
		if got := tr.feedTCP("k", true, seg(5, "ef"), true, f); len(got) != 0 {
			t.Errorf("early segment delivered: %v", got)
		}
		if got := tr.feedTCP("k", true, seg(3, "cd"), true, f); len(got) != 1 || got[0] != "cdef" {
			t.Errorf("gap closed: %v", got)
		}
		if !tr.Known("k") || tr.Len() != 1 {
			t.Error("connection state")
		}
	})
	t.Run("a gap clears pending bytes and tells the connection", func(t *testing.T) {
		tr := newToyTracker(10)
		f := feedToy(&tr)
		tr.feedTCP("k", true, seg(1, "ab"), true, f)
		c := tr.conns["k"]
		c.partial[dirToServer] = []byte("half")
		seq := uint32(1000)
		for i := 0; i < 40 && c.resets == 0; i++ { // far segments force the stream past the hole
			tr.feedTCP("k", true, seg(seq, "xxxx"), true, f)
			seq += 4
		}
		if c.resets == 0 || c.partial[dirToServer] != nil || !c.needProbe[dirToServer] {
			t.Errorf("resets=%d partial=%q needProbe=%v", c.resets, c.partial[dirToServer], c.needProbe[dirToServer])
		}
		if c.needProbe[dirToClient] {
			t.Error("the other direction is not affected")
		}
	})
	t.Run("RST, FIN both ways and a new SYN end the state", func(t *testing.T) {
		for name, ends := range map[string]func(tr *tcpTracker[*toyConn, string], f func(string, int, []byte, bool) []string){
			"rst": func(tr *tcpTracker[*toyConn, string], f func(string, int, []byte, bool) []string) {
				if got := tr.feedTCP("k", true, TCPSegment{Seq: 3, RST: true, Payload: []byte("zz")}, true, f); len(got) != 0 {
					panic("a RST segment's payload is not data")
				}
			},
			"fin": func(tr *tcpTracker[*toyConn, string], f func(string, int, []byte, bool) []string) {
				tr.feedTCP("k", true, TCPSegment{Seq: 3, FIN: true, ACK: true}, true, f)
				if !tr.Known("k") {
					panic("one FIN must not end the connection")
				}
				tr.feedTCP("k", false, TCPSegment{Seq: 50, FIN: true, ACK: true}, true, f)
			},
			"syn": func(tr *tcpTracker[*toyConn, string], f func(string, int, []byte, bool) []string) {
				tr.feedTCP("k", true, TCPSegment{Seq: 7, SYN: true}, true, f)
			},
		} {
			tr := newToyTracker(10)
			f := feedToy(&tr)
			tr.feedTCP("k", true, seg(1, "ab"), true, f)
			ends(&tr, f)
			if tr.Known("k") && name != "syn" {
				t.Errorf("%s: state remains", name)
			}
			if name == "syn" && tr.Len() > 1 {
				t.Errorf("syn: %d connections", tr.Len())
			}
		}
	})
	t.Run("limit and partial bytes", func(t *testing.T) {
		tr := newToyTracker(1)
		var c *toyConn
		tr.keep("a", &c, dirToServer, []byte("123"), true)
		var d *toyConn
		tr.keep("b", &d, dirToServer, []byte("123"), true)
		if tr.Len() != 1 || d != nil {
			t.Errorf("limit: len %d", tr.Len())
		}
		if string(c.partial[dirToServer]) != "123" {
			t.Errorf("partial %q", c.partial[dirToServer])
		}
		tr.keep("a", &c, dirToServer, []byte("123456789"), true) // longer than maxPartial
		if c.partial[dirToServer] != nil {
			t.Error("an over-long half frame is not kept")
		}
		var e *toyConn
		tr.keep("zzz", &e, dirToServer, nil, false) // nothing to remember: no entry
		if tr.Len() != 1 {
			t.Error("entry for nothing")
		}
	})
	t.Run("pending joins old and new bytes", func(t *testing.T) {
		c := &tcpConn{}
		c.partial[dirToServer] = []byte("ab")
		if got := string(pending(c, dirToServer, []byte("cd"))); got != "abcd" {
			t.Error(got)
		}
		if got := string(pending(c, dirToClient, []byte("cd"))); got != "cd" {
			t.Error(got)
		}
		if got := string(pending(nil, dirToServer, []byte("cd"))); got != "cd" {
			t.Error(got)
		}
	})
}
