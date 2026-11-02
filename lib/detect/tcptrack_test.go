package detect

import (
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/lib/tcpseq"
)

// toyConn counts how often the tracker told it that bytes were lost.
type toyConn struct {
	tcpConn
	resets int
}

func (c *toyConn) resetPending(dir streamDir) { c.resets++ }

// newToyTracker returns a tracker whose protocol feed is trivial: every
// payload is a message, and a connection is recognised by its first payload.
func newToyTracker(max int) *tcpTracker[*toyConn, string] {
	t := &tcpTracker[*toyConn, string]{}
	*t = newTCPTracker(max, 8, func() *toyConn { return &toyConn{} },
		func(key string, dir streamDir, p []byte, hint bool) []string {
			c := t.conns[key]
			t.keep(key, &c, dir, nil, true)
			return []string{string(p)}
		})
	return t
}

func toySeg(seq uint32, p string) TCPSegment {
	return TCPSegment{Seq: seq, ACK: true, Payload: []byte(p)}
}

// wantMessages fails the test unless the tracker returned exactly want.
func wantMessages(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %q, want %q", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: got %q, want %q", what, got, want)
		}
	}
}

func TestTCPTrackerOrdersSegments(t *testing.T) {
	tr := newToyTracker(10)
	wantMessages(t, "first segment", tr.FeedTCP("k", true, toySeg(1, "ab"), true), "ab")
	wantMessages(t, "retransmission", tr.FeedTCP("k", true, toySeg(1, "ab"), true))
	wantMessages(t, "early segment", tr.FeedTCP("k", true, toySeg(5, "ef"), true))
	wantMessages(t, "gap closed", tr.FeedTCP("k", true, toySeg(3, "cd"), true), "cdef")
	if !tr.Known("k") || tr.Len() != 1 {
		t.Errorf("connection state: known=%v len=%d", tr.Known("k"), tr.Len())
	}
}

func TestTCPTrackerGapClearsPendingBytes(t *testing.T) {
	tr := newToyTracker(10)
	tr.FeedTCP("k", true, toySeg(1, "ab"), true)
	c := tr.conns["k"]
	c.partial[dirToServer] = []byte("half")

	// A segment further ahead than tcpseq follows makes the stream skip bytes.
	tr.FeedTCP("k", true, toySeg(3+tcpseq.MaxWindow+10, "xxxx"), true)

	if c.resets != 1 {
		t.Errorf("resetPending called %d times, want 1", c.resets)
	}
	if c.partial[dirToServer] != nil {
		t.Errorf("partial bytes kept after a gap: %q", c.partial[dirToServer])
	}
	if !c.needProbe[dirToServer] {
		t.Error("the direction must pass the probe again")
	}
	if c.needProbe[dirToClient] {
		t.Error("the other direction must not be affected")
	}
}

func TestTCPTrackerEndsState(t *testing.T) {
	tests := []struct {
		name      string
		end       func(t *testing.T, tr *tcpTracker[*toyConn, string])
		wantKnown bool
		wantLen   int
	}{
		{"RST", func(t *testing.T, tr *tcpTracker[*toyConn, string]) {
			wantMessages(t, "payload of a RST segment", tr.FeedTCP("k", true, TCPSegment{Seq: 3, RST: true, Payload: []byte("zz")}, true))
		}, false, 0},
		{"FIN both ways", func(t *testing.T, tr *tcpTracker[*toyConn, string]) {
			tr.FeedTCP("k", true, TCPSegment{Seq: 3, FIN: true, ACK: true}, true)
			if !tr.Known("k") {
				t.Fatal("one FIN must not end the connection")
			}
			tr.FeedTCP("k", false, TCPSegment{Seq: 50, FIN: true, ACK: true}, true)
		}, false, 0},
		{"new SYN", func(t *testing.T, tr *tcpTracker[*toyConn, string]) {
			tr.FeedTCP("k", true, TCPSegment{Seq: 7, SYN: true}, true)
		}, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newToyTracker(10)
			tr.FeedTCP("k", true, toySeg(1, "ab"), true)
			tt.end(t, tr)
			if tr.Known("k") != tt.wantKnown || tr.Len() != tt.wantLen {
				t.Errorf("known=%v len=%d, want known=%v len=%d", tr.Known("k"), tr.Len(), tt.wantKnown, tt.wantLen)
			}
		})
	}
}

func TestTCPTrackerKeep(t *testing.T) {
	tr := newToyTracker(1)
	var a *toyConn
	tr.keep("a", &a, dirToServer, []byte("123"), true)
	if string(a.partial[dirToServer]) != "123" {
		t.Errorf("partial %q", a.partial[dirToServer])
	}

	var b *toyConn
	tr.keep("b", &b, dirToServer, []byte("123"), true)
	if tr.Len() != 1 || b != nil {
		t.Errorf("limit: len=%d, entry past the limit=%v", tr.Len(), b)
	}

	tr.keep("a", &a, dirToServer, []byte("123456789"), true) // longer than maxPartial
	if a.partial[dirToServer] != nil {
		t.Error("an over-long half frame is not kept")
	}

	var e *toyConn
	tr.keep("zzz", &e, dirToServer, nil, false) // nothing to remember: no entry
	if tr.Len() != 1 {
		t.Errorf("entry created for nothing: len=%d", tr.Len())
	}
}

func TestPendingJoinsOldAndNewBytes(t *testing.T) {
	c := &tcpConn{}
	c.partial[dirToServer] = []byte("ab")
	tests := []struct {
		name string
		c    *tcpConn
		dir  streamDir
		want string
	}{
		{"same direction", c, dirToServer, "abcd"},
		{"other direction", c, dirToClient, "cd"},
		{"no connection", nil, dirToServer, "cd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(pending(tt.c, tt.dir, []byte("cd"))); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
