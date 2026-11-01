package parser

import (
	"fmt"
	"sort"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
)

// maxTrackedConnections bounds the labeler's memory on very large captures.
// Past the limit new connections are labelled per packet only.
const maxTrackedConnections = 500_000

// connectionLabeler gives every packet of a connection the same application
// protocol label, which the flow table needs: flows are keyed by host pair and
// label, so a label that flips between packets of one connection splits the
// connection into several flow records.
//
// Rules, per connection and per probe-based protocol in the registry:
//   - A packet whose payload the probe Recognizes fixes the label for the rest
//     of the connection. After that nothing can remove it: without TCP
//     reassembly (plan phase 2) later segments of a long message do not start
//     with a header and would look unrecognised.
//   - Before recognition, a connection on a hint port keeps the hint label
//     (handshake and ACK segments carry no payload), until a payload shows it
//     is something else (probe says Unrecognized). That is a veto and sticks.
//   - Off the hint ports nothing is labelled until content is recognised.
//
// Packets before the first recognition or veto keep the label they were given.
// Suricata labels the whole flow including the handshake; matching that needs
// deferred flow accounting and is tracked in the plan.
type connectionLabeler struct {
	registry *detect.Registry
	conns    map[string]*connState
}

type connState struct {
	label  string // fixed by recognised content
	vetoed bool   // payload contradicted the hint-port guess
}

func newConnectionLabeler(r *detect.Registry) *connectionLabeler {
	return &connectionLabeler{registry: r, conns: make(map[string]*connState)}
}

// flowLabel is the label stored in the flows table for a protocol on a
// transport. It keeps the names the importer used before the registry existed.
func flowLabel(name string, t detect.Transport) string {
	switch name {
	case "EtherNet/IP":
		if t == detect.TCP {
			return "EtherNet/IP(TCP)"
		}
		return "EtherNet/IP(UDP)"
	case "Modbus":
		return "modbus"
	case "S7":
		return "s7"
	case "S7CommPlus":
		return "s7commplus"
	}
	return name
}

func connKey(t detect.Transport, srcIP string, srcPort uint16, dstIP string, dstPort uint16, vlan model.VLANTag) string {
	a := fmt.Sprintf("%s:%d", srcIP, srcPort)
	b := fmt.Sprintf("%s:%d", dstIP, dstPort)
	ends := []string{a, b}
	sort.Strings(ends)
	return fmt.Sprintf("%d|%s|%s|%s", t, ends[0], ends[1], vlan.Token())
}

// Label updates the connection state with this packet and returns the label
// for it, or "" if the registry has no opinion.
func (l *connectionLabeler) Label(packet gopacket.Packet, srcIP, dstIP string, vlan model.VLANTag) string {
	t, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok {
		return ""
	}
	key := connKey(t, srcIP, srcPort, dstIP, dstPort, vlan)
	st := l.conns[key]
	if st != nil && st.label != "" {
		return st.label
	}

	for _, proto := range l.registry.Protocols() {
		probe := proto.ProbeFor(t)
		if probe == nil || proto.Transports&t == 0 {
			continue
		}
		res := detect.Incomplete
		if len(payload) > 0 {
			res = probe(payload)
		}
		hint := false
		for _, h := range proto.HintPorts {
			if h.Transport&t != 0 && (h.Port == srcPort || h.Port == dstPort) {
				hint = true
			}
		}

		switch {
		case res == detect.Recognized:
			if st == nil && len(l.conns) >= maxTrackedConnections {
				return flowLabel(proto.Name, t)
			}
			if st == nil {
				st = &connState{}
				l.conns[key] = st
			}
			st.label = flowLabel(proto.Name, t)
			return st.label
		case res == detect.Unrecognized && hint:
			if st == nil && len(l.conns) < maxTrackedConnections {
				st = &connState{}
				l.conns[key] = st
			}
			if st != nil {
				st.vetoed = true
			}
		case hint && (st == nil || !st.vetoed):
			if st == nil && len(l.conns) < maxTrackedConnections {
				l.conns[key] = &connState{}
			}
			return flowLabel(proto.Name, t)
		}
	}
	return ""
}
