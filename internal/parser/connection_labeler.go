package parser

import (
	"fmt"
	"sort"
	"strings"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
)

// ConnectionLabeler names the application protocol of a packet's connection,
// or returns "" when it has no opinion. GopacketParser takes one by interface so
// a different labeler (or a fake in tests) can replace the registry-based one.
type ConnectionLabeler interface {
	Label(packet gopacket.Packet, srcIP, dstIP string, vlan model.VLANTag) string
}

var _ ConnectionLabeler = (*connectionLabeler)(nil)

// labelerRegistry is the detection registry without the protocols the
// configuration disables, so a disabled protocol is neither parsed nor labelled.
func labelerRegistry(cfg IndustrialParserConfig) *detect.Registry {
	var off []string
	for name, enabled := range map[string]bool{
		"EtherNet/IP": cfg.EnableEtherNetIP,
		"OPC UA":      cfg.EnableOPCUA,
		"Modbus":      cfg.EnableModbus,
		"DNP3":        cfg.EnableDNP3,
		"S7":          cfg.EnableS7,
		"S7CommPlus":  cfg.EnableS7,
	} {
		if !enabled {
			off = append(off, name)
		}
	}
	return detect.Default().Without(off...)
}

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
//   - A port hinted by several protocols (S7comm and S7CommPlus on 102) gets
//     the neutral label "s7+s7commplus" for the whole connection, before and
//     after recognition, so one connection stays one flow record.
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
	case "DNP3":
		return "dnp3"
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

// entry returns the connection's state, creating it if there is room. It
// returns nil when the connection has none and the limit is reached.
func (l *connectionLabeler) entry(key string, st *connState) *connState {
	if st != nil {
		return st
	}
	if len(l.conns) >= maxTrackedConnections {
		return nil
	}
	st = &connState{}
	l.conns[key] = st
	return st
}

func containsProto(ps []detect.Protocol, name string) bool {
	for _, p := range ps {
		if p.Name == name {
			return true
		}
	}
	return false
}

// sharedHint returns the probe-based protocols that hint the port of this
// connection on transport t. More than one means the port cannot name the
// protocol (S7comm and S7CommPlus on 102).
func (l *connectionLabeler) sharedHint(t detect.Transport, srcPort, dstPort uint16) []detect.Protocol {
	var out []detect.Protocol
	for _, proto := range l.registry.Protocols() {
		if proto.ProbeFor(t) == nil || proto.Transports&t == 0 {
			continue
		}
		for _, h := range proto.HintPorts {
			if h.Transport&t != 0 && (h.Port == srcPort || h.Port == dstPort) {
				out = append(out, proto)
				break
			}
		}
	}
	return out
}

// sharedLabel is the neutral flow label of a connection on a port several
// protocols hint, e.g. "s7+s7commplus". It stays for the whole connection,
// including after content is recognised, so handshake, ACK and data packets
// land in one flow record. Which protocol it really is comes from the
// decoders' protocol info, not from the flow label.
func sharedLabel(ps []detect.Protocol, t detect.Transport) string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, flowLabel(p.Name, t))
	}
	sort.Strings(names)
	return strings.Join(names, "+")
}

// labelShared applies the neutral label to a connection on a shared hint port.
// decided is false when every candidate vetoed the payload, so the caller
// falls through to the normal rules.
func (l *connectionLabeler) labelShared(key string, st *connState, t detect.Transport, payload []byte, shared []detect.Protocol) (label string, decided bool) {
	if st != nil && st.vetoed {
		return "", false
	}
	label = sharedLabel(shared, t)
	if len(payload) == 0 {
		l.entry(key, st)
		return label, true
	}
	allUnrecognized := true
	for _, p := range shared {
		switch p.ProbeFor(t)(payload) {
		case detect.Recognized:
			if st = l.entry(key, st); st != nil {
				st.label = label
			}
			return label, true
		case detect.Incomplete:
			allUnrecognized = false
		}
	}
	if allUnrecognized {
		if st = l.entry(key, st); st != nil {
			st.vetoed = true
		}
		return "", false
	}
	return label, true
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

	shared := l.sharedHint(t, srcPort, dstPort)
	if len(shared) > 1 {
		if label, decided := l.labelShared(key, st, t, payload, shared); decided {
			return label
		}
	}

	for _, proto := range l.registry.Protocols() {
		probe := proto.ProbeFor(t)
		if probe == nil || proto.Transports&t == 0 {
			continue
		}
		if len(shared) > 1 && containsProto(shared, proto.Name) {
			continue // handled above under the neutral label
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
			if st = l.entry(key, st); st == nil {
				return flowLabel(proto.Name, t) // over the limit: label without state
			}
			st.label = flowLabel(proto.Name, t)
			return st.label
		case res == detect.Unrecognized && hint:
			if st = l.entry(key, st); st != nil {
				st.vetoed = true
			}
		case hint && (st == nil || !st.vetoed):
			l.entry(key, st)
			return flowLabel(proto.Name, t)
		}
	}
	return ""
}
