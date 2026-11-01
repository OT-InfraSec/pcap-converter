// Package detect identifies application-layer protocols from payload content.
//
// Ports are only hints. A protocol is recognised by its Probe; the port merely
// raises confidence or lets a protocol without a probe (not implemented yet)
// be reported as port-only evidence. This mirrors Suricata's three-state probe
// result so a TCP stream whose first segment is short is not rejected early.
package detect

import "sort"

// Result is the outcome of probing a payload.
type Result uint8

const (
	// Unrecognized means the payload cannot be this protocol.
	Unrecognized Result = iota
	// Incomplete means more bytes are needed to decide.
	Incomplete
	// Recognized means the payload is this protocol.
	Recognized
)

func (r Result) String() string {
	switch r {
	case Recognized:
		return "recognized"
	case Incomplete:
		return "incomplete"
	default:
		return "unrecognized"
	}
}

// Transport is a bit set of transport protocols.
type Transport uint8

const (
	TCP Transport = 1 << iota
	UDP
)

// Probe inspects a payload (reassembled stream data for TCP) and decides.
type Probe func(payload []byte) Result

// HintPort is a port that commonly carries a protocol on a transport.
type HintPort struct {
	Transport Transport
	Port      uint16
}

// Protocol describes one detectable protocol.
type Protocol struct {
	Name       string
	Transports Transport
	HintPorts  []HintPort
	// Probe may be nil while no content check exists. Such a protocol is only
	// ever reported as port-only evidence (Match.PortOnly).
	Probe Probe
	// ProbeUDP, if set, replaces Probe for UDP payloads (for protocols whose
	// datagram format differs from the stream format).
	ProbeUDP Probe
}

// ProbeFor returns the probe to use on a transport, or nil.
func (p Protocol) ProbeFor(t Transport) Probe {
	if t == UDP && p.ProbeUDP != nil {
		return p.ProbeUDP
	}
	return p.Probe
}

// Match is one detection result.
type Match struct {
	Protocol string
	Result   Result
	// PortHint is true if one of the packet's ports is a hint port.
	PortHint bool
	// PortOnly is true if the protocol has no probe and matched by port alone.
	PortOnly bool
}

// Registry holds the known protocols in registration order.
type Registry struct {
	protocols []Protocol
}

// Register adds a protocol. A later registration with the same name replaces
// the earlier one.
func (r *Registry) Register(p Protocol) {
	for i := range r.protocols {
		if r.protocols[i].Name == p.Name {
			r.protocols[i] = p
			return
		}
	}
	r.protocols = append(r.protocols, p)
}

// Lookup returns the protocol with the given name.
func (r *Registry) Lookup(name string) (Protocol, bool) {
	for _, p := range r.protocols {
		if p.Name == name {
			return p, true
		}
	}
	return Protocol{}, false
}

// Protocols returns a copy of the registered protocols.
func (r *Registry) Protocols() []Protocol {
	return append([]Protocol(nil), r.protocols...)
}

// Detect returns all protocols that match. A protocol with a probe matches on
// Recognized (any port) or, when a port hint applies, also on Incomplete.
// Unrecognized never matches, even on a hint port: a Modbus port carrying
// garbage is not Modbus. A protocol without a probe matches on a hint port
// only. An empty payload yields hint-port matches with Result Incomplete.
func (r *Registry) Detect(t Transport, srcPort, dstPort uint16, payload []byte) []Match {
	var out []Match
	for _, p := range r.protocols {
		if p.Transports&t == 0 {
			continue
		}
		hint := hasHint(p, t, srcPort, dstPort)
		probe := p.ProbeFor(t)
		if probe == nil {
			if hint {
				out = append(out, Match{Protocol: p.Name, Result: Incomplete, PortHint: true, PortOnly: true})
			}
			continue
		}
		res := probe(payload)
		switch {
		case res == Recognized:
			out = append(out, Match{Protocol: p.Name, Result: res, PortHint: hint})
		case res == Incomplete && hint:
			out = append(out, Match{Protocol: p.Name, Result: res, PortHint: true})
		}
	}
	return out
}

func hasHint(p Protocol, t Transport, srcPort, dstPort uint16) bool {
	for _, h := range p.HintPorts {
		if h.Transport&t != 0 && (h.Port == srcPort || h.Port == dstPort) {
			return true
		}
	}
	return false
}

// HintPorts returns port -> protocol name for every hint port, across
// transports. If two protocols share a port the earlier registration wins.
func (r *Registry) HintPorts() map[uint16]string {
	out := make(map[uint16]string)
	for _, p := range r.protocols {
		for _, h := range p.HintPorts {
			if _, ok := out[h.Port]; !ok {
				out[h.Port] = p.Name
			}
		}
	}
	return out
}

// SortedHintPorts returns the hint ports in ascending order, for stable output.
func (r *Registry) SortedHintPorts() []uint16 {
	m := r.HintPorts()
	ports := make([]uint16, 0, len(m))
	for p := range m {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}
