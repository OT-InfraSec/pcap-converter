package helper

import (
	"strconv"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// FlowCanonicalizer determines a canonical flow direction (client -> server)
// based on well-known service ports and lexicographic fallback.
type FlowCanonicalizer interface {
	CanonicalizeFlow(srcIP string, dstIP string, srcPort model.Set, dstPort model.Set, protocol string) (canonicalSrc string, canonicalDst string, isReversed bool)
	HasServicePort(ports model.Set, protocol string) bool
	GetWellKnownPorts() map[uint16]string
}

// FlowCanonicalizerImpl is the default implementation.
type FlowCanonicalizerImpl struct {
	wellKnownPorts map[uint16]string
}

// NewFlowCanonicalizer creates a new canonicalizer with default ports.
func NewFlowCanonicalizer() *FlowCanonicalizerImpl {
	return &FlowCanonicalizerImpl{wellKnownPorts: defaultWellKnownPorts()}
}

func defaultWellKnownPorts() map[uint16]string {
	// Keep keys as uint16 ports mapped to a human-readable service name
	return map[uint16]string{
		80:    "HTTP",
		8080:  "HTTP",
		8000:  "HTTP",
		443:   "HTTPS",
		8443:  "HTTPS",
		4840:  "OPC UA",
		502:   "Modbus",
		44818: "EtherNet/IP",
		2222:  "EtherNet/IP",
		53:    "DNS",
		161:   "SNMP",
		162:   "SNMP",
		22:    "SSH",
		23:    "Telnet",
	}
}

// GetWellKnownPorts returns the configured well-known ports map.
func (f *FlowCanonicalizerImpl) GetWellKnownPorts() map[uint16]string {
	return f.wellKnownPorts
}

// IsServicePort returns true if the port is a known service port.
func (f *FlowCanonicalizerImpl) HasServicePort(ports model.Set, protocol string) bool {
	for _, p := range ports.List() {
		portNum, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			continue
		}
		if f.isServicePort(uint16(portNum), protocol) {
			return true
		}
	}
	return false
}

func (f *FlowCanonicalizerImpl) isServicePort(port uint16, protocol string) bool {
	_, ok := f.wellKnownPorts[port]
	return ok
}

// CanonicalizeFlow returns canonical source and destination.
// isReversed is true when the provided src/dst should be considered reversed
// relative to the canonical tuple (i.e., the packet belongs to server->client).
func (f *FlowCanonicalizerImpl) CanonicalizeFlow(srcIP string, dstIP string, srcPorts model.Set, dstPorts model.Set, protocol string) (string, string, bool) {
	srcIsService := f.HasServicePort(srcPorts, protocol)
	dstIsService := f.HasServicePort(dstPorts, protocol)

	// If destination is service port and source isn't, canonical is src->dst
	if dstIsService && !srcIsService {
		return srcIP, dstIP, false
	}
	// If source is service port and destination isn't, then original packet is server->client
	if srcIsService && !dstIsService {
		return dstIP, srcIP, true
	}

	// destination service has only one port and source has multiple
	if dstPorts.Size() == 1 && srcPorts.Size() > 1 {
		return srcIP, dstIP, false
	}
	// source service has only one port and destination has multiple
	if srcPorts.Size() == 1 && dstPorts.Size() > 1 {
		return dstIP, srcIP, true
	}

	return srcIP, dstIP, false
}
