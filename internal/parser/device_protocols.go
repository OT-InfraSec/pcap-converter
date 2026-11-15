package parser

import "slices"

// multiTransportProtocols run over both TCP and UDP and carry the same name on
// either, so the bare name would not say which variant a device used. Their
// entry in a device's protocol list names the transport, in the style of the
// registry's own "EtherNet/IP(UDP)" labels. Protocols that are fixed to one
// transport (modbus, s7, http, mdns, ...) and labels that already state it stay
// as they are.
var multiTransportProtocols = map[string]struct{}{
	"dns":   {},
	"llmnr": {},
	"dnp3":  {},
}

// HighestProtocol names the highest-level protocol of one packet for a device's
// protocol list, or "" when the packet has none (a bare Ethernet frame).
//
// flowProto is the label the flow table uses and is preferred, because it is
// the application protocol when one was recognised. When it is only a transport
// ("tcp", "udp") the last entry of protocols wins if it is something above the
// transport, which is how TLS (not a flow label) is reported. Otherwise the
// transport itself is the highest known protocol.
//
// A protocol in multiTransportProtocols gets the transport appended, e.g.
// "dns(UDP)" and "dns(TCP)" are two entries.
func HighestProtocol(flowProto string, protocols []string) string {
	highest := flowProto
	if highest == "tcp" || highest == "udp" {
		if n := len(protocols); n > 0 {
			if last := protocols[n-1]; last != "tcp" && last != "udp" {
				highest = last
			}
		}
	}
	if highest == "" {
		return ""
	}
	if _, ok := multiTransportProtocols[highest]; ok {
		switch {
		case slices.Contains(protocols, "tcp"):
			return highest + "(TCP)"
		case slices.Contains(protocols, "udp"):
			return highest + "(UDP)"
		}
	}
	return highest
}
