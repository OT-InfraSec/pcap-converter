package parser

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/hostid"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

// Host evidence: what DHCPv4 clients and LLMNR responders say about
// themselves. The functions below are pure and treat every byte as untrusted
// (anyone on the segment can send these packets): lengths are checked, strings
// are limited to printable ASCII and a bounded length, and malformed input is
// dropped, never reported as an error.

const (
	// llmnrPort is the UDP and TCP port of Link-Local Multicast Name
	// Resolution (RFC 4795). Only UDP is decoded.
	llmnrPort = 5355

	dhcpOptClientFQDN = layers.DHCPOpt(81) // RFC 4702

	maxHostString = 255 // longest option string kept: the DHCP option limit
	maxDNSName    = 253 // longest DNS name in presentation form (RFC 1035)
	maxParamList  = 64  // longest parameter request list kept
)

// dhcpClientEvidence is what one DHCPv4 packet says about its client.
type dhcpClientEvidence struct {
	MAC          string // client hardware address (Ethernet only)
	IP           string // ciaddr, else the requested address, else the assigned one (yiaddr)
	Hostname     string // option 12
	FQDN         string // option 81
	VendorClass  string // option 60
	ParamList    string // option 55 as "1,3,6,15": the order identifies the client's DHCP stack
	LeaseSeconds uint32 // option 51, replies only
}

// dhcpv4ClientEvidence extracts the client's facts from a DHCPv4 packet. ok is
// false when the packet has no usable client hardware address.
//
// Requests carry what the client says about itself (hostname, vendor class,
// parameter request list). Replies carry only the address binding and lease: a
// server's own options are not the client's.
func dhcpv4ClientEvidence(d *layers.DHCPv4) (dhcpClientEvidence, bool) {
	var e dhcpClientEvidence
	if d == nil || len(d.ClientHWAddr) != 6 {
		return e, false
	}
	e.MAC = strings.ToLower(d.ClientHWAddr.String())

	switch d.Operation {
	case layers.DHCPOpRequest:
		e.IP = usableIPv4(d.ClientIP)
		for _, o := range d.Options {
			switch o.Type {
			case layers.DHCPOptHostname:
				e.Hostname = cleanHostString(o.Data, maxHostString)
			case layers.DHCPOptClassID:
				e.VendorClass = cleanHostString(o.Data, maxHostString)
			case dhcpOptClientFQDN:
				e.FQDN = clientFQDN(o.Data)
			case layers.DHCPOptParamsRequest:
				e.ParamList = paramList(o.Data)
			case layers.DHCPOptRequestIP:
				if e.IP == "" && len(o.Data) == 4 {
					e.IP = usableIPv4(net.IP(o.Data))
				}
			}
		}
	case layers.DHCPOpReply:
		e.IP = usableIPv4(d.YourClientIP)
		for _, o := range d.Options {
			if o.Type == layers.DHCPOptLeaseTime && len(o.Data) == 4 {
				e.LeaseSeconds = binary.BigEndian.Uint32(o.Data)
			}
		}
	default:
		return e, false
	}
	return e, true
}

// usableIPv4 returns the string form of a unicast-looking IPv4 address, or "".
func usableIPv4(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil || ip4.IsUnspecified() || ip4.Equal(net.IPv4bcast) || ip4.IsMulticast() {
		return ""
	}
	return ip4.String()
}

// cleanHostString returns b as a string if it is printable ASCII and not longer
// than max after trailing NULs and spaces are removed (some clients NUL-terminate
// option strings, RFC 2132 section 2). Anything else is dropped whole, not
// repaired: a name with control bytes in it is not evidence.
func cleanHostString(b []byte, max int) string {
	for len(b) > 0 && (b[len(b)-1] == 0 || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	if len(b) == 0 || len(b) > max {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(b)
}

// clientFQDN decodes option 81 (RFC 4702): flags, two obsolete RCODE bytes and
// the name. With the E flag (0x04) the name is in DNS wire format (labels, one
// length byte each); without it, ASCII.
func clientFQDN(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	flags, name := b[0], b[3:]
	if flags&0x04 == 0 {
		return cleanHostString(name, maxDNSName)
	}
	var labels []string
	for len(name) > 0 {
		n := int(name[0])
		if n == 0 {
			break
		}
		if n > 63 || 1+n > len(name) { // a longer label or a pointer is not valid here
			return ""
		}
		l := cleanHostString(name[1:1+n], 63)
		if l == "" {
			return ""
		}
		labels = append(labels, l)
		name = name[1+n:]
	}
	fqdn := strings.Join(labels, ".")
	if len(fqdn) > maxDNSName {
		return ""
	}
	return fqdn
}

// paramList renders option 55 as comma-separated decimal option numbers in the
// order sent. The order is the DHCP fingerprint of a client stack.
func paramList(b []byte) string {
	if len(b) == 0 || len(b) > maxParamList {
		return ""
	}
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = strconv.Itoa(int(c))
	}
	return strings.Join(parts, ",")
}

// llmnrHost is a name an LLMNR responder gave for an address.
type llmnrHost struct {
	Name string
	IP   string
}

// llmnrResponses returns the name and address pairs of an LLMNR response
// (RFC 4795). Queries say nothing about who owns a name and yield none. The
// message has the DNS format, with the C, TC and T flags where DNS has AA, TC and
// RD, so a standard DNS decode is enough for the records.
func llmnrResponses(payload []byte) []llmnrHost {
	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	if !dns.QR || dns.OpCode != layers.DNSOpCodeQuery || dns.ResponseCode != layers.DNSResponseCodeNoErr {
		return nil
	}
	var out []llmnrHost
	for _, a := range dns.Answers {
		if a.Type != layers.DNSTypeA && a.Type != layers.DNSTypeAAAA {
			continue
		}
		name := cleanHostString(a.Name, maxDNSName)
		ip := a.IP
		if name == "" || len(ip) == 0 || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		out = append(out, llmnrHost{Name: name, IP: ip.String()})
	}
	return out
}

// hostEvidenceStore collects DHCP and LLMNR evidence while packets are read and
// applies it to devices once, before they are saved. A DHCP client is known by
// its hardware address first and gets an IP only when a later packet binds one
// (DISCOVER carries none), so evidence is held per MAC and joined at the end.
type hostEvidenceStore struct {
	dhcp  map[string]*dhcpClientEvidence // by MAC; the latest non-empty value of each field
	macIP map[string]string              // MAC -> the latest address bound to it
	llmnr map[string]map[string]struct{} // IP -> names its responder gave
	mdns  map[string]map[string]struct{} // IP -> names mDNS A/AAAA records gave

	identity map[string]*hostIdentity // IP -> NetBIOS and SMB identity, see host_identity.go
}

func newHostEvidenceStore() *hostEvidenceStore {
	return &hostEvidenceStore{
		dhcp:  make(map[string]*dhcpClientEvidence),
		macIP: make(map[string]string),
		llmnr: make(map[string]map[string]struct{}),
		mdns:  make(map[string]map[string]struct{}),

		identity: make(map[string]*hostIdentity),
	}
}

// maxHostEvidence bounds the store on captures with spoofed floods: past it new
// hosts are ignored.
const maxHostEvidence = 100_000

func (s *hostEvidenceStore) observeDHCP(e dhcpClientEvidence) {
	cur, ok := s.dhcp[e.MAC]
	if !ok {
		if len(s.dhcp) >= maxHostEvidence {
			return
		}
		cur = &dhcpClientEvidence{MAC: e.MAC}
		s.dhcp[e.MAC] = cur
	}
	if e.IP != "" {
		s.macIP[e.MAC] = e.IP
	}
	for dst, src := range map[*string]string{&cur.Hostname: e.Hostname, &cur.FQDN: e.FQDN, &cur.VendorClass: e.VendorClass, &cur.ParamList: e.ParamList} {
		if src != "" {
			*dst = src
		}
	}
	if e.LeaseSeconds != 0 {
		cur.LeaseSeconds = e.LeaseSeconds
	}
}

func (s *hostEvidenceStore) observeLLMNR(hosts []llmnrHost) {
	for _, h := range hosts {
		observeName(s.llmnr, h.IP, h.Name)
	}
}

// observeMDNS records the name an mDNS A or AAAA record gives for an address.
// The address in the record is not necessarily a packet endpoint, and the
// device may not exist yet, so the name is applied once at the end, like LLMNR.
func (s *hostEvidenceStore) observeMDNS(ip, name string) {
	observeName(s.mdns, ip, name)
}

func observeName(byIP map[string]map[string]struct{}, ip, name string) {
	names, ok := byIP[ip]
	if !ok {
		if len(byIP) >= maxHostEvidence {
			return
		}
		names = make(map[string]struct{})
		byIP[ip] = names
	}
	if len(names) < 16 { // a responder with more names than this is noise
		names[name] = struct{}{}
	}
}

// dhcpDeviceData is the "dhcp" entry in a device's additional data.
func dhcpDeviceData(e *dhcpClientEvidence) map[string]interface{} {
	out := map[string]interface{}{"mac": e.MAC}
	for k, v := range map[string]string{"hostname": e.Hostname, "fqdn": e.FQDN, "vendor_class": e.VendorClass, "param_request_list": e.ParamList} {
		if v != "" {
			out[k] = v
		}
	}
	if e.LeaseSeconds != 0 {
		out["lease_seconds"] = e.LeaseSeconds
	}
	return out
}

// evidence returns the parser's host evidence store, creating it for parsers
// built without NewGopacketParser.
func (p *GopacketParser) evidence() *hostEvidenceStore {
	if p.hostEvidence == nil {
		p.hostEvidence = newHostEvidenceStore()
	}
	return p.hostEvidence
}

// applyHostEvidence writes what DHCP clients and LLMNR responders said about
// themselves into the devices they belong to. A device the capture never saw
// as an endpoint is left alone: evidence alone does not create a host.
func (p *GopacketParser) applyHostEvidence() {
	s := p.evidence()
	for mac, e := range s.dhcp {
		dev := p.deviceManager.GetDevice(s.macIP[mac], "IP")
		if dev == nil {
			continue
		}
		if dev.Hostname == "" {
			dev.Hostname = firstNonEmpty(e.Hostname, e.FQDN)
		}
		if err := setAdditionalData(dev, "dhcp", dhcpDeviceData(e)); err != nil {
			log.Debug().Err(err).Str("ip", dev.Address).Msg("DHCP evidence not stored")
		}
	}
	for _, byIP := range []map[string]map[string]struct{}{s.llmnr, s.mdns} {
		for ip, names := range byIP {
			sorted := make([]string, 0, len(names))
			for n := range names {
				sorted = append(sorted, n)
			}
			sort.Strings(sorted)
			if err := p.associateDNSNames(ip, sorted...); err != nil {
				log.Debug().Err(err).Str("ip", ip).Msg("host name not stored")
			}
		}
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// setAdditionalData sets one key of the device's additional-data JSON object,
// keeping the others.
func setAdditionalData(dev *model.Device, key string, value interface{}) error {
	m := make(map[string]interface{})
	if dev.AdditionalData != "" {
		if err := json.Unmarshal([]byte(dev.AdditionalData), &m); err != nil {
			return fmt.Errorf("additional data of device %d: %w", dev.ID, err)
		}
	}
	m[key] = value
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	dev.AdditionalData = string(b)
	return nil
}

// observeHostIdentity feeds NetBIOS name service messages (UDP 137) and the
// start of SMB connections (TCP 445 and 139) to the identity store.
func (p *GopacketParser) observeHostIdentity(packet gopacket.Packet, srcIP string) {
	t, srcPort, dstPort, payload, ok := transportPayload(packet)
	if !ok || len(payload) == 0 || srcIP == "" {
		return
	}
	switch t {
	case detect.UDP:
		if p.noNBNS || (srcPort != detect.NBNSPort && dstPort != detect.NBNSPort) {
			return
		}
		if m, ok := hostid.DecodeNBNS(payload); ok {
			p.evidence().observeNBNS(srcIP, m)
		}
	case detect.TCP:
		if p.noSMB {
			return
		}
		isSMBPort := func(port uint16) bool { return port == detect.SMBPort || port == detect.SMBNetBIOSPort }
		if !isSMBPort(srcPort) && !isSMBPort(dstPort) {
			return
		}
		p.evidence().observeSMB(srcIP, isSMBPort(srcPort) && !isSMBPort(dstPort), payload)
	}
}
