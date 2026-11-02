package parser

import (
	"sort"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/hostid"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/rs/zerolog/log"
)

// Windows and NetBIOS host identity: what the NetBIOS name service and the
// start of an SMB connection say about the hosts on it. Decoding is in
// lib/hostid; this file collects it per address and applies it to the devices.
//
// Limits, on purpose: only the first PDU of a TCP segment is read, and a PDU
// split over several segments is not reassembled (a negotiate or an NTLM
// challenge is a few hundred bytes and fits one segment in practice). User
// names from NTLM AUTHENTICATE messages are not kept: they are personal data
// nobody asked the importer to store.

const (
	maxNetBIOSNamesPerHost = 32
	maxSMBDialects         = 8
)

// hostIdentity is everything observed about one address.
type hostIdentity struct {
	netbios map[string]hostid.NBName // by "NAME<xx>"
	nbMAC   string                   // adapter address from a node status reply
	calling string                   // NetBIOS name the host gave in a session request

	smb smbIdentity
}

type smbIdentity struct {
	// Server side (a negotiate response, an NTLM challenge).
	Dialect         string
	SigningEnabled  *bool
	SigningRequired *bool
	ServerGUID      string
	SystemTime      time.Time
	StartTime       time.Time
	SMB1            bool
	Encrypted       bool

	// Client side (a negotiate request, an NTLM authenticate).
	OfferedDialects []string
	ClientGUID      string
	ClientSigning   *bool // signing required by the client

	// NTLM identity, from the CHALLENGE (the server) or AUTHENTICATE (the client).
	NetBIOSComputer string
	NetBIOSDomain   string
	DNSComputer     string
	DNSDomain       string
	Domain          string // the domain a client authenticated with
	Workstation     string
	WindowsVersion  string
}

func (s *hostEvidenceStore) host(ip string) *hostIdentity {
	h, ok := s.identity[ip]
	if !ok {
		if len(s.identity) >= maxHostEvidence {
			return nil
		}
		h = &hostIdentity{netbios: make(map[string]hostid.NBName)}
		s.identity[ip] = h
	}
	return h
}

func (h *hostIdentity) addNames(names []hostid.NBName) {
	for _, n := range names {
		if n.Name == "" || len(h.netbios) >= maxNetBIOSNamesPerHost {
			continue
		}
		h.netbios[n.String()] = hostid.NBName{Name: n.Name, Suffix: n.Suffix, Group: n.Group}
	}
}

// observeNBNS records an NBNS message: names bound to their own addresses
// (registrations, name query answers) and a node status reply, which describes
// the host that sent it.
func (s *hostEvidenceStore) observeNBNS(srcIP string, m hostid.NBNSMessage) {
	for _, n := range m.Names {
		if h := s.host(n.IP); h != nil {
			h.addNames([]hostid.NBName{n})
		}
	}
	if len(m.Status) > 0 || m.StatusMAC != "" {
		if h := s.host(srcIP); h != nil {
			h.addNames(m.Status)
			if m.StatusMAC != "" {
				h.nbMAC = m.StatusMAC
			}
		}
	}
}

// observeSMB records one TCP payload that starts a session service frame.
// clientIP and serverIP follow the port: the server is the side on 445 or 139.
func (s *hostEvidenceStore) observeSMB(srcIP string, srcIsServer bool, payload []byte) {
	hdr, ok := hostid.ParseNBSS(payload)
	if !ok {
		return
	}
	body := payload[4:]
	if hdr.Length < len(body) {
		body = body[:hdr.Length]
	}
	h := s.host(srcIP)
	if h == nil {
		return
	}
	if hdr.Type == hostid.NBSSRequest {
		if r, ok := hostid.DecodeSessionRequest(body); ok && !srcIsServer && r.Calling.Name != "" {
			h.calling = r.Calling.String()
			h.addNames([]hostid.NBName{r.Calling})
		}
		return
	}
	if hdr.Type != hostid.NBSSMessage {
		return
	}
	info, ok := hostid.DecodeSMB(body)
	if !ok {
		return
	}
	smb := &h.smb
	switch info.Kind {
	case hostid.SMB1:
		if info.Response {
			smb.SMB1 = true // a server answering in SMB1 speaks it
		}
	case hostid.SMBEncrypted:
		smb.Encrypted = true
	}
	if info.Dialect != "" {
		smb.Dialect = info.Dialect
		smb.SigningEnabled = &info.SigningEnabled
		smb.SigningRequired = &info.SigningRequired
		smb.ServerGUID = info.GUID
		smb.SystemTime, smb.StartTime = info.SystemTime, info.ServerStartTime
	}
	if len(info.OfferedDialects) > 0 {
		smb.OfferedDialects = info.OfferedDialects
		if len(smb.OfferedDialects) > maxSMBDialects {
			smb.OfferedDialects = smb.OfferedDialects[:maxSMBDialects]
		}
		smb.ClientGUID = info.GUID
		smb.ClientSigning = &info.SigningRequired
	}
	if n := info.NTLM; n != nil {
		smb.applyNTLM(n)
	}
}

func (smb *smbIdentity) applyNTLM(n *hostid.NTLMMessage) {
	switch n.Type {
	case 2: // CHALLENGE: the server's own names
		smb.NetBIOSComputer, smb.NetBIOSDomain = n.NetBIOSComputer, n.NetBIOSDomain
		smb.DNSComputer, smb.DNSDomain = n.DNSComputer, n.DNSDomain
	case 3: // AUTHENTICATE: the client's domain and machine; the user name is not kept
		smb.Domain, smb.Workstation = n.Domain, n.Workstation
	}
	if n.Version != nil {
		smb.WindowsVersion = n.Version.String()
	}
}

// netbiosData is the "netbios" entry of a device's additional data.
func (h *hostIdentity) netbiosData() map[string]interface{} {
	if len(h.netbios) == 0 && h.nbMAC == "" && h.calling == "" {
		return nil
	}
	out := map[string]interface{}{}
	if len(h.netbios) > 0 {
		names := make([]string, 0, len(h.netbios))
		for k := range h.netbios {
			names = append(names, k)
		}
		sort.Strings(names)
		out["names"] = names
	}
	if h.nbMAC != "" {
		out["mac"] = h.nbMAC
	}
	if h.calling != "" {
		out["session_calling_name"] = h.calling
	}
	if c := h.computerName(); c != "" {
		out["computer_name"] = c
	}
	if w := h.workgroup(); w != "" {
		out["workgroup"] = w
	}
	return out
}

// computerName is the unique workstation name <00>, falling back to the
// session-request name. Names are sorted so the result does not depend on
// map order.
func (h *hostIdentity) computerName() string {
	var best string
	for _, n := range h.netbios {
		if n.Suffix == hostid.SuffixWorkstation && !n.Group && (best == "" || n.Name < best) {
			best = n.Name
		}
	}
	return best
}

// workgroup is the group name <00>: the workgroup or domain the host is in.
func (h *hostIdentity) workgroup() string {
	var best string
	for _, n := range h.netbios {
		if n.Suffix == hostid.SuffixWorkstation && n.Group && (best == "" || n.Name < best) {
			best = n.Name
		}
	}
	return best
}

// smbData is the "smb" entry of a device's additional data, nil if empty.
func (smb *smbIdentity) data() map[string]interface{} {
	out := map[string]interface{}{}
	set := func(k string, v string) {
		if v != "" {
			out[k] = v
		}
	}
	set("dialect", smb.Dialect)
	set("server_guid", smb.ServerGUID)
	set("client_guid", smb.ClientGUID)
	set("netbios_computer", smb.NetBIOSComputer)
	set("netbios_domain", smb.NetBIOSDomain)
	set("dns_computer", smb.DNSComputer)
	set("dns_domain", smb.DNSDomain)
	set("domain", smb.Domain)
	set("workstation", smb.Workstation)
	set("windows_version", smb.WindowsVersion)
	if smb.SigningEnabled != nil {
		out["signing_enabled"] = *smb.SigningEnabled
		out["signing_required"] = *smb.SigningRequired
	}
	if smb.ClientSigning != nil {
		out["client_signing_required"] = *smb.ClientSigning
	}
	if len(smb.OfferedDialects) > 0 {
		out["offered_dialects"] = smb.OfferedDialects
	}
	if smb.SMB1 {
		out["smb1"] = true
	}
	if smb.Encrypted {
		out["encrypted"] = true
	}
	if !smb.SystemTime.IsZero() {
		out["server_time"] = smb.SystemTime.Format(time.RFC3339)
		if !smb.StartTime.IsZero() && smb.SystemTime.After(smb.StartTime) {
			out["uptime_seconds"] = int64(smb.SystemTime.Sub(smb.StartTime).Seconds())
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// applyIdentity writes NetBIOS and SMB identity into the devices. A hostname
// is taken from it only when nothing better set one (DHCP is applied first).
func (p *GopacketParser) applyIdentity() {
	s := p.evidence()
	ips := make([]string, 0, len(s.identity))
	for ip := range s.identity {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		h := s.identity[ip]
		dev := p.deviceManager.GetDevice(ip, "IP")
		if dev == nil {
			continue
		}
		if dev.Hostname == "" {
			dev.Hostname = firstNonEmpty(h.computerName(), h.smb.NetBIOSComputer, h.smb.Workstation)
		}
		if d := h.netbiosData(); d != nil {
			p.storeEvidence(dev, "netbios", d)
		}
		if d := h.smb.data(); d != nil {
			p.storeEvidence(dev, "smb", d)
		}
		if h.smb.DNSComputer != "" {
			if err := p.AssociateDNSNameToIP(ip, h.smb.DNSComputer); err != nil {
				log.Debug().Err(err).Str("ip", ip).Msg("NTLM DNS name not stored")
			}
		}
	}
}

func (p *GopacketParser) storeEvidence(dev *model.Device, key string, v map[string]interface{}) {
	if err := setAdditionalData(dev, key, v); err != nil {
		log.Debug().Err(err).Str("ip", dev.Address).Str("key", key).Msg("host identity not stored")
	}
}
