package model

import (
	"fmt"
	"net/netip"
	"time"
)

// Subnet sources. Only dhcp and ra are written today; the others are reserved
// so the visualizer contract stays stable when more evidence is decoded.
const (
	SubnetSourceDHCP     = "dhcp"
	SubnetSourceRA       = "ra"
	SubnetSourceCDP      = "cdp"
	SubnetSourceEIGRP    = "eigrp"
	SubnetSourceOSPF     = "ospf"
	SubnetSourceInferred = "inferred"
)

// Subnet kinds tell the visualizer what a prefix means. A delegated prefix
// (DHCPv6 IA_PD) is handed to a router for downstream use and need not be
// on-link in the VLAN where it was observed.
const (
	SubnetKindOnLink    = "on-link"
	SubnetKindDelegated = "delegated"
)

// Subnet is an IP prefix observed in a VLAN. VlanID is the outer tag; nil means
// untagged. The same prefix in two VLANs, or from two sources, is two rows.
type Subnet struct {
	ID        int64
	TenantID  string
	CIDR      string
	VlanID    *int
	Source    string
	Kind      string
	FirstSeen time.Time
	LastSeen  time.Time
}

// CanonicalCIDR returns the masked prefix in its canonical text form.
func CanonicalCIDR(p netip.Prefix) string {
	return p.Masked().String()
}

// Validate checks that the CIDR is canonical and the source is known.
func (s *Subnet) Validate() error {
	p, err := netip.ParsePrefix(s.CIDR)
	if err != nil {
		return fmt.Errorf("invalid subnet CIDR %q: %w", s.CIDR, err)
	}
	if CanonicalCIDR(p) != s.CIDR {
		return fmt.Errorf("subnet CIDR %q is not canonical (want %s)", s.CIDR, CanonicalCIDR(p))
	}
	switch s.Kind {
	case SubnetKindOnLink, SubnetKindDelegated:
	default:
		return fmt.Errorf("unknown subnet kind %q", s.Kind)
	}
	switch s.Source {
	case SubnetSourceDHCP, SubnetSourceRA, SubnetSourceCDP, SubnetSourceEIGRP, SubnetSourceOSPF, SubnetSourceInferred:
		return nil
	}
	return fmt.Errorf("unknown subnet source %q", s.Source)
}
