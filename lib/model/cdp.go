package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// MaxVLANID is the highest usable 802.1Q VLAN ID; 4095 is reserved.
const MaxVLANID = 4094

// CDPNeighbor is one Cisco Discovery Protocol advertisement of an interface
// (SrcMAC + PortID), as seen in a VLAN. VlanID is the outer tag of the frame (nil =
// untagged). NativeVLAN and ManagementVLAN are nil when the neighbor did not
// advertise a usable value. Addresses, MgmtAddresses and Capabilities are
// comma-joined text, like devices.vlans.
type CDPNeighbor struct {
	ID              int64
	TenantID        string
	SrcMAC          string
	PortID          string
	VlanID          *int
	DeviceID        string
	Platform        string
	SoftwareVersion string
	SysName         string
	Capabilities    string
	Addresses       string
	MgmtAddresses   string
	NativeVLAN      *int
	ManagementVLAN  *int
	Fingerprint     string
	FirstSeen       time.Time
	LastSeen        time.Time
}

// VLANFromWire converts an advertised VLAN number to its stored form: 0 means
// "not set" and values above 4094 are invalid, both become nil.
func VLANFromWire(v uint16) *int {
	if v == 0 || v > MaxVLANID {
		return nil
	}
	id := int(v)
	return &id
}

// ComputeFingerprint hashes every advertised value (not the identity fields or
// timestamps). Fields are length-prefixed so that no two different value sets
// share a byte stream.
func (n *CDPNeighbor) ComputeFingerprint() string {
	h := sha256.New()
	write := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	vlan := func(v *int) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprint(*v)
	}
	for _, s := range []string{n.DeviceID, n.Platform, n.SoftwareVersion, n.SysName, n.Capabilities,
		n.Addresses, n.MgmtAddresses, vlan(n.NativeVLAN), vlan(n.ManagementVLAN)} {
		write(s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Validate checks the identity fields, the VLAN ranges and that the fingerprint
// matches the values, so rows with the same key cannot silently disagree.
func (n *CDPNeighbor) Validate() error {
	if n.SrcMAC == "" {
		return fmt.Errorf("cdp neighbor has no source MAC")
	}
	for name, v := range map[string]*int{"vlan": n.VlanID, "native VLAN": n.NativeVLAN, "management VLAN": n.ManagementVLAN} {
		if v != nil && (*v < 1 || *v > MaxVLANID) {
			return fmt.Errorf("cdp neighbor %s %d out of range 1..%d", name, *v, MaxVLANID)
		}
	}
	if want := n.ComputeFingerprint(); n.Fingerprint != want {
		return fmt.Errorf("cdp neighbor fingerprint %q does not match its values (want %s)", n.Fingerprint, want)
	}
	return nil
}
