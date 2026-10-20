package parser

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

// FuzzCDPEvidence feeds arbitrary bytes into the decoded fields the extractors read.
// Invariants: no panic, stored strings bounded and clean, prefixes valid and masked,
// VLANs in range, and the neighbor always passes model validation after fingerprinting.
func FuzzCDPEvidence(f *testing.F) {
	f.Add("sw1", "Gi1/0/1", []byte{10, 0, 0, 1}, []byte{10, 0, 1, 0}, byte(24), uint16(10), uint16(99))
	f.Add("\x00\xff\n", "", []byte{1, 2, 3}, []byte{255, 255, 255, 255}, byte(0), uint16(4095), uint16(0))
	f.Add("a", "b", make([]byte, 16), make([]byte, 16), byte(128), uint16(65535), uint16(1))
	f.Fuzz(func(t *testing.T, dev, port string, addr, prefixIP []byte, ones byte, native, mgmt uint16) {
		info := &layers.CiscoDiscoveryInfo{
			DeviceID: dev, PortID: port, SysName: dev, Platform: port, Version: dev,
			Addresses: []net.IP{addr}, MgmtAddresses: []net.IP{addr},
			NativeVLAN: native,
			IPPrefixes: []net.IPNet{{IP: prefixIP, Mask: net.CIDRMask(int(ones), len(prefixIP)*8)}},
		}
		info.CDPHello.ManagementVLAN = mgmt

		if n, ok := cdpNeighborFromInfo(info); ok {
			for _, s := range []string{n.DeviceID, n.PortID, n.Platform, n.SoftwareVersion, n.SysName} {
				if len(s) > maxCDPStringBytes {
					t.Fatalf("string too long: %d", len(s))
				}
				for _, r := range s {
					if r < 0x20 || r == 0x7f {
						t.Fatalf("control character in %q", s)
					}
				}
			}
			n.SrcMAC = "00:00:00:00:00:01"
			n.Fingerprint = n.ComputeFingerprint()
			if err := n.Validate(); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range cdpPrefixes(info) {
			if !p.IsValid() || p != p.Masked() || p.Bits() < 1 {
				t.Fatalf("bad prefix %v", p)
			}
		}
	})
}
