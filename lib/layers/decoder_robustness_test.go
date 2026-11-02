package lib_layers

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// robustnessDecoders are the decoders of this package that parse attacker-controlled bytes.
var robustnessDecoders = map[string]gopacket.DecodeFunc{
	"CiscoDiscovery":     decodeCiscoDiscovery,
	"CiscoDiscoveryInfo": decodeCiscoDiscoveryInfo,
	"EIGRP":              decodeEIGRP,
	"IGMP":               decodeIGMP,
	"LLDP":               decodeLinkLayerDiscovery,
	"MDNS":               decodeMDNS,
	"HTTP":               decodeHTTP,
	"ModbusTCP":          decodeModbusTCP,
	"NetBIOS":            DecodeNetBIOS,
	"SMBMailSlot":        DecodeSMBMailSlot,
	"OPCUA":              decodeOPCUA,
	"SSDP":               decodeSSDP,
	"TLS":                decodeTLS,
	"SMBProtocol":        DecodeSMBProtocol,
	"STP":                decodeSTP,
	"CIFSBrowser":        DecodeCIFSBrowserLayer,
}

// panicSite decodes data with recovery off and returns the first stack frame inside
// this package when the decoder panics, or "" when it does not.
func panicSite(fn gopacket.DecodeFunc, data []byte) (site string) {
	defer func() {
		if r := recover(); r != nil {
			site = fmt.Sprint(r)
			for _, line := range strings.Split(string(debug.Stack()), "\n") {
				if (strings.Contains(line, "lib/layers/") || strings.Contains(line, "gopacket@")) && !strings.Contains(line, "_test.go") {
					site = strings.TrimSpace(line)
					if i := strings.Index(site, " +0x"); i > 0 {
						site = site[:i]
					}
					return
				}
			}
		}
	}()
	gopacket.NewPacket(data, fn, gopacket.DecodeOptions{SkipDecodeRecovery: true})
	return ""
}

// TestDecodersDoNotPanicOnHostileInput reports every distinct panic site. Gopacket's
// recovery keeps an import alive, but a panicking decoder loses the whole frame.
func TestDecodersDoNotPanicOnHostileInput(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for name, fn := range robustnessDecoders {
		sites := map[string]int{}
		for i := 0; i < 200000; i++ {
			data := make([]byte, rng.Intn(120))
			rng.Read(data)
			if len(data) > 0 && i%2 == 0 {
				data[0] = byte(1 + rng.Intn(2)) // valid CDP version, so TLV parsing is reached
			}
			if len(data) > 8 && i%3 == 0 { // small values reach more length checks
				for j := 1; j < len(data); j++ {
					data[j] &= 0x1f
				}
			}
			if s := panicSite(fn, data); s != "" {
				sites[s]++
			}
		}
		for s, n := range sites {
			t.Errorf("%s panics (%d/200000): %s", name, n, s)
		}
	}
}

// TestStockGopacketCDPPanicIsRecovered documents that gopacket's own CDP decoder panics on
// hostile input (for example a payload shorter than 4 bytes) and that decode recovery,
// which the parser keeps on, turns that into a decode failure instead of an abort.
func TestStockGopacketCDPPanicIsRecovered(t *testing.T) {
	hostile := [][]byte{{}, {1}, {1, 2, 3}}
	for _, data := range hostile {
		if panicSite(gopacket.DecodeFunc(layers.LayerTypeCiscoDiscovery.Decode), data) == "" {
			t.Logf("stock decoder no longer panics on %v; this test can be dropped", data)
		}
		p := gopacket.NewPacket(data, layers.LayerTypeCiscoDiscovery, gopacket.Default)
		if p.ErrorLayer() == nil {
			t.Errorf("expected a decode failure for %v", data)
		}
	}
}

func TestCiscoDiscoveryInfoMalformedPowerTLVsDoNotPanic(t *testing.T) {
	tests := []struct {
		name    string
		tlvType CDPTLVType
	}{
		{name: "power requested", tlvType: CDPTLVPowerRequested},
		{name: "power available", tlvType: CDPTLVPowerAvailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for valueLen := 5; valueLen <= 7; valueLen++ {
				data := make([]byte, 4+valueLen)
				binary.BigEndian.PutUint16(data[0:2], uint16(tt.tlvType))
				binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
				if s := panicSite(decodeCiscoDiscoveryInfo, data); s != "" {
					t.Fatalf("unexpected panic for valueLen=%d: %s", valueLen, s)
				}
			}
		})
	}
}
