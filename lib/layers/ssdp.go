// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"bufio"
	"errors"
	"fmt"
	"net/textproto"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SSDP represents a Simple Service Discovery Protocol packet
// SSDP is HTTP-like protocol transmitted over UDP for UPnP device discovery
type SSDP struct {
	BaseLayer
	Method     string            // HTTP method (NOTIFY, M-SEARCH, HTTP/1.1)
	RequestURI string            // Request URI (usually *)
	Version    string            // HTTP version
	StatusCode int               // HTTP status code (for responses)
	StatusMsg  string            // HTTP status message (for responses)
	Headers    map[string]string // HTTP headers
	IsResponse bool              // true if this is a response, false if request
}

// LayerType returns the layer type for SSDP
func (s *SSDP) LayerType() gopacket.LayerType {
	return LayerTypeSSDP
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (s *SSDP) CanDecode() gopacket.LayerClass {
	return LayerTypeSSDP
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (s *SSDP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer
func (s *SSDP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	_ = df // Suppress unused parameter warning

	if len(data) == 0 {
		return errors.New("SSDP packet is empty")
	}

	s.BaseLayer = BaseLayer{
		Contents: data,
		Payload:  nil,
	}

	// Convert bytes to string for parsing
	content := string(data)

	// Split into lines
	lines := strings.Split(content, "\r\n")
	if len(lines) < 1 {
		lines = strings.Split(content, "\n")
	}

	if len(lines) < 1 {
		return errors.New("SSDP packet has no content")
	}

	// Initialize headers map
	s.Headers = make(map[string]string)

	// Parse first line to determine if it's a request or response
	firstLine := strings.TrimSpace(lines[0])
	if firstLine == "" {
		return errors.New("SSDP packet has empty first line")
	}

	// Check if it's a response (starts with HTTP/)
	if strings.HasPrefix(firstLine, "HTTP/") {
		s.IsResponse = true
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			s.Version = parts[0]
			if len(parts) >= 3 {
				s.StatusMsg = parts[2]
			}
			// Parse status code
			var err error
			if _, err = fmt.Sscanf(parts[1], "%d", &s.StatusCode); err != nil {
				s.StatusCode = 0
			}
		}
	} else {
		// It's a request
		s.IsResponse = false
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 1 {
			s.Method = parts[0]
		}
		if len(parts) >= 2 {
			s.RequestURI = parts[1]
		}
		if len(parts) >= 3 {
			s.Version = parts[2]
		}
	}

	// Parse headers
	reader := strings.NewReader(strings.Join(lines[1:], "\r\n"))
	tp := textproto.NewReader(bufio.NewReader(reader))

	for {
		line, err := tp.ReadLine()
		if err != nil || line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			s.Headers[strings.ToUpper(key)] = value
		}
	}

	return nil
}

// String returns a string representation of the SSDP packet
func (s *SSDP) String() string {
	if s.IsResponse {
		return fmt.Sprintf("SSDP Response %d %s", s.StatusCode, s.StatusMsg)
	}
	return fmt.Sprintf("SSDP Request %s %s", s.Method, s.RequestURI)
}

// GetHeader returns the value of a header (case-insensitive)
func (s *SSDP) GetHeader(name string) (string, bool) {
	value, exists := s.Headers[strings.ToUpper(name)]
	return value, exists
}

// IsAlive returns true if this is a ssdp:alive notification
func (s *SSDP) IsAlive() bool {
	if nts, exists := s.GetHeader("NTS"); exists {
		return strings.ToLower(nts) == "ssdp:alive"
	}
	return false
}

// IsByeBye returns true if this is a ssdp:byebye notification
func (s *SSDP) IsByeBye() bool {
	if nts, exists := s.GetHeader("NTS"); exists {
		return strings.ToLower(nts) == "ssdp:byebye"
	}
	return false
}

// IsSearch returns true if this is an M-SEARCH request
func (s *SSDP) IsSearch() bool {
	return !s.IsResponse && strings.ToUpper(s.Method) == "M-SEARCH"
}

// IsNotify returns true if this is a NOTIFY request
func (s *SSDP) IsNotify() bool {
	return !s.IsResponse && strings.ToUpper(s.Method) == "NOTIFY"
}

// LayerTypeSSDP is the layer type for SSDP packets
var LayerTypeSSDP = gopacket.RegisterLayerType(
	1001, // Layer type number - using a high number to avoid conflicts
	gopacket.LayerTypeMetadata{
		Name:    "SSDP",
		Decoder: gopacket.DecodeFunc(decodeSSDP),
	},
)

// decodeSSDP is the decoder function for SSDP packets
func decodeSSDP(data []byte, p gopacket.PacketBuilder) error {
	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(ssdp)
	return p.NextDecoder(ssdp.NextLayerType())
}

// RegisterSSDP registers the SSDP protocol with the UDP port 1900
func RegisterSSDP() {
	// SSDP typically uses UDP port 1900
	layers.RegisterUDPPortLayerType(1900, LayerTypeSSDP)
}

// InitLayerSSDP initializes the SSDP layer for gopacket
func InitLayerSSDP() {
	RegisterSSDP()
}
