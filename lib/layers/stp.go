// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// STP decode spanning tree protocol packets to transport BPDU (bridge protocol data unit) message.
type STP struct {
	layers.BaseLayer
}

func (s *STP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	//TODO implement me
	return nil
}

func (s *STP) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeSTP
}

func (s *STP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// LayerType returns gopacket.LayerTypeSTP.
func (s *STP) LayerType() gopacket.LayerType { return layers.LayerTypeSTP }

func decodeSTP(data []byte, p gopacket.PacketBuilder) error {
	stp := &STP{}
	stp.Contents = data[:]
	// TODO:  parse the STP protocol into actual subfields.
	p.AddLayer(stp)
	return nil
}
