package helper

import "github.com/google/gopacket"

// TestPacketBuilder is a mock implementation of gopacket.PacketBuilder for testing
type TestPacketBuilder struct {
	Packet          gopacket.Packet
	AddedLayer      gopacket.Layer
	NextDecoderType gopacket.LayerType
	Layers          []gopacket.Layer
}

func (pb *TestPacketBuilder) AddLayer(l gopacket.Layer) {
	pb.AddedLayer = l
	pb.Layers = append(pb.Layers, l)
}

func (pb *TestPacketBuilder) NextDecoder(next gopacket.Decoder) error {
	// Store the layer type if it's a LayerType
	if lt, ok := next.(gopacket.LayerType); ok {
		pb.NextDecoderType = lt
	}
	return nil
}

func (pb *TestPacketBuilder) DumpPacketData() {
}

func (pb *TestPacketBuilder) SetTruncated() {
}

func (pb *TestPacketBuilder) DecodeOptions() *gopacket.DecodeOptions {
	return &gopacket.DecodeOptions{}
}

func (pb *TestPacketBuilder) SetApplicationLayer(l gopacket.ApplicationLayer) {
}

func (pb *TestPacketBuilder) SetErrorLayer(l gopacket.ErrorLayer) {
}

func (pb *TestPacketBuilder) SetLinkLayer(l gopacket.LinkLayer) {
}

func (pb *TestPacketBuilder) SetNetworkLayer(l gopacket.NetworkLayer) {
}

func (pb *TestPacketBuilder) SetTransportLayer(l gopacket.TransportLayer) {
}
