package lib_layers

import (
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestSTP_DecodeFromBytes tests the DecodeFromBytes method
func TestSTP_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Valid STP packet (minimal)",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "Empty packet",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "Single byte",
			data:    []byte{0x00},
			wantErr: false,
		},
		{
			name: "Typical STP BPDU (35 bytes)",
			data: []byte{
				0x00, 0x00, // Protocol ID
				0x00,                                           // Version
				0x00,                                           // BPDU Type
				0x00,                                           // Flags
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Root ID
				0x00, 0x00, 0x00, 0x00, // Root Path Cost
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Bridge ID
				0x80, 0x00, // Port ID
				0x00, 0x00, // Message Age
				0x00, 0x00, // Max Age
				0x00, 0x00, // Hello Time
				0x00, 0x00, // Forward Delay
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &STP{}
			err := s.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSTP_LayerType tests the LayerType method
func TestSTP_LayerType(t *testing.T) {
	s := &STP{}
	assert.Equal(t, layers.LayerTypeSTP, s.LayerType())
}

// TestSTP_CanDecode tests the CanDecode method
func TestSTP_CanDecode(t *testing.T) {
	s := &STP{}
	assert.Equal(t, layers.LayerTypeSTP, s.CanDecode())
}

// TestSTP_NextLayerType tests the NextLayerType method
func TestSTP_NextLayerType(t *testing.T) {
	s := &STP{}
	assert.Equal(t, gopacket.LayerTypePayload, s.NextLayerType())
}

// TestDecodeSTP tests the decodeSTP function
func TestDecodeSTP(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "Minimal STP data",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name: "Full STP BPDU",
			data: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00,
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x80, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := gopacket.NewPacket(tt.data, layers.LayerTypeEthernet, gopacket.Default)
			builder := &helper.TestPacketBuilder{Packet: pb}

			err := decodeSTP(tt.data, builder)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, builder.AddedLayer, "Should have added a layer")

				if builder.AddedLayer != nil {
					stpLayer, ok := builder.AddedLayer.(*STP)
					assert.True(t, ok, "Added layer should be of type *STP")
					if ok {
						assert.Equal(t, tt.data, stpLayer.Contents, "Contents should match input data")
						assert.Equal(t, layers.LayerTypeSTP, stpLayer.LayerType())
					}
				}
			}
		})
	}
}

// TestSTP_BaseLayerImplementation tests that STP properly embeds BaseLayer
func TestSTP_BaseLayerImplementation(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	s := &STP{}

	// Decode some data
	err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	assert.NoError(t, err)

	// Test BaseLayer methods are accessible
	// These methods come from the embedded layers.BaseLayer
	pb := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	builder := &helper.TestPacketBuilder{Packet: pb}

	err = decodeSTP(data, builder)
	assert.NoError(t, err)

	if builder.AddedLayer != nil {
		stpLayer := builder.AddedLayer.(*STP)
		assert.NotNil(t, stpLayer.Contents)
		assert.NotNil(t, stpLayer.LayerContents())
	}
}

// TestSTP_EdgeCases tests edge cases
func TestSTP_EdgeCases(t *testing.T) {
	t.Run("Very large packet", func(t *testing.T) {
		data := make([]byte, 1500)
		for i := range data {
			data[i] = byte(i % 256)
		}

		s := &STP{}
		err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		assert.NoError(t, err)
	})

	t.Run("All zeros", func(t *testing.T) {
		data := make([]byte, 100)
		s := &STP{}
		err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		assert.NoError(t, err)
	})

	t.Run("All 0xFF", func(t *testing.T) {
		data := make([]byte, 100)
		for i := range data {
			data[i] = 0xFF
		}
		s := &STP{}
		err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		assert.NoError(t, err)
	})
}

// TestSTP_LayerIntegration tests integration with gopacket layer system
func TestSTP_LayerIntegration(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	pb := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	builder := &helper.TestPacketBuilder{Packet: pb}

	err := decodeSTP(data, builder)
	assert.NoError(t, err)
	assert.NotNil(t, builder.AddedLayer)

	// Verify layer type matches
	if builder.AddedLayer != nil {
		assert.Equal(t, layers.LayerTypeSTP, builder.AddedLayer.LayerType())
	}
}
