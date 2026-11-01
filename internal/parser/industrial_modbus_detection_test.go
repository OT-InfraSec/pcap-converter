package parser

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/detect"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real request from the minicps testbed capture: FC3, 4 registers from 0x37d0.
var modbusReadRequest = []byte{0x2d, 0xe9, 0x00, 0x00, 0x00, 0x06, 0x03, 0x03, 0x37, 0xd0, 0x00, 0x04}

func TestParseModbusTCP_Detection(t *testing.T) {
	p := newENIPTestParser(t)
	ts := time.Unix(1700000000, 0)
	tcp := func(src, dst uint16, syn bool, payload []byte) gopacket.Packet {
		return buildTransportPacket(t, &layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst), SYN: syn, ACK: !syn}, nil, payload)
	}

	t.Run("valid request on 502", func(t *testing.T) {
		info := p.parseModbusTCP(tcp(50000, 502, false, modbusReadRequest), ts)
		require.NotNil(t, info)
		assert.Equal(t, "modbus", info.Protocol)
		assert.Equal(t, 0.9, info.Confidence)
		assert.Equal(t, uint16(502), info.Port)
		assert.Equal(t, "outbound", info.Direction)
	})

	t.Run("response from 502 is inbound", func(t *testing.T) {
		info := p.parseModbusTCP(tcp(502, 50000, false, modbusReadRequest), ts)
		require.NotNil(t, info)
		assert.Equal(t, "inbound", info.Direction)
	})

	t.Run("content on another port is detected with lower confidence", func(t *testing.T) {
		info := p.parseModbusTCP(tcp(50000, 1502, false, modbusReadRequest), ts)
		require.NotNil(t, info)
		assert.Equal(t, 0.8, info.Confidence)
	})

	t.Run("garbage on 502 is not Modbus", func(t *testing.T) {
		assert.Nil(t, p.parseModbusTCP(tcp(50000, 502, false, []byte("GET / HTTP/1.1\r\nHost: plc\r\n")), ts))
	})

	t.Run("non-zero protocol id is not Modbus", func(t *testing.T) {
		bad := append([]byte(nil), modbusReadRequest...)
		bad[3] = 1
		assert.Nil(t, p.parseModbusTCP(tcp(50000, 502, false, bad), ts))
	})

	t.Run("handshake segment is below the default threshold", func(t *testing.T) {
		pkt := tcp(50000, 502, true, nil)
		info := p.parseModbusTCP(pkt, ts)
		require.NotNil(t, info)
		assert.Less(t, info.Confidence, DefaultIndustrialParserConfig().ConfidenceThreshold)
		got, err := p.ParseIndustrialProtocols(pkt)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("UDP is never Modbus/TCP", func(t *testing.T) {
		pkt := buildTransportPacket(t, nil, &layers.UDP{SrcPort: 50000, DstPort: 502}, modbusReadRequest)
		assert.Nil(t, p.parseModbusTCP(pkt, ts))
	})
}

func TestConnectionLabeler_Modbus(t *testing.T) {
	l := newConnectionLabeler(detect.Default())
	mk := func(src, dst uint16, syn bool, payload []byte) string {
		pkt := buildTransportPacket(t, &layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst), SYN: syn, ACK: !syn}, nil, payload)
		srcIP, dstIP := "10.0.0.1", "10.0.0.2"
		if src < dst {
			srcIP, dstIP = dstIP, srcIP
		}
		return l.Label(pkt, srcIP, dstIP, model.VLANTag{})
	}
	assert.Equal(t, "modbus", mk(50000, 502, true, nil))
	assert.Equal(t, "modbus", mk(502, 50000, true, nil))
	assert.Equal(t, "modbus", mk(50000, 502, false, modbusReadRequest))
	assert.Equal(t, "modbus", mk(502, 50000, false, nil))
	// Mid-ADU continuation after recognition keeps the label.
	assert.Equal(t, "modbus", mk(502, 50000, false, []byte("rest of a long response........")))
}

func TestModbusConnectionIsOneFlow(t *testing.T) {
	repo, err := repository.NewSQLiteRepository(filepath.Join(t.TempDir(), "db.sqlite"))
	require.NoError(t, err)
	cli := func(f layers.TCP, payload []byte) gopacket.Packet {
		f.SrcPort, f.DstPort = 50000, 502
		return buildTransportPacket(t, &f, nil, payload)
	}
	pkts := []gopacket.Packet{
		cli(layers.TCP{SYN: true}, nil),
		cli(layers.TCP{ACK: true}, nil),
		cli(layers.TCP{ACK: true, PSH: true}, modbusReadRequest),
		cli(layers.TCP{ACK: true}, nil),
		cli(layers.TCP{ACK: true, PSH: true}, modbusReadRequest),
		cli(layers.TCP{ACK: true, FIN: true}, nil),
	}
	require.NoError(t, NewGopacketParser(writePCAP(t, pkts), repo, "").ParseFile())

	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	require.Len(t, flows, 1, "handshake, data and teardown must be one flow")
	assert.Equal(t, "modbus", flows[0].Protocol)
	assert.Equal(t, 6, flows[0].PacketCountOut+flows[0].PacketCountIn)
}

func TestNonModbusOnPort502IsNotLabelled(t *testing.T) {
	repo, err := repository.NewSQLiteRepository(filepath.Join(t.TempDir(), "db.sqlite"))
	require.NoError(t, err)
	pkts := []gopacket.Packet{
		buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 502, ACK: true, PSH: true}, nil,
			[]byte("GET /index.html HTTP/1.1\r\nHost: plc\r\n\r\n")),
		buildTransportPacket(t, &layers.TCP{SrcPort: 50000, DstPort: 502, ACK: true}, nil, nil),
	}
	require.NoError(t, NewGopacketParser(writePCAP(t, pkts), repo, "").ParseFile())
	flows, err := repo.GetFlows("", nil)
	require.NoError(t, err)
	for _, f := range flows {
		assert.NotEqual(t, "modbus", f.Protocol, "flow %+v", f)
	}
}
