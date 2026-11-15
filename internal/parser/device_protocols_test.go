package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHighestProtocol(t *testing.T) {
	tests := []struct {
		name      string
		flowProto string
		protocols []string
		want      string
	}{
		{"bare ethernet frame", "", []string{"ethernet"}, ""},
		{"plain tcp", "tcp", []string{"ethernet", "ipv4", "tcp"}, "tcp"},
		{"plain udp", "udp", []string{"ethernet", "ipv4", "udp"}, "udp"},
		{"tls is above tcp", "tcp", []string{"ethernet", "ipv4", "tcp", "tls"}, "tls"},
		{"http flow label wins", "http", []string{"ethernet", "ipv4", "tcp", "http"}, "http"},
		{"modbus is tcp only", "modbus", []string{"ethernet", "ipv4", "tcp", "modbus"}, "modbus"},
		{"label already names transport", "EtherNet/IP(UDP)", []string{"ethernet", "ipv4", "udp"}, "EtherNet/IP(UDP)"},
		{"neutral label is kept", "s7+s7commplus", []string{"ethernet", "ipv4", "tcp"}, "s7+s7commplus"},
		{"dns over udp", "dns", []string{"ethernet", "ipv4", "udp", "dns"}, "dns(UDP)"},
		{"dns over tcp", "dns", []string{"ethernet", "ipv4", "tcp", "dns"}, "dns(TCP)"},
		{"dnp3 over udp", "dnp3", []string{"ethernet", "ipv4", "udp", "dnp3"}, "dnp3(UDP)"},
		{"mdns is udp only", "mdns", []string{"ethernet", "ipv4", "udp", "mdns"}, "mdns"},
		{"arp", "arp", []string{"ethernet", "arp"}, "arp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HighestProtocol(tt.flowProto, tt.protocols))
		})
	}
}

func TestDefaultDeviceManager_IsExternalAndProtocolList(t *testing.T) {
	dm := NewDefaultDeviceManager("t", 1)
	ts := time.Now()
	dm.UpsertDevice("8.8.8.8", "IP", ts, "", "00:11:22:33:44:55", "", true)
	dm.UpsertDevice("10.0.0.1", "IP", ts, "", "00:11:22:33:44:66", "", false)
	dm.UpsertDevice("10.0.0.1", "IP", ts, "", "", "", false) // update must not change the flag

	assert.True(t, dm.GetDevice("8.8.8.8", "IP").IsExternal)
	assert.False(t, dm.GetDevice("10.0.0.1", "IP").IsExternal)

	dm.RecordProtocol("10.0.0.1", "IP", "dns(UDP)")
	dm.RecordProtocol("10.0.0.1", "IP", "dns(UDP)")
	dm.RecordProtocol("10.0.0.1", "IP", "dns(TCP)")
	dm.RecordProtocol("10.0.0.1", "IP", "")
	dm.RecordProtocol("10.0.0.9", "IP", "tls") // unknown device is ignored

	assert.ElementsMatch(t, []string{"dns(UDP)", "dns(TCP)"}, dm.GetDevice("10.0.0.1", "IP").ProtocolList.List())
	assert.Equal(t, 0, dm.GetDevice("8.8.8.8", "IP").ProtocolList.Size())
}
