package parser

import (
	"fmt"

	"pcap-importer-golang/internal/model"
	"pcap-importer-golang/internal/repository"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type GopacketParser struct {
	PcapFile string
}

func NewGopacketParser(pcapFile string) *GopacketParser {
	return &GopacketParser{PcapFile: pcapFile}
}

func (p *GopacketParser) ParseFile(repo repository.Repository) error {
	handle, err := pcap.OpenOffline(p.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetID := int64(0)
	for packet := range packetSource.Packets() {
		layersMap := make(map[string]interface{})
		protocols := []string{}

		// Ethernet
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth := ethLayer.(*layers.Ethernet)
			layersMap["ethernet"] = map[string]interface{}{
				"src_mac":       eth.SrcMAC.String(),
				"dst_mac":       eth.DstMAC.String(),
				"ethernet_type": eth.EthernetType.String(),
			}
			protocols = append(protocols, "ethernet")
		}
		// IPv4
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			layersMap["ip"] = map[string]interface{}{
				"src_ip":   ip4.SrcIP.String(),
				"dst_ip":   ip4.DstIP.String(),
				"protocol": ip4.Protocol.String(),
				"ttl":      ip4.TTL,
			}
			protocols = append(protocols, "ipv4")
		}
		// IPv6
		if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6 := ip6Layer.(*layers.IPv6)
			layersMap["ipv6"] = map[string]interface{}{
				"src_ip":      ip6.SrcIP.String(),
				"dst_ip":      ip6.DstIP.String(),
				"next_header": ip6.NextHeader.String(),
				"hop_limit":   ip6.HopLimit,
			}
			protocols = append(protocols, "ipv6")
		}
		// TCP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			layersMap["tcp"] = map[string]interface{}{
				"src_port": tcp.SrcPort.String(),
				"dst_port": tcp.DstPort.String(),
				"seq":      tcp.Seq,
				"ack":      tcp.Ack,
				"flags":    tcp.Flags,
			}
			protocols = append(protocols, "tcp")
		}
		// UDP
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			layersMap["udp"] = map[string]interface{}{
				"src_port": udp.SrcPort.String(),
				"dst_port": udp.DstPort.String(),
			}
			protocols = append(protocols, "udp")
		}
		// DNS
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			layersMap["dns"] = map[string]interface{}{
				"id":        dns.ID,
				"qr":        dns.QR,
				"opcode":    dns.OpCode.String(),
				"rcode":     dns.ResponseCode.String(),
				"questions": len(dns.Questions),
				"answers":   len(dns.Answers),
			}
			protocols = append(protocols, "dns")
		}

		timestamp := packet.Metadata().Timestamp
		length := len(packet.Data())
		modelPacket := &model.Packet{
			ID:        packetID,
			Timestamp: timestamp,
			Length:    length,
			Layers:    layersMap,
			Protocols: protocols,
		}
		if err := repo.AddPacket(modelPacket); err != nil {
			return fmt.Errorf("failed to add packet: %w", err)
		}
		packetID++
	}
	return nil
}
