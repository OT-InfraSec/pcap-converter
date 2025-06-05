package parser

import "pcap-importer-golang/internal/repository"

// PacketParser defines the contract for parsing a PCAP file and storing results in a repository.
type PacketParser interface {
	ParseFile(repo repository.Repository) error
}
