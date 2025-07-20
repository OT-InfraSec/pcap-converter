package parser

// PacketParser defines the contract for parsing a PCAP file and storing results in a repository.
type PacketParser interface {
	ParseFile() error
}
