package dns

import "github.com/InfraSecConsult/pcap-importer-go/internal/repository"

// DNSProcessor defines the contract for extracting and storing DNS transactions after import.
type DNSProcessor interface {
	Process(repo repository.Repository) error
}
