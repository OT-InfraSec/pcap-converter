package main

import (
	"fmt"
	"log"
	"os"

	"pcap-importer-golang/internal/dns"
	"pcap-importer-golang/internal/parser"
	"pcap-importer-golang/internal/repository"

	"github.com/spf13/cobra"
)

// DependencyProvider allows injection for testability
// (in production, use real implementations)
type DependencyProvider struct {
	Parser       parser.PacketParser
	Repository   repository.Repository
	DNSProcessor dns.DNSProcessor
}

// newRootCmd wires up the CLI with the given dependencies
func newRootCmd(provider *DependencyProvider) *cobra.Command {
	var (
		dbPath    string
		batchSize int
		clear     bool
	)

	rootCmd := &cobra.Command{
		Use:   "importer",
		Short: "PCAP Importer - Import packet capture files into a database",
	}

	importCmd := &cobra.Command{
		Use:   "import <pcap-file>",
		Short: "Import packets from a PCAP file into the database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pcapFile := args[0]

			// If not injected, use real implementations
			if provider.Parser == nil || provider.Repository == nil || provider.DNSProcessor == nil {
				repo, err := repository.NewSQLiteRepository(dbPath)
				if err != nil {
					return fmt.Errorf("failed to open database: %w", err)
				}
				log.Printf("Using database at %s", dbPath)
				provider.Repository = repo
				provider.Parser = parser.NewGopacketParser(pcapFile)
				// TODO: Replace with real DNS processor implementation
				provider.DNSProcessor = &dns.NoopDNSProcessor{}
			}

			if err := provider.Parser.ParseFile(provider.Repository); err != nil {
				return err
			}
			if err := provider.DNSProcessor.Process(provider.Repository); err != nil {
				return err
			}
			if err := provider.Repository.Commit(); err != nil {
				return err
			}
			if err := provider.Repository.Close(); err != nil {
				return err
			}
			return nil
		},
	}
	importCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	importCmd.Flags().IntVar(&batchSize, "batch-size", 1000, "Number of packets to import in each batch")
	importCmd.Flags().BoolVar(&clear, "clear", false, "Clear the database before importing")

	rootCmd.AddCommand(importCmd)
	return rootCmd
}

func main() {
	provider := &DependencyProvider{}
	rootCmd := newRootCmd(provider)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
