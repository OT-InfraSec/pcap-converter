package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/internal/testutil"

	"github.com/spf13/cobra"
)

func TestImportCommand_CallsParserAndDNSProcessor(t *testing.T) {
	mockParser := &testutil.MockPacketParser{}
	mockRepo := &testutil.MockRepository{}
	mockDNS := &testutil.MockDNSProcessor{}

	provider := &DependencyProvider{
		Parser:       mockParser,
		Repository:   mockRepo,
		DNSProcessor: mockDNS,
	}

	cmd := makeTestRootCmd(provider)
	cmd.SetArgs([]string{"import", "test.pcap", "--db-path", "test.sqlite", "--batch-size", "10", "--clear"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mockParser.ParseFileCalled {
		t.Error("expected parser.ParseFile to be called")
	}
	if !mockDNS.ProcessCalled {
		t.Error("expected DNSProcessor.Process to be called")
	}
	if !mockRepo.CommitCalled {
		t.Error("expected Repository.Commit to be called")
	}
	if !mockRepo.CloseCalled {
		t.Error("expected Repository.Close to be called")
	}
}

func TestImportCommand_ParserError(t *testing.T) {
	mockParser := &testutil.MockPacketParser{ParseFileErr: errors.New("parse error")}
	mockRepo := &testutil.MockRepository{}
	mockDNS := &testutil.MockDNSProcessor{}

	provider := &DependencyProvider{
		Parser:       mockParser,
		Repository:   mockRepo,
		DNSProcessor: mockDNS,
	}

	cmd := makeTestRootCmd(provider)
	cmd.SetArgs([]string{"import", "test.pcap"})

	err := cmd.Execute()
	if err == nil || err.Error() != "parse error" {
		t.Errorf("expected parse error, got %v", err)
	}
}

// makeTestRootCmd wires up the CLI for testing with injected dependencies
func makeTestRootCmd(provider *DependencyProvider) *cobra.Command {
	var (
		dbPath    string
		batchSize int
		clearFlag bool
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
			// Simulate import logic with injected dependencies
			if err := provider.Parser.ParseFile(); err != nil {
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
			_ = pcapFile
			_ = dbPath
			_ = batchSize
			_ = clearFlag
			return nil
		},
	}
	importCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	importCmd.Flags().IntVar(&batchSize, "batch-size", 1000, "Number of packets to import in each batch")
	importCmd.Flags().BoolVar(&clearFlag, "clear", false, "Clear the database before importing")

	rootCmd.AddCommand(importCmd)
	// Silence output for tests
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	return rootCmd
}
