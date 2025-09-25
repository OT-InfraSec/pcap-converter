package helper

import (
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

func TestCanonicalizeServicePortClientServer(t *testing.T) {
	fc := NewFlowCanonicalizer()
	srcPortSet := model.NewSet()
	srcPortSet.Add("50000")
	dstPortSet := model.NewSet()
	dstPortSet.Add("80")
	cs, cd, rev := fc.CanonicalizeFlow("192.168.0.10", "192.168.0.20", *srcPortSet, *dstPortSet, "TCP")
	if cs != "192.168.0.10" || cd != "192.168.0.20" || rev != false {
		t.Fatalf("unexpected canonicalization for client->server: got %s, %s, %v", cs, cd, rev)
	}
}

func TestCanonicalizeServicePortServerClient(t *testing.T) {
	fc := NewFlowCanonicalizer()
	srcPortSet := model.NewSet()
	srcPortSet.Add("80")
	dstPortSet := model.NewSet()
	dstPortSet.Add("50000")
	cs, cd, rev := fc.CanonicalizeFlow("192.168.0.20", "192.168.0.10", *srcPortSet, *dstPortSet, "TCP")
	if cs != "192.168.0.10" || cd != "192.168.0.20" || rev != true {
		t.Fatalf("unexpected canonicalization for server->client: got %s, %s, %v", cs, cd, rev)
	}
}

func TestCanonicalizeFallback(t *testing.T) {
	fc := NewFlowCanonicalizer()
	srcPortSet := model.NewSet()
	srcPortSet.Add("1000")
	dstPortSet := model.NewSet()
	dstPortSet.Add("2000")
	cs, cd, rev := fc.CanonicalizeFlow("10.0.0.2", "10.0.0.1", *srcPortSet, *dstPortSet, "UDP")
	if cs != "10.0.0.2" || cd != "10.0.0.1" || rev != false {
		t.Fatalf("unexpected canonicalization lexicographic fallback: got %s, %s, %v", cs, cd, rev)
	}
}

func TestCanonicalizeBothServicePorts(t *testing.T) {
	fc := NewFlowCanonicalizer()
	srcPortSet := model.NewSet()
	srcPortSet.Add("80")
	dstPortSet := model.NewSet()
	dstPortSet.Add("443")
	cs, cd, rev := fc.CanonicalizeFlow("1.1.1.1", "2.2.2.2", *srcPortSet, *dstPortSet, "TCP")
	if cs != "1.1.1.1" || cd != "2.2.2.2" || rev != false {
		t.Fatalf("unexpected canonicalization when both are service ports: got %s, %s, %v", cs, cd, rev)
	}
}
