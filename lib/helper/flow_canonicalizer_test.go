package helper

import (
	"testing"
)

func TestCanonicalizeServicePortClientServer(t *testing.T) {
	fc := NewFlowCanonicalizer()
	cs, cd, rev := fc.CanonicalizeFlow("192.168.0.10", "192.168.0.20", 50000, 80, "TCP")
	if cs != "192.168.0.10:50000" || cd != "192.168.0.20:80" || rev != false {
		t.Fatalf("unexpected canonicalization for client->server: got %s, %s, %v", cs, cd, rev)
	}
}

func TestCanonicalizeServicePortServerClient(t *testing.T) {
	fc := NewFlowCanonicalizer()
	cs, cd, rev := fc.CanonicalizeFlow("192.168.0.20", "192.168.0.10", 80, 50000, "TCP")
	if cs != "192.168.0.10:50000" || cd != "192.168.0.20:80" || rev != true {
		t.Fatalf("unexpected canonicalization for server->client: got %s, %s, %v", cs, cd, rev)
	}
}

func TestCanonicalizeLexicographicFallback(t *testing.T) {
	fc := NewFlowCanonicalizer()
	// src > dst lexicographically -> canonical should be dst,src and reversed true
	cs, cd, rev := fc.CanonicalizeFlow("10.0.0.2", "10.0.0.1", 1000, 2000, "UDP")
	if cs != "10.0.0.1:2000" || cd != "10.0.0.2:1000" || rev != true {
		t.Fatalf("unexpected canonicalization lexicographic fallback: got %s, %s, %v", cs, cd, rev)
	}
}

func TestCanonicalizeBothServicePorts(t *testing.T) {
	fc := NewFlowCanonicalizer()
	cs, cd, rev := fc.CanonicalizeFlow("1.1.1.1", "2.2.2.2", 80, 443, "TCP")
	if cs != "1.1.1.1:80" || cd != "2.2.2.2:443" || rev != false {
		t.Fatalf("unexpected canonicalization when both are service ports: got %s, %s, %v", cs, cd, rev)
	}
}
