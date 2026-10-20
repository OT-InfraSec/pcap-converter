package model

import "testing"

func intPtr(i int) *int { return &i }

func TestVLANToken(t *testing.T) {
	tests := []struct {
		name         string
		outer, inner *int
		want         string
	}{
		{"untagged", nil, nil, "untagged"},
		{"single tag", intPtr(100), nil, "100"},
		{"qinq", intPtr(100), intPtr(200), "100.200"},
		{"inner without outer is untagged", nil, intPtr(5), "untagged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VLANToken(tt.outer, tt.inner); got != tt.want {
				t.Errorf("VLANToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVLANSetSortedStringRoundTrip(t *testing.T) {
	v := NewVLANSet()
	v.Add(intPtr(200), nil)
	v.Add(intPtr(10), intPtr(2))
	v.Add(nil, nil)
	v.Add(intPtr(10), nil)
	v.Add(intPtr(10), nil) // duplicate

	const want = "untagged,10,10.2,200"
	if got := v.ToString(); got != want {
		t.Fatalf("ToString() = %q, want %q", got, want)
	}
	if v.Size() != 4 {
		t.Errorf("Size() = %d, want 4", v.Size())
	}

	parsed := VLANSetFromString(want)
	if parsed.ToString() != want || !parsed.Contains(VLANUntagged) {
		t.Errorf("round trip failed: %q", parsed.ToString())
	}
}

func TestVLANSetNilAndEmpty(t *testing.T) {
	var v *VLANSet
	if v.ToString() != "" || v.Size() != 0 || v.Contains("10") || len(v.List()) != 0 {
		t.Error("nil VLANSet must behave as empty")
	}
	if VLANSetFromString("").Size() != 0 {
		t.Error("empty string must parse to empty set")
	}
}
