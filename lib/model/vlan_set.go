package model

import (
	"sort"
	"strconv"
	"strings"
)

// VLANUntagged is the VLANSet token for frames seen without an 802.1Q tag.
const VLANUntagged = "untagged"

// VLANTag is the VLAN pair of a frame: Outer is the 802.1Q tag, Inner the
// second tag of QinQ. The zero value means untagged.
type VLANTag struct {
	Outer *int
	Inner *int
}

// Token returns the VLANSet token / flow key part for the tag.
func (t VLANTag) Token() string {
	return VLANToken(t.Outer, t.Inner)
}

// VLANSet records the VLANs a device was seen in. Tokens are "untagged",
// "<outer>" or "<outer>.<inner>" (QinQ). It mirrors MACAddressSet so the
// visualizer can read both columns the same way.
type VLANSet struct {
	set *Set
}

// NewVLANSet creates an empty VLANSet.
func NewVLANSet() *VLANSet {
	return &VLANSet{set: NewSet()}
}

// VLANToken builds the set token for a packet's VLAN pair; nil outer means untagged.
func VLANToken(outer, inner *int) string {
	if outer == nil {
		return VLANUntagged
	}
	if inner == nil {
		return strconv.Itoa(*outer)
	}
	return strconv.Itoa(*outer) + "." + strconv.Itoa(*inner)
}

// AddTag records a frame's VLAN tag.
func (v *VLANSet) AddTag(t VLANTag) {
	v.Add(t.Outer, t.Inner)
}

// Add records a VLAN pair (nil outer = untagged).
func (v *VLANSet) Add(outer, inner *int) {
	v.AddToken(VLANToken(outer, inner))
}

// AddToken records an already formatted token; empty tokens are ignored.
func (v *VLANSet) AddToken(token string) {
	if token == "" {
		return
	}
	if v.set == nil {
		v.set = NewSet()
	}
	v.set.Add(token)
}

// Contains reports whether the token is in the set.
func (v *VLANSet) Contains(token string) bool {
	return v != nil && v.set != nil && v.set.Contains(token)
}

// Size returns the number of distinct VLAN tokens.
func (v *VLANSet) Size() int {
	if v == nil || v.set == nil {
		return 0
	}
	return v.set.Size()
}

// List returns the tokens sorted: untagged first, then by outer and inner ID.
func (v *VLANSet) List() []string {
	if v == nil || v.set == nil {
		return []string{}
	}
	list := v.set.List()
	sort.Slice(list, func(i, j int) bool {
		return vlanSortKey(list[i]) < vlanSortKey(list[j])
	})
	return list
}

// vlanSortKey maps a token to a sortable number: untagged first, then outer*10000+inner+1.
func vlanSortKey(token string) int {
	if token == VLANUntagged {
		return -1
	}
	outer, inner, hasInner := strings.Cut(token, ".")
	o, _ := strconv.Atoi(outer)
	i := -1
	if hasInner {
		i, _ = strconv.Atoi(inner)
	}
	return o*10000 + i + 1
}

// ToString returns the comma-joined sorted tokens, the stored column format.
func (v *VLANSet) ToString() string {
	if v == nil {
		return ""
	}
	return strings.Join(v.List(), ",")
}

// VLANSetFromString parses the stored column format.
func VLANSetFromString(s string) *VLANSet {
	v := NewVLANSet()
	for _, token := range strings.Split(s, ",") {
		v.AddToken(strings.TrimSpace(token))
	}
	return v
}
