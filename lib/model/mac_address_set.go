package model

import (
	"github.com/InfraSecConsult/pcap-importer-go/internal/helper"
	"strings"
)

type MACAddressSet struct {
	set *helper.Set
}

func NewMACAddressSet() *MACAddressSet {
	return &MACAddressSet{
		set: helper.NewSet(),
	}
}

func (m *MACAddressSet) Add(value string) {
	if m.set == nil {
		m.set = helper.NewSet()
	}
	m.set.Add(value)
}

func (m *MACAddressSet) Remove(value string) {
	if m.set == nil {
		return // Nothing to remove if the set is nil
	}
	m.set.Remove(value)
}

func (m *MACAddressSet) Contains(value string) bool {
	if m.set == nil {
		return false // If the set is nil, it cannot contain any values
	}
	return m.set.Contains(value)
}

func (m *MACAddressSet) Size() int {
	if m.set == nil {
		return 0 // If the set is nil, its size is 0
	}
	return m.set.Size()
}

func (m *MACAddressSet) List() []string {
	if m.set == nil {
		return []string{} // If the set is nil, return an empty slice
	}
	list := make([]string, 0, m.set.Size())

	for _, value := range m.set.List() {
		if value != "00:00:00:00:00:00" { // Exclude the zero MAC address
			list = append(list, value)
		}
	}
	return list
}

func (m *MACAddressSet) Union(other *helper.Set) *helper.Set {
	if m.set == nil {
		return other // If this set is nil, return the other set
	}
	if other == nil {
		return m.set // If the other set is nil, return this set
	}
	return m.set.Union(other)
}

func (m *MACAddressSet) Intersection(other *helper.Set) *helper.Set {
	if m.set == nil || other == nil {
		return helper.NewSet() // If either set is nil, return an empty set
	}
	return m.set.Intersection(other)
}

func (m *MACAddressSet) Difference(other *helper.Set) *helper.Set {
	if m.set == nil {
		return helper.NewSet() // If this set is nil, return an empty set
	}
	if other == nil {
		return m.set // If the other set is nil, return this set
	}
	return m.set.Difference(other)
}

func (m *MACAddressSet) ToString() string {
	if m.set == nil {
		return "" // If the set is nil, return an empty string
	}
	return strings.Join(m.List(), ",")
}

func (m *MACAddressSet) ToSet() *helper.Set {
	if m.set == nil {
		return helper.NewSet() // If the set is nil, return an empty set
	}
	return m.set
}

func FromSet(set *helper.Set) *MACAddressSet {
	if set == nil {
		return NewMACAddressSet() // Return a new empty MACAddressSet if the input set is nil
	}
	macSet := MACAddressSet{set: set}
	return &macSet
}
