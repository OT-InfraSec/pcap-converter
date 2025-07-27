package model

import "strings"

type SetInterface interface {
	Add(value string)
	Remove(value string)
	Contains(value string) bool
	Size() int
	List() []string
	Union(other *Set) *Set
	Intersection(other *Set) *Set
	Difference(other *Set) *Set
	ToString() string
}

// Set is a collection of unique elements
type Set struct {
	elements map[string]struct{}
}

// NewSet creates a new set
func NewSet() *Set {
	return &Set{
		elements: make(map[string]struct{}),
	}
}

// Add inserts an element into the set
func (s *Set) Add(value string) {
	s.elements[value] = struct{}{}
}

// Remove deletes an element from the set
func (s *Set) Remove(value string) {
	delete(s.elements, value)
}

// Contains checks if an element is in the set
func (s *Set) Contains(value string) bool {
	_, found := s.elements[value]
	return found
}

// Size returns the number of elements in the set
func (s *Set) Size() int {
	return len(s.elements)
}

// List returns all elements in the set as a slice
func (s *Set) List() []string {
	keys := make([]string, 0, len(s.elements))
	for key := range s.elements {
		keys = append(keys, key)
	}
	return keys
}

func (s *Set) Union(other *Set) *Set {
	result := NewSet()
	for key := range s.elements {
		result.Add(key)
	}
	for key := range other.elements {
		result.Add(key)
	}
	return result
}

func (s *Set) Intersection(other *Set) *Set {
	result := NewSet()
	for key := range s.elements {
		if other.Contains(key) {
			result.Add(key)
		}
	}
	return result
}

func (s *Set) Difference(other *Set) *Set {
	result := NewSet()
	for key := range s.elements {
		if !other.Contains(key) {
			result.Add(key)
		}
	}
	return result
}

func (s *Set) ToString() string {
	return strings.Join(s.List(), ",")
}
