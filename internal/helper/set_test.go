package helper

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSet_Add(t *testing.T) {
	s := NewSet()
	s.Add("a")
	if !s.Contains("a") {
		t.Errorf("expected set to contain 'a' after Add")
	}

	// Sad path: Add duplicate
	s.Add("a")
	if s.Size() != 1 {
		t.Errorf("expected set size to remain 1 after adding duplicate, got %d", s.Size())
	}

	// Edge case: Add empty string
	s.Add("")
	if !s.Contains("") {
		t.Errorf("expected set to contain empty string after Add")
	}
}

func TestSet_Remove(t *testing.T) {
	s := NewSet()
	s.Add("a")
	s.Remove("a")
	if s.Contains("a") {
		t.Errorf("expected set to not contain 'a' after Remove")
	}

	// Sad path: Remove non-existent element
	s.Remove("b") // should not panic or error
	if s.Size() != 0 {
		t.Errorf("expected set size to remain 0 after removing non-existent element, got %d", s.Size())
	}

	// Edge case: Remove from empty set
	empty := NewSet()
	empty.Remove("x") // should not panic
	if empty.Size() != 0 {
		t.Errorf("expected empty set to remain empty after Remove")
	}
}

func TestSet_Contains(t *testing.T) {
	s := NewSet()
	s.Add("a")
	if !s.Contains("a") {
		t.Errorf("expected set to contain 'a'")
	}

	// Sad path: Check for non-existent element
	if s.Contains("b") {
		t.Errorf("expected set to not contain 'b'")
	}

	// Edge case: Check for empty string
	s.Add("")
	if !s.Contains("") {
		t.Errorf("expected set to contain empty string")
	}
}

func TestSet_Size(t *testing.T) {
	s := NewSet()
	if s.Size() != 0 {
		t.Errorf("expected size 0 for new set, got %d", s.Size())
	}

	s.Add("a")
	s.Add("b")
	if s.Size() != 2 {
		t.Errorf("expected size 2 after adding two elements, got %d", s.Size())
	}

	// Edge case: Add duplicate
	s.Add("a")
	if s.Size() != 2 {
		t.Errorf("expected size to remain 2 after adding duplicate, got %d", s.Size())
	}
}

func TestSet_List(t *testing.T) {
	s := NewSet()
	s.Add("a")
	s.Add("b")
	list := s.List()
	sort.Strings(list)
	expected := []string{"a", "b"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected list %v, got %v", expected, list)
	}

	// Sad path: List on empty set
	empty := NewSet()
	if len(empty.List()) != 0 {
		t.Errorf("expected empty list for empty set")
	}

	// Edge case: List with empty string
	s.Add("")
	list = s.List()
	sort.Strings(list)
	expected = []string{"", "a", "b"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected list %v, got %v", expected, list)
	}
}

func TestSet_Union(t *testing.T) {
	s1 := NewSet()
	s2 := NewSet()
	s1.Add("a")
	s2.Add("b")
	union := s1.Union(s2)
	list := union.List()
	sort.Strings(list)
	expected := []string{"a", "b"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected union %v, got %v", expected, list)
	}

	// Sad path: Union with empty set
	empty := NewSet()
	union2 := s1.Union(empty)
	if !reflect.DeepEqual(union2.List(), s1.List()) {
		t.Errorf("expected union with empty set to equal original set")
	}

	// Edge case: Union with self
	union3 := s1.Union(s1)
	if !reflect.DeepEqual(union3.List(), s1.List()) {
		t.Errorf("expected union with self to equal original set")
	}
}

func TestSet_Intersection(t *testing.T) {
	s1 := NewSet()
	s2 := NewSet()
	s1.Add("a")
	s1.Add("b")
	s2.Add("b")
	s2.Add("c")
	inter := s1.Intersection(s2)
	list := inter.List()
	expected := []string{"b"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected intersection %v, got %v", expected, list)
	}

	// Sad path: No intersection
	s3 := NewSet()
	s3.Add("x")
	inter2 := s1.Intersection(s3)
	if inter2.Size() != 0 {
		t.Errorf("expected empty intersection, got %v", inter2.List())
	}

	// Edge case: Intersection with self
	inter3 := s1.Intersection(s1)
	list3 := inter3.List()
	sort.Strings(list3)
	expected3 := []string{"a", "b"}
	if !reflect.DeepEqual(list3, expected3) {
		t.Errorf("expected intersection with self %v, got %v", expected3, list3)
	}
}

func TestSet_IntersectionWithEmptySet(t *testing.T) {
	s1 := NewSet()
	s1.Add("a")
	s1.Add("b")
	empty := NewSet()

	// Intersection with empty set should be empty
	inter := s1.Intersection(empty)
	if inter.Size() != 0 {
		t.Errorf("expected empty intersection with empty set, got %v", inter.List())
	}

	// Empty set intersection with non-empty set should also be empty
	interReverse := empty.Intersection(s1)
	if interReverse.Size() != 0 {
		t.Errorf("expected empty intersection, got %v", interReverse.List())
	}
}

func TestSet_Difference(t *testing.T) {
	s1 := NewSet()
	s2 := NewSet()
	s1.Add("a")
	s1.Add("b")
	s2.Add("b")
	s2.Add("c")
	diff := s1.Difference(s2)
	list := diff.List()
	expected := []string{"a"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected difference %v, got %v", expected, list)
	}

	// Sad path: Difference with self should be empty
	diffSelf := s1.Difference(s1)
	if diffSelf.Size() != 0 {
		t.Errorf("expected empty difference with self, got %v", diffSelf.List())
	}

	// Edge case: Difference with empty set should equal original set
	empty := NewSet()
	diffEmpty := s1.Difference(empty)
	list = diffEmpty.List()
	sort.Strings(list)
	expected = []string{"a", "b"}
	sort.Strings(expected)
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected difference with empty set %v, got %v", expected, list)
	}

	// Edge case: Empty set difference with non-empty set should be empty
	diffEmptyWithNonEmpty := empty.Difference(s1)
	if diffEmptyWithNonEmpty.Size() != 0 {
		t.Errorf("expected empty difference, got %v", diffEmptyWithNonEmpty.List())
	}
}

func TestSet_NilSafety(t *testing.T) {
	// Create a set to work with
	s := NewSet()
	s.Add("a")
	s.Add("b")

	// Test creating a set from nil map (defensive programming)
	nilSet := &Set{elements: nil}

	// These operations should not panic with nil maps
	if nilSet.Size() != 0 {
		t.Errorf("expected nil set size to be 0, got %d", nilSet.Size())
	}

	if len(nilSet.List()) != 0 {
		t.Errorf("expected nil set list to be empty")
	}

	// Operations with nil set should behave predictably
	union := s.Union(nilSet)
	if union.Size() != s.Size() {
		t.Errorf("expected union with nil set to equal original set size")
	}

	inter := s.Intersection(nilSet)
	if inter.Size() != 0 {
		t.Errorf("expected intersection with nil set to be empty")
	}

	diff := s.Difference(nilSet)
	if diff.Size() != s.Size() {
		t.Errorf("expected difference with nil set to equal original set size")
	}
}

func TestSet_ToString(t *testing.T) {
	s1 := NewSet()
	s1.Add("a")
	s1.Add("b")
	s1.Add("c")
	str := s1.ToString()
	// expected to contain an 'a'
	// expected to contain a 'b'
	// expected to contain a 'c'
	if !strings.Contains(str, "a") || !strings.Contains(str, "b") || !strings.Contains(str, "c") {
		t.Errorf("expected string representation to contain 'a', 'b', and 'c', got %s", str)
	}

	s2 := NewSet()
	s2.Add("b")
	str2 := s2.ToString()
	expected2 := "b"
	if str2 != expected2 {
		t.Errorf("expected string representation to be 'b', got %s", str2)
	}

	// Sad path: Empty set string representation
	empty := NewSet()
	strEmpty := empty.ToString()
	expectedEmpty := ""
	if strEmpty != expectedEmpty {
		t.Errorf("expected empty set string representation to be empty, got %s", strEmpty)
	}

	// Edge case: Set with empty string
	s1.Add("")
	strWithEmpty := s1.ToString()
	expectedWithEmpty := "a,b,c,"
	if !strings.Contains(str, "a") || !strings.Contains(str, "b") || !strings.Contains(str, "c") || !(strWithEmpty[0] == ',' || strWithEmpty[len(strWithEmpty)-1] == ',' || strings.Contains(strWithEmpty, ",,")) {
		t.Errorf("expected string representation with empty string %s got %s", expectedWithEmpty, strWithEmpty)
	}

	// Edge case: Set with only empty string
	emptySet := NewSet()
	emptySet.Add("")
	strOnlyEmpty := emptySet.ToString()
	expectedOnlyEmpty := ""
	if strOnlyEmpty != expectedOnlyEmpty {
		t.Errorf("expected string representation of set with only empty string to be empty, got %s", strOnlyEmpty)
	}
}
