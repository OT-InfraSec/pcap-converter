package helper

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestRingBuffer_AddAndGet(t *testing.T) {
	ringBuffer := NewRingBuffer[int](5)
	ringBuffer.Add(1)
	ringBuffer.Add(2)
	ringBuffer.Add(3)

	expected := []int{1, 2, 3}
	actual := ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.Add(4)
	ringBuffer.Add(5)
	ringBuffer.Add(6)

	expected = []int{2, 3, 4, 5, 6}
	actual = ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.Add(7)
	ringBuffer.Add(8)

	expected = []int{4, 5, 6, 7, 8}
	actual = ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}
}

func TestRingBuffer_LIFO(t *testing.T) {
	ringBuffer := NewRingBuffer[int](5)
	ringBuffer.Add(1)
	ringBuffer.Add(2)
	ringBuffer.Add(3)

	expected := []int{3, 2, 1}
	actual := ringBuffer.GetAllLIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.Add(4)
	ringBuffer.Add(5)
	ringBuffer.Add(6)

	expected = []int{6, 5, 4, 3, 2}
	actual = ringBuffer.GetAllLIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.Add(7)
	ringBuffer.Add(8)

	expected = []int{8, 7, 6, 5, 4}
	actual = ringBuffer.GetAllLIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}
}

func TestRingBufferConcurrent(t *testing.T) {
	ringBuffer := NewRingBuffer[int](3)
	var wg sync.WaitGroup

	addValues := func(values []int) {
		for _, value := range values {
			ringBuffer.Add(value)
			// Simulate delay
			time.Sleep(10 * time.Millisecond)
		}
		wg.Done()
	}

	readValues := func() {
		prices := ringBuffer.GetAllFIFO()
		if len(prices) > 0 && len(prices) != ringBuffer.size {
			t.Errorf("Buffer length inconsistency: expected size %d but got %d", ringBuffer.size, len(prices))
		}
		wg.Done()
	}

	wg.Add(3)
	go addValues([]int{1, 2, 3})
	go addValues([]int{4, 5})
	go addValues([]int{6, 7, 8})

	wg.Add(2)
	time.Sleep(100 * time.Millisecond) // Allow some time for adds to complete
	go readValues()
	go readValues()

	wg.Wait()

	finalValues := ringBuffer.GetAllFIFO()

	for _, value := range finalValues {
		if value < 1 || value > 8 {
			t.Errorf("Unexpected value in buffer: %d", value)
		}
	}

	// Ensure the buffer size is consistent with expectations
	if len(finalValues) != ringBuffer.size {
		t.Errorf("Expected buffer size %d, but got %d", ringBuffer.size, len(finalValues))
	}
}

func isEqual(a, b int) bool {
	return a == b
}

func TestRingBuffer_AddAndGet_NonDuplicate(t *testing.T) {
	ringBuffer := NewRingBuffer[int](5)
	ringBuffer.AddNonDuplicate(1, isEqual)
	ringBuffer.AddNonDuplicate(2, isEqual)
	ringBuffer.AddNonDuplicate(3, isEqual)

	expected := []int{1, 2, 3}
	actual := ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.AddNonDuplicate(4, isEqual)
	ringBuffer.AddNonDuplicate(5, isEqual)
	ringBuffer.AddNonDuplicate(6, isEqual)

	expected = []int{2, 3, 4, 5, 6}
	actual = ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.AddNonDuplicate(7, isEqual)
	ringBuffer.AddNonDuplicate(8, isEqual)

	expected = []int{4, 5, 6, 7, 8}
	actual = ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}
}

func TestRingBuffer_AddAndGet_Duplicate(t *testing.T) {
	ringBuffer := NewRingBuffer[int](5)
	ringBuffer.AddNonDuplicate(1, isEqual)
	ringBuffer.AddNonDuplicate(1, isEqual)
	ringBuffer.AddNonDuplicate(3, isEqual)

	expected := []int{1, 3}
	actual := ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.AddNonDuplicate(4, isEqual)
	ringBuffer.AddNonDuplicate(5, isEqual)
	ringBuffer.AddNonDuplicate(5, isEqual)

	expected = []int{1, 3, 4, 5}
	actual = ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.AddNonDuplicate(7, isEqual)
	ringBuffer.AddNonDuplicate(8, isEqual)

	expected = []int{3, 4, 5, 7, 8}
	actual = ringBuffer.GetAllFIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}
}

func TestRingBuffer_LIFO_NonDuplicate(t *testing.T) {
	ringBuffer := NewRingBuffer[int](5)
	ringBuffer.AddNonDuplicate(1, isEqual)
	ringBuffer.AddNonDuplicate(2, isEqual)
	ringBuffer.AddNonDuplicate(3, isEqual)

	expected := []int{3, 2, 1}
	actual := ringBuffer.GetAllLIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.AddNonDuplicate(4, isEqual)
	ringBuffer.AddNonDuplicate(5, isEqual)
	ringBuffer.AddNonDuplicate(6, isEqual)

	expected = []int{6, 5, 4, 3, 2}
	actual = ringBuffer.GetAllLIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}

	ringBuffer.AddNonDuplicate(7, isEqual)
	ringBuffer.AddNonDuplicate(8, isEqual)

	expected = []int{8, 7, 6, 5, 4}
	actual = ringBuffer.GetAllLIFO()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}
}

func TestRingBufferConcurrent_NonDuplicate(t *testing.T) {
	ringBuffer := NewRingBuffer[int](3)
	var wg sync.WaitGroup

	addValues := func(values []int) {
		for _, value := range values {
			ringBuffer.AddNonDuplicate(value, isEqual)
			// Simulate delay
			time.Sleep(10 * time.Millisecond)
		}
		wg.Done()
	}

	readValues := func() {
		prices := ringBuffer.GetAllFIFO()
		if len(prices) > 0 && len(prices) != ringBuffer.size {
			t.Errorf("Buffer length inconsistency: expected size %d but got %d", ringBuffer.size, len(prices))
		}
		wg.Done()
	}

	wg.Add(3)
	go addValues([]int{1, 2, 3})
	go addValues([]int{4, 5})
	go addValues([]int{6, 7, 8})

	wg.Add(2)
	time.Sleep(100 * time.Millisecond) // Allow some time for adds to complete
	go readValues()
	go readValues()

	wg.Wait()

	finalValues := ringBuffer.GetAllFIFO()

	for _, value := range finalValues {
		if value < 1 || value > 8 {
			t.Errorf("Unexpected value in buffer: %d", value)
		}
	}

	// Ensure the buffer size is consistent with expectations
	if len(finalValues) != ringBuffer.size {
		t.Errorf("Expected buffer size %d, but got %d", ringBuffer.size, len(finalValues))
	}
}
