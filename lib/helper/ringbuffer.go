package helper

import (
	"sync"
)

type RingBuffer[T any] struct {
	buffer    []T
	size      int
	mu        sync.Mutex
	write     int
	lastWrite int
	count     int
}

// NewRingBuffer creates a new ring buffer with a fixed size.
func NewRingBuffer[T any](size int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buffer: make([]T, size),
		size:   size,
	}
}

// Add inserts a new element into the buffer, overwriting the oldest if full.
func (rb *RingBuffer[T]) Add(value T) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.buffer[rb.write] = value
	rb.lastWrite = rb.write
	rb.write = (rb.write + 1) % rb.size

	if rb.count < rb.size {
		rb.count++
	}
}

func (rb *RingBuffer[T]) AddNonDuplicate(value T, isEqual func(T, T) bool) {
	shouldAdd := true
	func() {
		rb.mu.Lock()
		defer rb.mu.Unlock()

		if isEqual(value, rb.buffer[rb.lastWrite]) {
			shouldAdd = false // Do not add if the value is a duplicate
			return            // Do not add if the value is a duplicate
		}
	}()
	if shouldAdd {
		rb.Add(value)
	}
}

// Get returns the contents of the buffer in FIFO order.
func (rb *RingBuffer[T]) GetAllFIFO() []T {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	result := make([]T, 0, rb.count)

	for i := 0; i < rb.count; i++ {
		index := (rb.write + rb.size - rb.count + i) % rb.size
		result = append(result, rb.buffer[index])
	}

	return result
}

func (rb *RingBuffer[T]) GetAllLIFO() []T {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	result := make([]T, 0, rb.count)

	for i := rb.count - 1; i >= 0; i-- {
		index := (rb.write + rb.size - rb.count + i) % rb.size
		result = append(result, rb.buffer[index])
	}

	return result
}

// Len returns the current number of elements in the buffer.
func (rb *RingBuffer[T]) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}
