package parser

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// ErrorHandler defines the interface for handling industrial protocol parsing errors
type ErrorHandler interface {
	// HandleProtocolError handles an error encountered while parsing a protocol
	// Returns an error if the handler itself encounters an error
	HandleProtocolError(err *IndustrialProtocolError) error
	HandleClassificationError(deviceId string, err error) error
	HandleValidationError(data map[string]interface{}, err error) error
	// SetErrorThreshold sets the maximum number of errors before stopping processing
	SetErrorThreshold(threshold int)
	// GetErrorCount returns the current error count
	GetErrorCount() int
	// IsThresholdExceeded checks if the error threshold has been exceeded
	IsThresholdExceeded() bool
	// Reset resets the error handler state
	Reset()
}

// IndustrialProtocolError represents an error that occurred during industrial protocol parsing
type IndustrialProtocolError struct {
	Protocol    string          // The protocol being parsed (e.g., "ethernetip", "opcua")
	Packet      gopacket.Packet // The packet that caused the error (optional, may be nil)
	Err         error           // The underlying error
	Context     string          // Additional context about where the error occurred
	Recoverable bool            // Whether the error is recoverable
	Timestamp   time.Time       // When the error occurred
}

// Error implements the error interface
func (e *IndustrialProtocolError) Error() string {
	if e.Packet != nil {
		return fmt.Sprintf("industrial protocol error [%s] at %s: %s - %s (packet length: %d)",
			e.Protocol, e.Timestamp.Format(time.RFC3339), e.Context, e.Err.Error(), e.Packet.Metadata().Length)
	}
	return fmt.Sprintf("industrial protocol error [%s] at %s: %s - %s",
		e.Protocol, e.Timestamp.Format(time.RFC3339), e.Context, e.Err.Error())
}

// Unwrap returns the underlying error for error unwrapping
func (e *IndustrialProtocolError) Unwrap() error {
	return e.Err
}

// IsRecoverable returns whether the error allows continued processing
func (e *IndustrialProtocolError) IsRecoverable() bool {
	return e.Recoverable
}

// GetPacketInfo returns information about the packet that caused the error
func (e *IndustrialProtocolError) GetPacketInfo() map[string]interface{} {
	if e.Packet != nil {
		dataPreviewBytes := e.Packet.Data()[54:]
		dataPreview := ""
		for i, b := range dataPreviewBytes {
			if i >= 32 { // Limit preview to first 32 bytes
				break
			}
			dataPreview += fmt.Sprintf("%02x", b)
		}
		// limit raw_data_preview to raw_data_length
		rawDataLength := len(e.Packet.Data())
		dataLength := rawDataLength - 56 + 4
		sliceEnd := min(dataLength, len(dataPreview)) // +4 to account for the last byte
		dataPreview = dataPreview[:sliceEnd]
		if dataLength > sliceEnd {
			dataPreview += "..."
		}
		return map[string]interface{}{
			"length":           e.Packet.Metadata().Length,
			"timestamp":        e.Packet.Metadata().Timestamp,
			"truncated":        e.Packet.Metadata().Truncated,
			"interface_index":  e.Packet.Metadata().InterfaceIndex,
			"raw_data_length":  rawDataLength,
			"raw_data_preview": dataPreview,
		}
	}
	return map[string]interface{}{}
}

// NoOpErrorHandler is an error handler that does nothing
type NoOpErrorHandler struct{}

func (h *NoOpErrorHandler) HandleClassificationError(deviceId string, err error) error {
	return nil
}

func (h *NoOpErrorHandler) HandleValidationError(data map[string]interface{}, err error) error {
	return nil
}

func NewNoOpErrorHandler() ErrorHandler {
	return &NoOpErrorHandler{}
}

func (h *NoOpErrorHandler) HandleProtocolError(err *IndustrialProtocolError) error {
	return nil
}

func (h *NoOpErrorHandler) SetErrorThreshold(threshold int) {}

func (h *NoOpErrorHandler) GetErrorCount() int {
	return 0
}

func (h *NoOpErrorHandler) IsThresholdExceeded() bool {
	return false
}

func (h *NoOpErrorHandler) Reset() {}

// DefaultErrorHandler is a basic error handler with logging and threshold management
type DefaultErrorHandler struct {
	mu                sync.RWMutex
	errorCount        int
	errorThreshold    int
	logger            *log.Logger
	thresholdExceeded bool
}

func NewDefaultErrorHandler(logger *log.Logger) *DefaultErrorHandler {
	if logger == nil {
		logger = log.Default()
	}
	return &DefaultErrorHandler{
		errorThreshold: 100, // Default threshold
		logger:         logger,
	}
}

func (h *DefaultErrorHandler) HandleProtocolError(err *IndustrialProtocolError) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.errorCount++

	if h.errorCount > h.errorThreshold {
		h.thresholdExceeded = true
		return fmt.Errorf("error threshold exceeded (%d): %w", h.errorThreshold, err)
	}

	// Log the error with appropriate level based on recoverability
	if err.Recoverable {
		h.logger.Printf("WARN: Recoverable protocol error: %s", err.Error())
		return nil
	}
	h.logger.Printf("ERROR: Non-recoverable protocol error: %s", err.Error())

	return err
}

func (h *DefaultErrorHandler) SetErrorThreshold(threshold int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errorThreshold = threshold
}

func (h *DefaultErrorHandler) GetErrorCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.errorCount
}

func (h *DefaultErrorHandler) IsThresholdExceeded() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.thresholdExceeded
}

func (h *DefaultErrorHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errorCount = 0
	h.thresholdExceeded = false
}

// ResetErrorCount resets just the error count (alias for Reset for backward compatibility)
func (h *DefaultErrorHandler) ResetErrorCount() {
	h.Reset()
}

func (h *DefaultErrorHandler) HandleClassificationError(deviceId string, err error) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.errorCount++
	h.logger.Printf("ERROR: Classification error for device %s: %s", deviceId, err.Error())
	if h.errorCount > h.errorThreshold {
		h.thresholdExceeded = true
		return fmt.Errorf("error threshold exceeded (%d): %w", h.errorThreshold, err)
	}
	return nil
}

func (h *DefaultErrorHandler) HandleValidationError(data map[string]interface{}, err error) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.errorCount++
	h.logger.Printf("ERROR: Validation error for data %v: %s", data, err.Error())
	if h.errorCount > h.errorThreshold {
		h.thresholdExceeded = true
		return fmt.Errorf("error threshold exceeded (%d): %w", h.errorThreshold, err)
	}
	return nil
}
