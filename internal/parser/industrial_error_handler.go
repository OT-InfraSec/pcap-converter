package parser

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
)

// IndustrialProtocolError represents an error that occurred during industrial protocol parsing
type IndustrialProtocolError struct {
	Protocol    string          // The protocol being parsed (e.g., "ethernetip", "opcua")
	Packet      gopacket.Packet // The packet that caused the error (optional, may be nil)
	Err         error           // The underlying error
	Context     string          // Additional context about where the error occurred
	Timestamp   time.Time       // When the error occurred
	Recoverable bool            // Whether the error is recoverable
	PacketData  []byte          // Raw packet data for debugging (optional)
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

// GetPacketInfo returns packet information for debugging
func (e *IndustrialProtocolError) GetPacketInfo() map[string]interface{} {
	info := make(map[string]interface{})
	if e.Packet != nil {
		metadata := e.Packet.Metadata()
		info["timestamp"] = metadata.Timestamp
		info["length"] = metadata.Length
		info["truncated"] = metadata.Truncated
		info["interface_index"] = metadata.InterfaceIndex
	}
	if len(e.PacketData) > 0 {
		info["raw_data_length"] = len(e.PacketData)
		// Include first 64 bytes for debugging (avoid logging sensitive data)
		if len(e.PacketData) > 64 {
			info["raw_data_preview"] = fmt.Sprintf("%x...", e.PacketData[:64])
		} else {
			info["raw_data_preview"] = fmt.Sprintf("%x", e.PacketData)
		}
	}
	return info
}

// ErrorHandler defines the interface for handling industrial protocol parsing errors
type ErrorHandler interface {
	// HandleProtocolError handles errors that occur during protocol parsing
	HandleProtocolError(err *IndustrialProtocolError) error

	// HandleClassificationError handles errors that occur during device classification
	HandleClassificationError(deviceID string, err error) error

	// HandleValidationError handles errors that occur during data validation
	HandleValidationError(data interface{}, err error) error

	// SetErrorThreshold sets the maximum number of errors before stopping processing
	SetErrorThreshold(threshold int)

	// GetErrorCount returns the current error count
	GetErrorCount() int

	// ResetErrorCount resets the error counter
	ResetErrorCount()

	// IsErrorThresholdExceeded returns true if error threshold has been exceeded
	IsErrorThresholdExceeded() bool
}

// DefaultErrorHandler provides a default implementation of ErrorHandler
type DefaultErrorHandler struct {
	errorCount     int
	errorThreshold int
	logger         *log.Logger
}

// NewDefaultErrorHandler creates a new default error handler
func NewDefaultErrorHandler(logger *log.Logger) *DefaultErrorHandler {
	if logger == nil {
		logger = log.Default()
	}
	return &DefaultErrorHandler{
		errorCount:     0,
		errorThreshold: 100, // Default threshold
		logger:         logger,
	}
}

// HandleProtocolError handles industrial protocol parsing errors
func (h *DefaultErrorHandler) HandleProtocolError(err *IndustrialProtocolError) error {
	h.errorCount++

	// Log the error with appropriate level based on recoverability
	if err.IsRecoverable() {
		h.logger.Printf("WARN: Recoverable protocol error: %s", err.Error())

		// Log packet info for debugging if available
		if packetInfo := err.GetPacketInfo(); len(packetInfo) > 0 {
			h.logger.Printf("DEBUG: Packet info: %+v", packetInfo)
		}
	} else {
		h.logger.Printf("ERROR: Non-recoverable protocol error: %s", err.Error())

		// Log detailed packet info for non-recoverable errors
		if packetInfo := err.GetPacketInfo(); len(packetInfo) > 0 {
			h.logger.Printf("ERROR: Packet info: %+v", packetInfo)
		}

		// For non-recoverable errors, we might want to stop processing
		if h.IsErrorThresholdExceeded() {
			return fmt.Errorf("error threshold exceeded (%d errors), stopping processing", h.errorThreshold)
		}
	}

	return nil
}

// HandleClassificationError handles device classification errors
func (h *DefaultErrorHandler) HandleClassificationError(deviceID string, err error) error {
	h.errorCount++
	h.logger.Printf("WARN: Device classification error for device %s: %s", deviceID, err.Error())

	// Classification errors are generally recoverable
	return nil
}

// HandleValidationError handles data validation errors
func (h *DefaultErrorHandler) HandleValidationError(data interface{}, err error) error {
	h.errorCount++
	h.logger.Printf("WARN: Data validation error: %s (data type: %T)", err.Error(), data)

	// Validation errors are generally recoverable - we just skip the invalid data
	return nil
}

// SetErrorThreshold sets the maximum number of errors before stopping processing
func (h *DefaultErrorHandler) SetErrorThreshold(threshold int) {
	h.errorThreshold = threshold
}

// GetErrorCount returns the current error count
func (h *DefaultErrorHandler) GetErrorCount() int {
	return h.errorCount
}

// ResetErrorCount resets the error counter
func (h *DefaultErrorHandler) ResetErrorCount() {
	h.errorCount = 0
}

// IsErrorThresholdExceeded returns true if error threshold has been exceeded
func (h *DefaultErrorHandler) IsErrorThresholdExceeded() bool {
	return h.errorCount >= h.errorThreshold
}

// NoOpErrorHandler provides a no-operation error handler for testing
type NoOpErrorHandler struct{}

// NewNoOpErrorHandler creates a new no-op error handler
func NewNoOpErrorHandler() *NoOpErrorHandler {
	return &NoOpErrorHandler{}
}

// HandleProtocolError does nothing and returns nil
func (h *NoOpErrorHandler) HandleProtocolError(err *IndustrialProtocolError) error {
	return nil
}

// HandleClassificationError does nothing and returns nil
func (h *NoOpErrorHandler) HandleClassificationError(deviceID string, err error) error {
	return nil
}

// HandleValidationError does nothing and returns nil
func (h *NoOpErrorHandler) HandleValidationError(data interface{}, err error) error {
	return nil
}

// SetErrorThreshold does nothing
func (h *NoOpErrorHandler) SetErrorThreshold(threshold int) {}

// GetErrorCount always returns 0
func (h *NoOpErrorHandler) GetErrorCount() int {
	return 0
}

// ResetErrorCount does nothing
func (h *NoOpErrorHandler) ResetErrorCount() {}

// IsErrorThresholdExceeded always returns false
func (h *NoOpErrorHandler) IsErrorThresholdExceeded() bool {
	return false
}

// Helper functions for creating common industrial protocol errors

// NewMalformedPacketError creates an error for malformed packets
func NewMalformedPacketError(protocol string, packet gopacket.Packet, err error, context string) *IndustrialProtocolError {
	var packetData []byte
	if packet != nil && packet.Data() != nil {
		// Copy packet data for debugging (limit to 256 bytes to avoid memory issues)
		dataLen := len(packet.Data())
		if dataLen > 256 {
			dataLen = 256
		}
		packetData = make([]byte, dataLen)
		copy(packetData, packet.Data()[:dataLen])
	}

	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: true, // Malformed packets are generally recoverable
		PacketData:  packetData,
	}
}

// NewIncompleteDataError creates an error for incomplete protocol data
func NewIncompleteDataError(protocol string, packet gopacket.Packet, expectedSize, actualSize int, context string) *IndustrialProtocolError {
	err := fmt.Errorf("incomplete data: expected %d bytes, got %d bytes", expectedSize, actualSize)

	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: true, // Incomplete data is generally recoverable
	}
}

// NewProtocolDetectionError creates an error for protocol detection failures
func NewProtocolDetectionError(protocol string, packet gopacket.Packet, err error, context string) *IndustrialProtocolError {
	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: true, // Detection failures are generally recoverable
	}
}

// NewParsingError creates a general parsing error
func NewParsingError(protocol string, packet gopacket.Packet, err error, context string, recoverable bool) *IndustrialProtocolError {
	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: recoverable,
	}
}
