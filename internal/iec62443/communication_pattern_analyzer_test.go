package iec62443

import (
	"net"
	"testing"
	"time"

	addressHelper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
)

func TestCommunicationPatternAnalyzer_AnalyzePeriodicPatterns(t *testing.T) {
	analyzer := NewCommunicationPatternAnalyzer()

	tests := []struct {
		name                     string
		flows                    []model.Flow
		expectedPatternCount     int
		expectedPatternType      string
		expectedCriticalityLevel string
		minConfidence            float64
	}{
		{
			name: "Strict periodic EtherNet/IP control traffic",
			flows: createPeriodicFlows("192.168.1.10", "192.168.1.20", "EtherNetIP",
				100*time.Millisecond, 10, 5*time.Millisecond), // Very regular, 100ms intervals
			expectedPatternCount:     1,
			expectedPatternType:      "strict_periodic",
			expectedCriticalityLevel: "critical",
			minConfidence:            0.8,
		},
		{
			name: "Loose periodic OPC UA monitoring traffic",
			flows: createPeriodicFlows("192.168.1.20", "192.168.1.30", "OPCUA",
				5*time.Second, 8, 1*time.Second), // Less regular, 5s intervals
			expectedPatternCount:     1,
			expectedPatternType:      "loose_periodic",
			expectedCriticalityLevel: "medium",
			minConfidence:            0.5,
		},
		{
			name: "Burst periodic Modbus polling",
			flows: createBurstPeriodicFlows("192.168.1.15", "192.168.1.25", "Modbus",
				2*time.Second, 6), // Burst pattern every 2 seconds
			expectedPatternCount:     1,
			expectedPatternType:      "irregular", // Burst patterns are detected as irregular
			expectedCriticalityLevel: "low",
			minConfidence:            0.1,
		},
		{
			name: "Insufficient samples",
			flows: createPeriodicFlows("192.168.1.10", "192.168.1.20", "EtherNetIP",
				100*time.Millisecond, 3, 5*time.Millisecond), // Only 3 flows, below minimum
			expectedPatternCount: 0,
		},
		{
			name:                 "No flows",
			flows:                []model.Flow{},
			expectedPatternCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := analyzer.AnalyzePeriodicPatterns(tt.flows)

			assert.Equal(t, tt.expectedPatternCount, len(patterns))

			if len(patterns) > 0 {
				pattern := patterns[0]
				assert.Equal(t, tt.expectedPatternType, pattern.PatternType)
				assert.Equal(t, tt.expectedCriticalityLevel, pattern.CriticalityLevel)
				assert.GreaterOrEqual(t, pattern.Confidence, tt.minConfidence)
				assert.Greater(t, pattern.Regularity, 0.0)
				assert.LessOrEqual(t, pattern.Regularity, 1.0)
				// Source device should match the first parameter of the test flows
				assert.NotEmpty(t, pattern.SourceDevice)
				assert.NotZero(t, pattern.Frequency)
			}
		})
	}
}

func TestCommunicationPatternAnalyzer_AnalyzeRequestResponsePatterns(t *testing.T) {
	analyzer := NewCommunicationPatternAnalyzer()

	tests := []struct {
		name                     string
		flows                    []model.Flow
		expectedPatternCount     int
		expectedPatternType      string
		expectedCriticalityLevel string
		expectedServiceType      string
	}{
		{
			name: "Synchronous EtherNet/IP control requests",
			flows: createRequestResponseFlows("192.168.1.10", "192.168.1.20", "EtherNetIP",
				10*time.Millisecond, 8), // Low latency, synchronous
			expectedPatternCount:     1,
			expectedPatternType:      "synchronous",
			expectedCriticalityLevel: "critical",
			expectedServiceType:      "control",
		},
		{
			name: "Asynchronous OPC UA data collection",
			flows: createRequestResponseFlows("192.168.1.20", "192.168.1.30", "OPCUA",
				200*time.Millisecond, 6), // Higher latency, asynchronous
			expectedPatternCount:     1,
			expectedPatternType:      "asynchronous",
			expectedCriticalityLevel: "medium",
			expectedServiceType:      "data_collection",
		},
		{
			name: "High-frequency Modbus polling",
			flows: createHighFrequencyRequestResponseFlows("192.168.1.15", "192.168.1.25", "Modbus",
				50*time.Millisecond, 15), // High request rate
			expectedPatternCount:     1,
			expectedPatternType:      "polling",
			expectedCriticalityLevel: "high",
			expectedServiceType:      "monitoring",
		},
		{
			name: "HTTP configuration requests",
			flows: createRequestResponseFlows("192.168.1.100", "192.168.1.10", "HTTP",
				300*time.Millisecond, 5),
			expectedPatternCount:     1,
			expectedPatternType:      "asynchronous",
			expectedCriticalityLevel: "low",
			expectedServiceType:      "configuration",
		},
		{
			name: "Insufficient request-response pairs",
			flows: createRequestResponseFlows("192.168.1.10", "192.168.1.20", "EtherNetIP",
				10*time.Millisecond, 3), // Only 3 pairs, below minimum
			expectedPatternCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := analyzer.AnalyzeRequestResponsePatterns(tt.flows)

			assert.Equal(t, tt.expectedPatternCount, len(patterns))

			if len(patterns) > 0 {
				pattern := patterns[0]
				assert.Equal(t, tt.expectedPatternType, pattern.PatternType)
				assert.Equal(t, tt.expectedCriticalityLevel, pattern.CriticalityLevel)
				assert.Equal(t, tt.expectedServiceType, pattern.ServiceType)
				// Initiator device should match the first parameter of the test flows
				assert.NotEmpty(t, pattern.InitiatorDevice)
				assert.Greater(t, pattern.RequestRate, 0.0)
				assert.GreaterOrEqual(t, pattern.ResponseRate, 0.0)
				assert.LessOrEqual(t, pattern.ResponseRate, 1.0)
			}
		})
	}
}

func TestCommunicationPatternAnalyzer_DetermineCommunicationCriticality(t *testing.T) {
	analyzer := NewCommunicationPatternAnalyzer()

	tests := []struct {
		name                       string
		patterns                   []model.CommunicationPattern
		expectedOverallCriticality string
		expectedCriticalCount      int
		expectedHighCount          int
		expectedRiskFactors        int
		expectedRecommendations    int
	}{
		{
			name: "Critical industrial network",
			patterns: []model.CommunicationPattern{
				createCommunicationPattern("192.168.1.10", "192.168.1.20", "EtherNetIP", "periodic", "critical", 100*time.Millisecond),
				createCommunicationPattern("192.168.1.10", "192.168.1.21", "EtherNetIP", "periodic", "critical", 100*time.Millisecond),
				createCommunicationPattern("192.168.1.20", "192.168.1.30", "OPCUA", "event-driven", "high", 1*time.Second),
			},
			expectedOverallCriticality: "critical",
			expectedCriticalCount:      2,
			expectedHighCount:          1,
			expectedRiskFactors:        2, // Unencrypted critical + high frequency
			expectedRecommendations:    3, // Encryption + QoS + segmentation
		},
		{
			name: "High criticality network",
			patterns: []model.CommunicationPattern{
				createCommunicationPattern("192.168.1.20", "192.168.1.30", "OPCUA", "event-driven", "high", 2*time.Second),
				createCommunicationPattern("192.168.1.25", "192.168.1.35", "Modbus", "periodic", "high", 5*time.Second),
				createCommunicationPattern("192.168.1.30", "192.168.1.40", "HTTP", "event-driven", "medium", 10*time.Second),
			},
			expectedOverallCriticality: "high",
			expectedCriticalCount:      0,
			expectedHighCount:          2,
			expectedRiskFactors:        1, // Unencrypted critical
			expectedRecommendations:    2, // Encryption + segmentation
		},
		{
			name: "Medium criticality network",
			patterns: []model.CommunicationPattern{
				createCommunicationPattern("192.168.1.30", "192.168.1.40", "HTTP", "event-driven", "medium", 10*time.Second),
				createCommunicationPattern("192.168.1.35", "192.168.1.45", "HTTPS", "event-driven", "medium", 15*time.Second),
				createCommunicationPattern("192.168.1.40", "192.168.1.50", "DNS", "event-driven", "low", 30*time.Second),
			},
			expectedOverallCriticality: "medium",
			expectedCriticalCount:      0,
			expectedHighCount:          0,
			expectedRiskFactors:        0,
			expectedRecommendations:    1, // Monitor traffic
		},
		{
			name:                       "No patterns",
			patterns:                   []model.CommunicationPattern{},
			expectedOverallCriticality: "low",
			expectedCriticalCount:      0,
			expectedHighCount:          0,
			expectedRiskFactors:        0,
			expectedRecommendations:    1, // Monitor traffic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := analyzer.DetermineCommunicationCriticality(tt.patterns)

			assert.Equal(t, tt.expectedOverallCriticality, assessment.OverallCriticality)
			assert.Equal(t, tt.expectedCriticalCount, assessment.CriticalPatternCount)
			assert.Equal(t, tt.expectedHighCount, assessment.HighPatternCount)
			assert.GreaterOrEqual(t, len(assessment.RiskFactors), tt.expectedRiskFactors)
			assert.GreaterOrEqual(t, len(assessment.RecommendedActions), tt.expectedRecommendations)
			assert.NotZero(t, assessment.AssessmentTimestamp)

			// Verify pattern breakdown
			if len(tt.patterns) > 0 {
				assert.NotEmpty(t, assessment.PatternBreakdown)
				for _, breakdown := range assessment.PatternBreakdown {
					assert.Greater(t, breakdown.Count, 0)
					assert.GreaterOrEqual(t, breakdown.AverageCriticality, 0.0)
					assert.LessOrEqual(t, breakdown.AverageCriticality, 1.0)
				}
			}
		})
	}
}

func TestCommunicationPatternAnalyzer_DetectPatternChanges(t *testing.T) {
	analyzer := NewCommunicationPatternAnalyzer()

	oldPatterns := []model.CommunicationPattern{
		createCommunicationPattern("192.168.1.10", "192.168.1.20", "EtherNetIP", "periodic", "high", 1*time.Second),
		createCommunicationPattern("192.168.1.20", "192.168.1.30", "OPCUA", "event-driven", "medium", 5*time.Second),
	}

	tests := []struct {
		name                string
		newPatterns         []model.CommunicationPattern
		expectedChangeCount int
		expectedChangeTypes []string
		expectedHighImpact  int
	}{
		{
			name: "New critical pattern added",
			newPatterns: append(oldPatterns,
				createCommunicationPattern("192.168.1.15", "192.168.1.25", "Modbus", "periodic", "critical", 100*time.Millisecond)),
			expectedChangeCount: 1,
			expectedChangeTypes: []string{"new_pattern"},
			expectedHighImpact:  1,
		},
		{
			name: "Pattern removed",
			newPatterns: []model.CommunicationPattern{
				oldPatterns[0], // Keep first, remove second
			},
			expectedChangeCount: 1,
			expectedChangeTypes: []string{"pattern_removed"},
			expectedHighImpact:  0,
		},
		{
			name: "Frequency changed significantly",
			newPatterns: []model.CommunicationPattern{
				createCommunicationPattern("192.168.1.10", "192.168.1.20", "EtherNetIP", "periodic", "high", 100*time.Millisecond), // 10x faster
				oldPatterns[1],
			},
			expectedChangeCount: 1,
			expectedChangeTypes: []string{"frequency_changed"},
			expectedHighImpact:  1,
		},
		{
			name: "Criticality changed",
			newPatterns: []model.CommunicationPattern{
				createCommunicationPattern("192.168.1.10", "192.168.1.20", "EtherNetIP", "periodic", "critical", 1*time.Second), // High -> Critical
				oldPatterns[1],
			},
			expectedChangeCount: 1,
			expectedChangeTypes: []string{"criticality_changed"},
			expectedHighImpact:  1,
		},
		{
			name: "Multiple changes",
			newPatterns: []model.CommunicationPattern{
				createCommunicationPattern("192.168.1.10", "192.168.1.20", "EtherNetIP", "periodic", "critical", 100*time.Millisecond), // Freq + criticality change
				createCommunicationPattern("192.168.1.25", "192.168.1.35", "HTTP", "event-driven", "low", 10*time.Second),              // New pattern
			},
			expectedChangeCount: 3, // freq change + criticality change + new pattern + removed pattern
			expectedChangeTypes: []string{"frequency_changed", "criticality_changed", "new_pattern"},
			expectedHighImpact:  2,
		},
		{
			name:                "No changes",
			newPatterns:         oldPatterns,
			expectedChangeCount: 0,
			expectedChangeTypes: []string{},
			expectedHighImpact:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes := analyzer.DetectPatternChanges(oldPatterns, tt.newPatterns)

			assert.Equal(t, tt.expectedChangeCount, len(changes))

			// Check change types
			changeTypes := make(map[string]bool)
			highImpactCount := 0
			for _, change := range changes {
				changeTypes[change.ChangeType] = true
				if change.Impact == "high" || change.Impact == "critical" {
					highImpactCount++
				}

				// Verify change properties
				assert.NotEmpty(t, change.DeviceID)
				assert.GreaterOrEqual(t, change.ChangeSignificance, 0.0)
				assert.LessOrEqual(t, change.ChangeSignificance, 1.0)
				assert.NotZero(t, change.DetectedAt)
				assert.NotEmpty(t, change.Reason)
			}

			for _, expectedType := range tt.expectedChangeTypes {
				assert.True(t, changeTypes[expectedType], "Expected change type %s not found", expectedType)
			}

			assert.Equal(t, tt.expectedHighImpact, highImpactCount)
		})
	}
}

func TestCommunicationPatternAnalyzer_UpdateDeviceClassificationFromPatterns(t *testing.T) {
	analyzer := NewCommunicationPatternAnalyzer()

	tests := []struct {
		name                  string
		deviceID              string
		changes               []PatternChange
		expectedDeviceType    model.IndustrialDeviceType
		expectedRole          model.IndustrialDeviceRole
		expectedSecurityLevel model.SecurityLevel
		minConfidence         float64
		expectError           bool
	}{
		{
			name:     "PLC with critical EtherNet/IP patterns",
			deviceID: "192.168.1.10",
			changes: []PatternChange{
				{
					DeviceID:           "192.168.1.10",
					ChangeType:         "new_pattern",
					NewPattern:         &model.CommunicationPattern{Protocol: "EtherNetIP", Criticality: "critical"},
					ChangeSignificance: 0.9,
					Impact:             "critical",
				},
			},
			expectedDeviceType:    model.DeviceTypePLC,
			expectedRole:          model.RoleController,
			expectedSecurityLevel: model.SecurityLevel4,
			minConfidence:         0.5,
			expectError:           false,
		},
		{
			name:     "HMI with OPC UA patterns",
			deviceID: "192.168.1.20",
			changes: []PatternChange{
				{
					DeviceID:           "192.168.1.20",
					ChangeType:         "new_pattern",
					NewPattern:         &model.CommunicationPattern{Protocol: "OPCUA", Criticality: "high"},
					ChangeSignificance: 0.7,
					Impact:             "high",
				},
			},
			expectedDeviceType:    model.DeviceTypeHMI,
			expectedRole:          model.RoleOperator,
			expectedSecurityLevel: model.SecurityLevel3,
			minConfidence:         0.5,
			expectError:           false,
		},
		{
			name:     "Engineering workstation with HTTP patterns",
			deviceID: "192.168.1.100",
			changes: []PatternChange{
				{
					DeviceID:           "192.168.1.100",
					ChangeType:         "new_pattern",
					NewPattern:         &model.CommunicationPattern{Protocol: "HTTP", Criticality: "medium"},
					ChangeSignificance: 0.5,
					Impact:             "medium",
				},
			},
			expectedDeviceType:    model.DeviceTypeEngWorkstation,
			expectedRole:          model.RoleEngineer,
			expectedSecurityLevel: model.SecurityLevel2,
			minConfidence:         0.4,
			expectError:           false,
		},
		{
			name:        "No changes provided",
			deviceID:    "192.168.1.30",
			changes:     []PatternChange{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification, err := analyzer.UpdateDeviceClassificationFromPatterns(tt.deviceID, tt.changes)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedDeviceType, classification.DeviceType)
			assert.Equal(t, tt.expectedRole, classification.Role)
			assert.Equal(t, tt.expectedSecurityLevel, classification.SecurityLevel)
			assert.GreaterOrEqual(t, classification.Confidence, tt.minConfidence)
			assert.NotZero(t, classification.LastUpdated)
			assert.NotEmpty(t, classification.Reasoning)
			assert.NotEmpty(t, classification.Protocols)
		})
	}
}

// Helper functions for creating test data

func createPeriodicFlows(sourceAddr, destAddr, protocol string, interval time.Duration, count int, jitter time.Duration) []model.Flow {
	flows := make([]model.Flow, count)
	baseTime := time.Now().Add(-time.Duration(count) * interval)

	for i := 0; i < count; i++ {
		// Add some jitter to make it more realistic
		jitterOffset := time.Duration(i%3-1) * jitter
		timestamp := baseTime.Add(time.Duration(i) * interval).Add(jitterOffset)

		srcIP, _, _ := addressHelper.ParseAddress(sourceAddr)
		dstIP, _, _ := addressHelper.ParseAddress(destAddr)
		flows[i] = model.Flow{
			ID:          int64(i + 1),
			SrcIP:       net.ParseIP(srcIP),
			DstIP:       net.ParseIP(dstIP),
			Protocol:    protocol,
			PacketCount: 1,
			ByteCount:   int64(64),
			FirstSeen:   timestamp,
			LastSeen:    timestamp.Add(10 * time.Millisecond),
		}
	}

	return flows
}

func createBurstPeriodicFlows(sourceAddr, destAddr, protocol string, burstInterval time.Duration, burstCount int) []model.Flow {
	flows := make([]model.Flow, burstCount*3) // 3 flows per burst
	baseTime := time.Now().Add(-time.Duration(burstCount) * burstInterval)

	for burst := 0; burst < burstCount; burst++ {
		burstTime := baseTime.Add(time.Duration(burst) * burstInterval)

		for i := 0; i < 3; i++ {
			flowIndex := burst*3 + i
			timestamp := burstTime.Add(time.Duration(i) * 50 * time.Millisecond)

			srcIP, _, _ := addressHelper.ParseAddress(sourceAddr)
			dstIP, _, _ := addressHelper.ParseAddress(destAddr)
			flows[flowIndex] = model.Flow{
				ID:          int64(flowIndex + 1),
				SrcIP:       net.ParseIP(srcIP),
				DstIP:       net.ParseIP(dstIP),
				Protocol:    protocol,
				PacketCount: 1,
				ByteCount:   int64(32),
				FirstSeen:   timestamp,
				LastSeen:    timestamp.Add(5 * time.Millisecond),
			}
		}
	}

	return flows
}

func createRequestResponseFlows(sourceAddr, destAddr, protocol string, latency time.Duration, pairCount int) []model.Flow {
	flows := make([]model.Flow, pairCount*2) // Request + response for each pair
	baseTime := time.Now().Add(-time.Duration(pairCount) * 2 * time.Second)

	for i := 0; i < pairCount; i++ {
		requestTime := baseTime.Add(time.Duration(i) * 2 * time.Second)
		responseTime := requestTime.Add(latency)

		// Request flow
		srcIP, _, _ := addressHelper.ParseAddress(sourceAddr)
		dstIP, _, _ := addressHelper.ParseAddress(destAddr)
		flows[i*2] = model.Flow{
			ID:          int64(i*2 + 1),
			SrcIP:       net.ParseIP(srcIP),
			DstIP:       net.ParseIP(dstIP),
			Protocol:    protocol,
			PacketCount: 1,
			ByteCount:   int64(32), // Smaller request
			FirstSeen:   requestTime,
			LastSeen:    requestTime.Add(5 * time.Millisecond),
		}

		// Response flow
		srcIP2, _, _ := addressHelper.ParseAddress(destAddr)
		dstIP2, _, _ := addressHelper.ParseAddress(sourceAddr)
		flows[i*2+1] = model.Flow{
			ID:          int64(i*2 + 2),
			SrcIP:       net.ParseIP(srcIP2),
			DstIP:       net.ParseIP(dstIP2),
			Protocol:    protocol,
			PacketCount: 1,
			ByteCount:   int64(128), // Larger response
			FirstSeen:   responseTime,
			LastSeen:    responseTime.Add(10 * time.Millisecond),
		}
	}

	return flows
}

func createHighFrequencyRequestResponseFlows(sourceAddr, destAddr, protocol string, latency time.Duration, pairCount int) []model.Flow {
	flows := make([]model.Flow, pairCount*2)
	baseTime := time.Now().Add(-time.Duration(pairCount) * 100 * time.Millisecond) // High frequency: every 100ms

	for i := 0; i < pairCount; i++ {
		requestTime := baseTime.Add(time.Duration(i) * 100 * time.Millisecond)
		responseTime := requestTime.Add(latency)

		// Request flow
		srcIP, _, _ := addressHelper.ParseAddress(sourceAddr)
		dstIP, _, _ := addressHelper.ParseAddress(destAddr)
		flows[i*2] = model.Flow{
			ID:          int64(i*2 + 1),
			SrcIP:       net.ParseIP(srcIP),
			DstIP:       net.ParseIP(dstIP),
			Protocol:    protocol,
			PacketCount: 1,
			ByteCount:   int64(16),
			FirstSeen:   requestTime,
			LastSeen:    requestTime.Add(2 * time.Millisecond),
		}

		// Response flow
		srcIP2, _, _ := addressHelper.ParseAddress(destAddr)
		dstIP2, _, _ := addressHelper.ParseAddress(sourceAddr)
		flows[i*2+1] = model.Flow{
			ID:          int64(i*2 + 2),
			SrcIP:       net.ParseIP(srcIP2),
			DstIP:       net.ParseIP(dstIP2),
			Protocol:    protocol,
			PacketCount: 1,
			ByteCount:   int64(32),
			FirstSeen:   responseTime,
			LastSeen:    responseTime.Add(5 * time.Millisecond),
		}
	}

	return flows
}

func createCommunicationPattern(sourceAddr, destAddr, protocol, patternType, criticality string, frequency time.Duration) model.CommunicationPattern {
	return model.CommunicationPattern{
		SourceDevice:      sourceAddr,
		DestinationDevice: destAddr,
		Protocol:          protocol,
		Frequency:         frequency,
		DataVolume:        1024,
		PatternType:       patternType,
		Criticality:       criticality,
	}
}
