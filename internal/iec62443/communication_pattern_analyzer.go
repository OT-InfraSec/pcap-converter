package iec62443

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// CommunicationPatternAnalyzer provides advanced analysis of communication patterns
type CommunicationPatternAnalyzer interface {
	// AnalyzePeriodicPatterns detects and classifies periodic communication patterns
	AnalyzePeriodicPatterns(flows []model.Flow) []PeriodicPattern

	// AnalyzeRequestResponsePatterns identifies request-response patterns and determines criticality
	AnalyzeRequestResponsePatterns(flows []model.Flow) []RequestResponsePattern

	// DetermineCommunicationCriticality calculates criticality levels based on pattern analysis
	DetermineCommunicationCriticality(patterns []model.CommunicationPattern) CriticalityAssessment

	// DetectPatternChanges identifies changes in communication patterns over time
	DetectPatternChanges(oldPatterns, newPatterns []model.CommunicationPattern) []PatternChange

	// UpdateDeviceClassificationFromPatterns updates device classifications based on pattern changes
	UpdateDeviceClassificationFromPatterns(deviceID string, changes []PatternChange) (IndustrialDeviceClassification, error)
}

// PeriodicPattern represents a detected periodic communication pattern
type PeriodicPattern struct {
	SourceDevice      string        `json:"source_device"`
	DestinationDevice string        `json:"destination_device"`
	Protocol          string        `json:"protocol"`
	Frequency         time.Duration `json:"frequency"`
	FrequencyStdDev   time.Duration `json:"frequency_std_dev"`
	Regularity        float64       `json:"regularity"`   // 0.0 to 1.0, how regular the pattern is
	Confidence        float64       `json:"confidence"`   // 0.0 to 1.0, confidence in detection
	SampleCount       int           `json:"sample_count"` // Number of samples used for analysis
	FirstSeen         time.Time     `json:"first_seen"`
	LastSeen          time.Time     `json:"last_seen"`
	PatternType       string        `json:"pattern_type"`      // "strict_periodic", "loose_periodic", "burst_periodic"
	CriticalityLevel  string        `json:"criticality_level"` // "low", "medium", "high", "critical"
}

// RequestResponsePattern represents a detected request-response communication pattern
type RequestResponsePattern struct {
	InitiatorDevice  string        `json:"initiator_device"`
	ResponderDevice  string        `json:"responder_device"`
	Protocol         string        `json:"protocol"`
	AverageLatency   time.Duration `json:"average_latency"`
	LatencyStdDev    time.Duration `json:"latency_std_dev"`
	RequestRate      float64       `json:"request_rate"`  // Requests per second
	ResponseRate     float64       `json:"response_rate"` // Response rate (0.0 to 1.0)
	TimeoutRate      float64       `json:"timeout_rate"`  // Timeout rate (0.0 to 1.0)
	SampleCount      int           `json:"sample_count"`
	FirstSeen        time.Time     `json:"first_seen"`
	LastSeen         time.Time     `json:"last_seen"`
	PatternType      string        `json:"pattern_type"`      // "synchronous", "asynchronous", "polling"
	CriticalityLevel string        `json:"criticality_level"` // Based on latency requirements and timeout rates
	ServiceType      string        `json:"service_type"`      // "control", "monitoring", "configuration", "data_collection"
}

// CriticalityAssessment represents the overall criticality assessment of communication patterns
type CriticalityAssessment struct {
	OverallCriticality   string                          `json:"overall_criticality"`
	CriticalPatternCount int                             `json:"critical_pattern_count"`
	HighPatternCount     int                             `json:"high_pattern_count"`
	MediumPatternCount   int                             `json:"medium_pattern_count"`
	LowPatternCount      int                             `json:"low_pattern_count"`
	PatternBreakdown     map[string]CriticalityBreakdown `json:"pattern_breakdown"`
	RiskFactors          []string                        `json:"risk_factors"`
	RecommendedActions   []string                        `json:"recommended_actions"`
	AssessmentTimestamp  time.Time                       `json:"assessment_timestamp"`
}

// CriticalityBreakdown provides detailed breakdown of criticality by pattern type
type CriticalityBreakdown struct {
	PatternType        string  `json:"pattern_type"`
	Count              int     `json:"count"`
	AverageCriticality float64 `json:"average_criticality"` // 0.0 to 1.0
	MaxCriticality     float64 `json:"max_criticality"`
	MinCriticality     float64 `json:"min_criticality"`
}

// PatternChange represents a detected change in communication patterns
type PatternChange struct {
	DeviceID           string                      `json:"device_id"`
	ChangeType         string                      `json:"change_type"` // "new_pattern", "pattern_removed", "frequency_changed", "criticality_changed"
	OldPattern         *model.CommunicationPattern `json:"old_pattern,omitempty"`
	NewPattern         *model.CommunicationPattern `json:"new_pattern,omitempty"`
	ChangeSignificance float64                     `json:"change_significance"` // 0.0 to 1.0, how significant the change is
	DetectedAt         time.Time                   `json:"detected_at"`
	Impact             string                      `json:"impact"`          // "low", "medium", "high", "critical"
	Reason             string                      `json:"reason"`          // Human-readable explanation
	RequiresAction     bool                        `json:"requires_action"` // Whether this change requires immediate attention
}

// CommunicationPatternAnalyzerImpl implements the CommunicationPatternAnalyzer interface
type CommunicationPatternAnalyzerImpl struct {
	// Configuration parameters
	minSamplesForPattern     int           // Minimum number of samples to detect a pattern
	periodicityTolerance     float64       // Tolerance for periodic pattern detection (0.0 to 1.0)
	criticalLatencyThreshold time.Duration // Latency threshold for critical classification
	highLatencyThreshold     time.Duration // Latency threshold for high classification
}

// NewCommunicationPatternAnalyzer creates a new communication pattern analyzer
func NewCommunicationPatternAnalyzer() CommunicationPatternAnalyzer {
	return &CommunicationPatternAnalyzerImpl{
		minSamplesForPattern:     5,
		periodicityTolerance:     0.2, // 20% tolerance
		criticalLatencyThreshold: 100 * time.Millisecond,
		highLatencyThreshold:     500 * time.Millisecond,
	}
}

// AnalyzePeriodicPatterns detects and classifies periodic communication patterns
func (cpa *CommunicationPatternAnalyzerImpl) AnalyzePeriodicPatterns(flows []model.Flow) []PeriodicPattern {
	if len(flows) < cpa.minSamplesForPattern {
		return []PeriodicPattern{}
	}

	// Group flows by source-destination-protocol combination
	flowGroups := cpa.groupFlowsByEndpoints(flows)
	patterns := make([]PeriodicPattern, 0)

	for key, groupFlows := range flowGroups {
		if len(groupFlows) < cpa.minSamplesForPattern {
			continue
		}

		pattern := cpa.analyzePeriodicityInFlowGroup(key, groupFlows)
		if pattern != nil {
			patterns = append(patterns, *pattern)
		}
	}

	return patterns
}

// AnalyzeRequestResponsePatterns identifies request-response patterns and determines criticality
func (cpa *CommunicationPatternAnalyzerImpl) AnalyzeRequestResponsePatterns(flows []model.Flow) []RequestResponsePattern {
	if len(flows) < 2 {
		return []RequestResponsePattern{}
	}

	// Group flows by protocol and endpoints to find request-response pairs
	patterns := make([]RequestResponsePattern, 0)
	flowPairs := cpa.findRequestResponsePairs(flows)

	for _, pairs := range flowPairs {
		if len(pairs) < cpa.minSamplesForPattern {
			continue
		}

		pattern := cpa.analyzeRequestResponseLatency(pairs)
		if pattern != nil {
			patterns = append(patterns, *pattern)
		}
	}

	return patterns
}

// DetermineCommunicationCriticality calculates criticality levels based on pattern analysis
func (cpa *CommunicationPatternAnalyzerImpl) DetermineCommunicationCriticality(patterns []model.CommunicationPattern) CriticalityAssessment {
	assessment := CriticalityAssessment{
		PatternBreakdown:    make(map[string]CriticalityBreakdown),
		RiskFactors:         make([]string, 0),
		RecommendedActions:  make([]string, 0),
		AssessmentTimestamp: time.Now(),
	}

	if len(patterns) == 0 {
		assessment.OverallCriticality = "low"
		assessment.RecommendedActions = append(assessment.RecommendedActions, "Monitor network traffic to establish communication patterns")
		return assessment
	}

	// Count patterns by criticality level
	criticalityScores := make([]float64, 0)
	patternTypeBreakdown := make(map[string][]float64)

	for _, pattern := range patterns {
		score := cpa.calculateCriticalityScore(pattern)
		criticalityScores = append(criticalityScores, score)

		// Update pattern type breakdown
		if _, exists := patternTypeBreakdown[pattern.PatternType]; !exists {
			patternTypeBreakdown[pattern.PatternType] = make([]float64, 0)
		}
		patternTypeBreakdown[pattern.PatternType] = append(patternTypeBreakdown[pattern.PatternType], score)

		// Count by criticality level
		switch pattern.Criticality {
		case "critical":
			assessment.CriticalPatternCount++
		case "high":
			assessment.HighPatternCount++
		case "medium":
			assessment.MediumPatternCount++
		default:
			assessment.LowPatternCount++
		}
	}

	// Calculate pattern breakdown statistics
	for patternType, scores := range patternTypeBreakdown {
		breakdown := CriticalityBreakdown{
			PatternType:        patternType,
			Count:              len(scores),
			AverageCriticality: cpa.calculateAverage(scores),
			MaxCriticality:     cpa.calculateMax(scores),
			MinCriticality:     cpa.calculateMin(scores),
		}
		assessment.PatternBreakdown[patternType] = breakdown
	}

	// Determine overall criticality
	assessment.OverallCriticality = cpa.determineOverallCriticality(assessment)

	// Generate risk factors and recommendations
	cpa.generateRiskFactorsAndRecommendations(&assessment, patterns)

	return assessment
}

// DetectPatternChanges identifies changes in communication patterns over time
func (cpa *CommunicationPatternAnalyzerImpl) DetectPatternChanges(oldPatterns, newPatterns []model.CommunicationPattern) []PatternChange {
	changes := make([]PatternChange, 0)

	// Create maps for easier comparison
	oldPatternMap := cpa.createPatternMap(oldPatterns)
	newPatternMap := cpa.createPatternMap(newPatterns)

	// Detect new patterns
	for key, newPattern := range newPatternMap {
		if _, exists := oldPatternMap[key]; !exists {
			change := PatternChange{
				DeviceID:           newPattern.SourceDevice,
				ChangeType:         "new_pattern",
				NewPattern:         &newPattern,
				ChangeSignificance: cpa.calculateNewPatternSignificance(newPattern),
				DetectedAt:         time.Now(),
				Impact:             cpa.determineChangeImpact(newPattern.Criticality),
				Reason:             fmt.Sprintf("New %s communication pattern detected between %s and %s", newPattern.Protocol, newPattern.SourceDevice, newPattern.DestinationDevice),
				RequiresAction:     newPattern.Criticality == "critical" || newPattern.Criticality == "high",
			}
			changes = append(changes, change)
		}
	}

	// Detect removed patterns
	for key, oldPattern := range oldPatternMap {
		if _, exists := newPatternMap[key]; !exists {
			change := PatternChange{
				DeviceID:           oldPattern.SourceDevice,
				ChangeType:         "pattern_removed",
				OldPattern:         &oldPattern,
				ChangeSignificance: cpa.calculateRemovedPatternSignificance(oldPattern),
				DetectedAt:         time.Now(),
				Impact:             cpa.determineChangeImpact(oldPattern.Criticality),
				Reason:             fmt.Sprintf("%s communication pattern removed between %s and %s", oldPattern.Protocol, oldPattern.SourceDevice, oldPattern.DestinationDevice),
				RequiresAction:     oldPattern.Criticality == "critical" || oldPattern.Criticality == "high",
			}
			changes = append(changes, change)
		}
	}

	// Detect changed patterns
	for key, newPattern := range newPatternMap {
		if oldPattern, exists := oldPatternMap[key]; exists {
			patternChanges := cpa.comparePatterns(oldPattern, newPattern)
			changes = append(changes, patternChanges...)
		}
	}

	return changes
}

// UpdateDeviceClassificationFromPatterns updates device classifications based on pattern changes
func (cpa *CommunicationPatternAnalyzerImpl) UpdateDeviceClassificationFromPatterns(deviceID string, changes []PatternChange) (IndustrialDeviceClassification, error) {
	if len(changes) == 0 {
		return IndustrialDeviceClassification{}, fmt.Errorf("no pattern changes provided for device %s", deviceID)
	}

	// Analyze the significance of changes
	totalSignificance := 0.0
	criticalChanges := 0
	highImpactChanges := 0

	for _, change := range changes {
		totalSignificance += change.ChangeSignificance
		if change.Impact == "critical" {
			criticalChanges++
		} else if change.Impact == "high" {
			highImpactChanges++
		}
	}

	// Determine if classification update is needed
	averageSignificance := totalSignificance / float64(len(changes))

	// Create updated classification based on pattern changes
	classification := IndustrialDeviceClassification{
		LastUpdated: time.Now(),
		Reasoning:   cpa.generatePatternChangeReasoning(changes, averageSignificance),
	}

	// Adjust device type and role based on pattern changes
	classification.DeviceType, classification.Role = cpa.inferDeviceTypeFromPatternChanges(changes)

	// Calculate new confidence based on pattern stability and significance
	classification.Confidence = cpa.calculatePatternBasedConfidence(changes, averageSignificance)

	// Determine security level based on criticality of patterns
	classification.SecurityLevel = cpa.determineSecurityLevelFromPatterns(changes)

	// Extract protocols from pattern changes
	protocolSet := make(map[string]bool)
	for _, change := range changes {
		if change.NewPattern != nil {
			protocolSet[change.NewPattern.Protocol] = true
		}
		if change.OldPattern != nil {
			protocolSet[change.OldPattern.Protocol] = true
		}
	}

	protocols := make([]string, 0, len(protocolSet))
	for protocol := range protocolSet {
		protocols = append(protocols, protocol)
	}
	classification.Protocols = protocols

	return classification, nil
}

// Helper methods for flow grouping and analysis

// flowGroupKey represents a unique key for grouping flows
type flowGroupKey struct {
	sourceAddr string
	destAddr   string
	protocol   string
}

// requestResponsePair represents a request-response pair
type requestResponsePair struct {
	request  model.Flow
	response model.Flow
	latency  time.Duration
}

// groupFlowsByEndpoints groups flows by source-destination-protocol combination
func (cpa *CommunicationPatternAnalyzerImpl) groupFlowsByEndpoints(flows []model.Flow) map[flowGroupKey][]model.Flow {
	groups := make(map[flowGroupKey][]model.Flow)

	for _, flow := range flows {
		key := flowGroupKey{
			sourceAddr: flow.Source,
			destAddr:   flow.Destination,
			protocol:   flow.Protocol,
		}

		if _, exists := groups[key]; !exists {
			groups[key] = make([]model.Flow, 0)
		}
		groups[key] = append(groups[key], flow)
	}

	return groups
}

// analyzePeriodicityInFlowGroup analyzes periodicity within a group of flows
func (cpa *CommunicationPatternAnalyzerImpl) analyzePeriodicityInFlowGroup(key flowGroupKey, flows []model.Flow) *PeriodicPattern {
	if len(flows) < cpa.minSamplesForPattern {
		return nil
	}

	// Sort flows by timestamp
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].FirstSeen.Before(flows[j].FirstSeen)
	})

	// Calculate intervals between consecutive flows
	intervals := make([]time.Duration, 0, len(flows)-1)
	for i := 1; i < len(flows); i++ {
		interval := flows[i].FirstSeen.Sub(flows[i-1].FirstSeen)
		if interval > 0 {
			intervals = append(intervals, interval)
		}
	}

	if len(intervals) < cpa.minSamplesForPattern-1 {
		return nil
	}

	// Calculate statistics
	avgInterval := cpa.calculateAverageInterval(intervals)
	stdDev := cpa.calculateStdDevInterval(intervals, avgInterval)
	regularity := cpa.calculateRegularity(intervals, avgInterval)
	confidence := cpa.calculatePeriodicityConfidence(intervals, regularity)

	// Determine pattern type based on regularity
	patternType := cpa.determinePeriodicPatternType(regularity, stdDev, avgInterval)

	// Determine criticality based on frequency and regularity
	criticalityLevel := cpa.determinePeriodicCriticality(avgInterval, regularity, patternType)

	return &PeriodicPattern{
		SourceDevice:      key.sourceAddr,
		DestinationDevice: key.destAddr,
		Protocol:          key.protocol,
		Frequency:         avgInterval,
		FrequencyStdDev:   stdDev,
		Regularity:        regularity,
		Confidence:        confidence,
		SampleCount:       len(intervals),
		FirstSeen:         flows[0].FirstSeen,
		LastSeen:          flows[len(flows)-1].FirstSeen,
		PatternType:       patternType,
		CriticalityLevel:  criticalityLevel,
	}
}

// findRequestResponsePairs identifies request-response pairs in flows
func (cpa *CommunicationPatternAnalyzerImpl) findRequestResponsePairs(flows []model.Flow) map[string][]requestResponsePair {
	pairs := make(map[string][]requestResponsePair)

	// Sort flows by timestamp
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].FirstSeen.Before(flows[j].FirstSeen)
	})

	// Group flows by protocol and endpoints for bidirectional analysis
	for i := 0; i < len(flows)-1; i++ {
		for j := i + 1; j < len(flows) && j < i+10; j++ { // Look ahead up to 10 flows
			if cpa.isRequestResponsePair(flows[i], flows[j]) {
				key := fmt.Sprintf("%s_%s_%s", flows[i].Protocol, flows[i].Source, flows[j].Source)

				pair := requestResponsePair{
					request:  flows[i],
					response: flows[j],
					latency:  flows[j].FirstSeen.Sub(flows[i].FirstSeen),
				}

				if _, exists := pairs[key]; !exists {
					pairs[key] = make([]requestResponsePair, 0)
				}
				pairs[key] = append(pairs[key], pair)
				break // Found response for this request
			}
		}
	}

	return pairs
}

// isRequestResponsePair determines if two flows form a request-response pair
func (cpa *CommunicationPatternAnalyzerImpl) isRequestResponsePair(flow1, flow2 model.Flow) bool {
	// Check if flows are in opposite directions
	if flow1.Source != flow2.Destination || flow1.Destination != flow2.Source {
		return false
	}

	// Check if they use the same protocol
	if flow1.Protocol != flow2.Protocol {
		return false
	}

	// Check if response comes after request within reasonable time
	timeDiff := flow2.FirstSeen.Sub(flow1.FirstSeen)
	if timeDiff <= 0 || timeDiff > 30*time.Second {
		return false
	}

	// Check if request is typically smaller than response (common pattern)
	// This is a heuristic and may need adjustment based on specific protocols
	return flow1.Bytes <= flow2.Bytes*2 // Allow some tolerance
}

// analyzeRequestResponseLatency analyzes latency patterns in request-response pairs
func (cpa *CommunicationPatternAnalyzerImpl) analyzeRequestResponseLatency(pairs []requestResponsePair) *RequestResponsePattern {
	if len(pairs) < cpa.minSamplesForPattern {
		return nil
	}

	// Calculate latency statistics
	latencies := make([]time.Duration, len(pairs))
	for i, pair := range pairs {
		latencies[i] = pair.latency
	}

	avgLatency := cpa.calculateAverageInterval(latencies)
	stdDev := cpa.calculateStdDevInterval(latencies, avgLatency)

	// Calculate request rate (requests per second)
	timeSpan := pairs[len(pairs)-1].request.FirstSeen.Sub(pairs[0].request.FirstSeen)
	requestRate := float64(len(pairs)) / timeSpan.Seconds()

	// Calculate response rate and timeout rate
	responseRate := 1.0 // Assume all pairs have responses since we found them
	timeoutRate := 0.0  // Calculate based on missing responses if needed

	// Determine pattern type based on latency characteristics
	patternType := cpa.determineRequestResponsePatternType(avgLatency, stdDev, requestRate)

	// Determine criticality based on latency requirements
	criticalityLevel := cpa.determineRequestResponseCriticality(avgLatency, stdDev, timeoutRate)

	// Infer service type based on protocol and latency characteristics
	serviceType := cpa.inferServiceType(pairs[0].request.Protocol, avgLatency, requestRate)

	return &RequestResponsePattern{
		InitiatorDevice:  pairs[0].request.Source,
		ResponderDevice:  pairs[0].request.Destination,
		Protocol:         pairs[0].request.Protocol,
		AverageLatency:   avgLatency,
		LatencyStdDev:    stdDev,
		RequestRate:      requestRate,
		ResponseRate:     responseRate,
		TimeoutRate:      timeoutRate,
		SampleCount:      len(pairs),
		FirstSeen:        pairs[0].request.FirstSeen,
		LastSeen:         pairs[len(pairs)-1].request.FirstSeen,
		PatternType:      patternType,
		CriticalityLevel: criticalityLevel,
		ServiceType:      serviceType,
	}
}

// Statistical calculation helper methods

func (cpa *CommunicationPatternAnalyzerImpl) calculateAverageInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	total := time.Duration(0)
	for _, interval := range intervals {
		total += interval
	}
	return total / time.Duration(len(intervals))
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateStdDevInterval(intervals []time.Duration, avg time.Duration) time.Duration {
	if len(intervals) <= 1 {
		return 0
	}

	sumSquaredDiffs := float64(0)
	for _, interval := range intervals {
		diff := float64(interval - avg)
		sumSquaredDiffs += diff * diff
	}

	variance := sumSquaredDiffs / float64(len(intervals)-1)
	return time.Duration(math.Sqrt(variance))
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateRegularity(intervals []time.Duration, avg time.Duration) float64 {
	if len(intervals) == 0 || avg == 0 {
		return 0.0
	}

	// Calculate coefficient of variation (CV = stddev / mean)
	stdDev := cpa.calculateStdDevInterval(intervals, avg)
	cv := float64(stdDev) / float64(avg)

	// Convert to regularity score (1.0 = perfectly regular, 0.0 = completely irregular)
	regularity := math.Max(0.0, 1.0-cv)
	return math.Min(1.0, regularity)
}

func (cpa *CommunicationPatternAnalyzerImpl) calculatePeriodicityConfidence(intervals []time.Duration, regularity float64) float64 {
	// Base confidence on regularity and sample size
	sampleSizeBonus := math.Min(1.0, float64(len(intervals))/20.0) // Bonus for more samples
	confidence := regularity*0.8 + sampleSizeBonus*0.2
	return math.Min(1.0, confidence)
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	sum := 0.0
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateMax(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	max := values[0]
	for _, value := range values[1:] {
		if value > max {
			max = value
		}
	}
	return max
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateMin(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}

// Pattern classification helper methods

func (cpa *CommunicationPatternAnalyzerImpl) determinePeriodicPatternType(regularity float64, stdDev, avgInterval time.Duration) string {
	if regularity >= 0.8 {
		return "strict_periodic"
	} else if regularity >= 0.5 {
		return "loose_periodic"
	} else if avgInterval < 5*time.Second && regularity >= 0.3 {
		return "burst_periodic"
	}
	return "irregular"
}

func (cpa *CommunicationPatternAnalyzerImpl) determinePeriodicCriticality(frequency time.Duration, regularity float64, patternType string) string {
	// High-frequency, regular patterns are typically more critical
	if frequency <= 100*time.Millisecond && regularity >= 0.8 {
		return "critical"
	} else if frequency <= 1*time.Second && regularity >= 0.6 {
		return "high"
	} else if frequency <= 10*time.Second && regularity >= 0.4 {
		return "medium"
	}
	return "low"
}

func (cpa *CommunicationPatternAnalyzerImpl) determineRequestResponsePatternType(avgLatency, stdDev time.Duration, requestRate float64) string {
	// Classify based on latency characteristics and request rate
	if avgLatency <= 50*time.Millisecond && stdDev <= 10*time.Millisecond {
		return "synchronous"
	} else if requestRate >= 10.0 { // High request rate suggests polling
		return "polling"
	}
	return "asynchronous"
}

func (cpa *CommunicationPatternAnalyzerImpl) determineRequestResponseCriticality(avgLatency, stdDev time.Duration, timeoutRate float64) string {
	// Critical systems typically have low latency requirements
	if avgLatency <= cpa.criticalLatencyThreshold && timeoutRate <= 0.01 {
		return "critical"
	} else if avgLatency <= cpa.highLatencyThreshold && timeoutRate <= 0.05 {
		return "high"
	} else if timeoutRate <= 0.1 {
		return "medium"
	}
	return "low"
}

func (cpa *CommunicationPatternAnalyzerImpl) inferServiceType(protocol string, avgLatency time.Duration, requestRate float64) string {
	// Infer service type based on protocol and characteristics
	switch protocol {
	case "EtherNetIP":
		if avgLatency <= 10*time.Millisecond {
			return "control"
		} else if requestRate >= 1.0 {
			return "monitoring"
		}
		return "data_collection"
	case "OPCUA":
		if requestRate >= 10.0 {
			return "monitoring"
		} else if avgLatency <= 100*time.Millisecond {
			return "control"
		}
		return "data_collection"
	case "Modbus":
		if requestRate >= 5.0 {
			return "monitoring"
		}
		return "control"
	case "HTTP", "HTTPS":
		return "configuration"
	default:
		return "data_collection"
	}
}

// Criticality assessment helper methods

func (cpa *CommunicationPatternAnalyzerImpl) calculateCriticalityScore(pattern model.CommunicationPattern) float64 {
	// Convert criticality level to numeric score
	switch pattern.Criticality {
	case "critical":
		return 1.0
	case "high":
		return 0.75
	case "medium":
		return 0.5
	case "low":
		return 0.25
	default:
		return 0.0
	}
}

func (cpa *CommunicationPatternAnalyzerImpl) determineOverallCriticality(assessment CriticalityAssessment) string {
	total := assessment.CriticalPatternCount + assessment.HighPatternCount + assessment.MediumPatternCount + assessment.LowPatternCount
	if total == 0 {
		return "low"
	}

	// Calculate weighted criticality score
	criticalRatio := float64(assessment.CriticalPatternCount) / float64(total)
	highRatio := float64(assessment.HighPatternCount) / float64(total)

	if criticalRatio >= 0.3 {
		return "critical"
	} else if criticalRatio >= 0.1 || highRatio >= 0.5 {
		return "high"
	} else if highRatio >= 0.2 || float64(assessment.MediumPatternCount)/float64(total) >= 0.4 {
		return "medium"
	}
	return "low"
}

func (cpa *CommunicationPatternAnalyzerImpl) generateRiskFactorsAndRecommendations(assessment *CriticalityAssessment, patterns []model.CommunicationPattern) {
	// Analyze patterns for risk factors
	unencryptedCritical := 0
	highFrequencyPatterns := 0
	irregularCriticalPatterns := 0

	for _, pattern := range patterns {
		if pattern.Criticality == "critical" || pattern.Criticality == "high" {
			// Check for unencrypted critical communications
			if pattern.Protocol == "Modbus" || pattern.Protocol == "EtherNetIP" {
				unencryptedCritical++
			}

			// Check for high-frequency patterns
			if pattern.Frequency <= 1*time.Second {
				highFrequencyPatterns++
			}

			// Check for irregular critical patterns
			if pattern.PatternType == "event-driven" && pattern.Criticality == "critical" {
				irregularCriticalPatterns++
			}
		}
	}

	// Generate risk factors
	if unencryptedCritical > 0 {
		assessment.RiskFactors = append(assessment.RiskFactors, fmt.Sprintf("%d critical communications using unencrypted protocols", unencryptedCritical))
		assessment.RecommendedActions = append(assessment.RecommendedActions, "Implement encryption for critical industrial protocols")
	}

	if highFrequencyPatterns > 0 {
		assessment.RiskFactors = append(assessment.RiskFactors, fmt.Sprintf("%d high-frequency communication patterns detected", highFrequencyPatterns))
		assessment.RecommendedActions = append(assessment.RecommendedActions, "Monitor network bandwidth and implement QoS for critical communications")
	}

	if irregularCriticalPatterns > 0 {
		assessment.RiskFactors = append(assessment.RiskFactors, fmt.Sprintf("%d irregular critical communication patterns", irregularCriticalPatterns))
		assessment.RecommendedActions = append(assessment.RecommendedActions, "Investigate irregular critical communications for potential security issues")
	}

	if assessment.CriticalPatternCount > 0 {
		assessment.RecommendedActions = append(assessment.RecommendedActions, "Implement network segmentation for critical industrial communications")
	}
}

// Pattern change detection helper methods

func (cpa *CommunicationPatternAnalyzerImpl) createPatternMap(patterns []model.CommunicationPattern) map[string]model.CommunicationPattern {
	patternMap := make(map[string]model.CommunicationPattern)
	for _, pattern := range patterns {
		key := fmt.Sprintf("%s_%s_%s", pattern.SourceDevice, pattern.DestinationDevice, pattern.Protocol)
		patternMap[key] = pattern
	}
	return patternMap
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateNewPatternSignificance(pattern model.CommunicationPattern) float64 {
	// New patterns are more significant if they are critical or high frequency
	significance := 0.5 // Base significance for new patterns

	switch pattern.Criticality {
	case "critical":
		significance += 0.4
	case "high":
		significance += 0.3
	case "medium":
		significance += 0.1
	}

	if pattern.Frequency <= 1*time.Second {
		significance += 0.1
	}

	return math.Min(1.0, significance)
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateRemovedPatternSignificance(pattern model.CommunicationPattern) float64 {
	// Removed patterns are significant based on their previous criticality
	significance := 0.3 // Base significance for removed patterns

	switch pattern.Criticality {
	case "critical":
		significance += 0.5
	case "high":
		significance += 0.4
	case "medium":
		significance += 0.2
	}

	return math.Min(1.0, significance)
}

func (cpa *CommunicationPatternAnalyzerImpl) comparePatterns(oldPattern, newPattern model.CommunicationPattern) []PatternChange {
	changes := make([]PatternChange, 0)

	// Check for frequency changes
	if cpa.isSignificantFrequencyChange(oldPattern.Frequency, newPattern.Frequency) {
		change := PatternChange{
			DeviceID:           newPattern.SourceDevice,
			ChangeType:         "frequency_changed",
			OldPattern:         &oldPattern,
			NewPattern:         &newPattern,
			ChangeSignificance: cpa.calculateFrequencyChangeSignificance(oldPattern.Frequency, newPattern.Frequency),
			DetectedAt:         time.Now(),
			Impact:             cpa.determineFrequencyChangeImpact(oldPattern, newPattern),
			Reason:             fmt.Sprintf("Communication frequency changed from %v to %v", oldPattern.Frequency, newPattern.Frequency),
			RequiresAction:     newPattern.Criticality == "critical" || newPattern.Criticality == "high",
		}
		changes = append(changes, change)
	}

	// Check for criticality changes
	if oldPattern.Criticality != newPattern.Criticality {
		change := PatternChange{
			DeviceID:           newPattern.SourceDevice,
			ChangeType:         "criticality_changed",
			OldPattern:         &oldPattern,
			NewPattern:         &newPattern,
			ChangeSignificance: cpa.calculateCriticalityChangeSignificance(oldPattern.Criticality, newPattern.Criticality),
			DetectedAt:         time.Now(),
			Impact:             cpa.determineCriticalityChangeImpact(oldPattern.Criticality, newPattern.Criticality),
			Reason:             fmt.Sprintf("Communication criticality changed from %s to %s", oldPattern.Criticality, newPattern.Criticality),
			RequiresAction:     newPattern.Criticality == "critical" || (oldPattern.Criticality == "critical" && newPattern.Criticality != "critical"),
		}
		changes = append(changes, change)
	}

	return changes
}

func (cpa *CommunicationPatternAnalyzerImpl) isSignificantFrequencyChange(oldFreq, newFreq time.Duration) bool {
	if oldFreq == 0 || newFreq == 0 {
		return oldFreq != newFreq
	}

	// Consider change significant if it's more than 50% difference
	ratio := float64(newFreq) / float64(oldFreq)
	return ratio < 0.5 || ratio > 2.0
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateFrequencyChangeSignificance(oldFreq, newFreq time.Duration) float64 {
	if oldFreq == 0 || newFreq == 0 {
		return 1.0
	}

	ratio := float64(newFreq) / float64(oldFreq)
	if ratio < 1.0 {
		ratio = 1.0 / ratio
	}

	// Logarithmic scale for significance
	significance := math.Log2(ratio) / 4.0 // Normalize to 0-1 range
	return math.Min(1.0, significance)
}

func (cpa *CommunicationPatternAnalyzerImpl) calculateCriticalityChangeSignificance(oldCrit, newCrit string) float64 {
	oldScore := cpa.getCriticalityScore(oldCrit)
	newScore := cpa.getCriticalityScore(newCrit)

	diff := math.Abs(newScore - oldScore)
	return diff // Already in 0-1 range
}

func (cpa *CommunicationPatternAnalyzerImpl) getCriticalityScore(criticality string) float64 {
	switch criticality {
	case "critical":
		return 1.0
	case "high":
		return 0.75
	case "medium":
		return 0.5
	case "low":
		return 0.25
	default:
		return 0.0
	}
}

func (cpa *CommunicationPatternAnalyzerImpl) determineChangeImpact(criticality string) string {
	switch criticality {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func (cpa *CommunicationPatternAnalyzerImpl) determineFrequencyChangeImpact(oldPattern, newPattern model.CommunicationPattern) string {
	// Higher impact if critical communications change frequency
	if oldPattern.Criticality == "critical" || newPattern.Criticality == "critical" {
		return "critical"
	} else if oldPattern.Criticality == "high" || newPattern.Criticality == "high" {
		return "high"
	}
	return "medium"
}

func (cpa *CommunicationPatternAnalyzerImpl) determineCriticalityChangeImpact(oldCrit, newCrit string) string {
	// Impact based on the higher of the two criticality levels
	if oldCrit == "critical" || newCrit == "critical" {
		return "critical"
	} else if oldCrit == "high" || newCrit == "high" {
		return "high"
	} else if oldCrit == "medium" || newCrit == "medium" {
		return "medium"
	}
	return "low"
}

// Device classification update helper methods

func (cpa *CommunicationPatternAnalyzerImpl) generatePatternChangeReasoning(changes []PatternChange, averageSignificance float64) string {
	if len(changes) == 0 {
		return "No pattern changes detected"
	}

	changeTypes := make(map[string]int)
	for _, change := range changes {
		changeTypes[change.ChangeType]++
	}

	reasoning := fmt.Sprintf("Classification updated based on %d pattern changes (avg significance: %.2f): ", len(changes), averageSignificance)

	reasons := make([]string, 0)
	for changeType, count := range changeTypes {
		reasons = append(reasons, fmt.Sprintf("%d %s", count, changeType))
	}

	return reasoning + fmt.Sprintf("%s", reasons)
}

func (cpa *CommunicationPatternAnalyzerImpl) inferDeviceTypeFromPatternChanges(changes []PatternChange) (model.IndustrialDeviceType, model.IndustrialDeviceRole) {
	// Analyze pattern changes to infer device type and role
	protocolCounts := make(map[string]int)
	criticalityLevels := make(map[string]int)

	for _, change := range changes {
		if change.NewPattern != nil {
			protocolCounts[change.NewPattern.Protocol]++
			criticalityLevels[change.NewPattern.Criticality]++
		}
	}

	// Determine device type based on dominant protocols
	deviceType := model.DeviceTypeUnknown
	role := model.RoleFieldDevice

	// Check for industrial protocols
	if protocolCounts["EtherNetIP"] > 0 || protocolCounts["Modbus"] > 0 {
		if criticalityLevels["critical"] > 0 || criticalityLevels["high"] > 0 {
			deviceType = model.DeviceTypePLC
			role = model.RoleController
		} else {
			deviceType = model.DeviceTypeIODevice
			role = model.RoleFieldDevice
		}
	} else if protocolCounts["OPCUA"] > 0 {
		if criticalityLevels["high"] > 0 {
			deviceType = model.DeviceTypeHMI
			role = model.RoleOperator
		} else {
			deviceType = model.DeviceTypeHistorian
			role = model.RoleDataCollector
		}
	} else if protocolCounts["HTTP"] > 0 || protocolCounts["HTTPS"] > 0 {
		deviceType = model.DeviceTypeEngWorkstation
		role = model.RoleEngineer
	}

	return deviceType, role
}

func (cpa *CommunicationPatternAnalyzerImpl) calculatePatternBasedConfidence(changes []PatternChange, averageSignificance float64) float64 {
	// Base confidence on pattern stability and significance
	baseConfidence := 0.5

	// Adjust based on number of changes (more changes = more evidence)
	changeBonus := math.Min(0.3, float64(len(changes))*0.05)

	// Adjust based on average significance
	significanceBonus := averageSignificance * 0.2

	confidence := baseConfidence + changeBonus + significanceBonus
	return math.Min(1.0, confidence)
}

func (cpa *CommunicationPatternAnalyzerImpl) determineSecurityLevelFromPatterns(changes []PatternChange) model.SecurityLevel {
	// Determine security level based on criticality of patterns
	maxCriticality := "low"

	for _, change := range changes {
		if change.NewPattern != nil {
			if change.NewPattern.Criticality == "critical" {
				maxCriticality = "critical"
			} else if change.NewPattern.Criticality == "high" && maxCriticality != "critical" {
				maxCriticality = "high"
			} else if change.NewPattern.Criticality == "medium" && maxCriticality != "critical" && maxCriticality != "high" {
				maxCriticality = "medium"
			}
		}
	}

	switch maxCriticality {
	case "critical":
		return model.SecurityLevel4
	case "high":
		return model.SecurityLevel3
	case "medium":
		return model.SecurityLevel2
	default:
		return model.SecurityLevel1
	}
}
