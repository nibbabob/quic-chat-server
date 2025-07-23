package monitoring

import (
	"encoding/json"
	"fmt"
	"quic-chat-server/security"
	"quic-chat-server/types"
	"runtime"
	"sync"
	"time"
)

var (
	systemMetrics       *SystemMetrics
	securityMetrics     *types.SecurityMetrics
	alertHistory        []types.SecurityAlert
	metricsHistory      []MetricsSnapshot
	mutex               sync.RWMutex
	monitoringStartTime = time.Now()
)

type SystemMetrics struct {
	// System resources
	MemoryUsage  MemoryStats  `json:"memory_usage"`
	CPUUsage     CPUStats     `json:"cpu_usage"`
	NetworkStats NetworkStats `json:"network_stats"`

	// Application metrics
	ServerUptime time.Duration `json:"server_uptime"`
	GoRoutines   int           `json:"go_routines"`
	GCStats      GCStats       `json:"gc_stats"`

	// Performance metrics
	RequestsPerSecond float64       `json:"requests_per_second"`
	AverageLatency    time.Duration `json:"average_latency"`
	ErrorRate         float64       `json:"error_rate"`

	// Security metrics
	SecurityLevel    string    `json:"security_level"`
	LastSecurityScan time.Time `json:"last_security_scan"`
	ThreatLevel      string    `json:"threat_level"`
}

type MemoryStats struct {
	Allocated  uint64 `json:"allocated_bytes"`
	TotalAlloc uint64 `json:"total_allocated_bytes"`
	System     uint64 `json:"system_bytes"`
	NumGC      uint32 `json:"gc_count"`
	HeapInUse  uint64 `json:"heap_in_use_bytes"`
	StackInUse uint64 `json:"stack_in_use_bytes"`
}

type CPUStats struct {
	UserTime     time.Duration `json:"user_time"`
	SystemTime   time.Duration `json:"system_time"`
	IdleTime     time.Duration `json:"idle_time"`
	UsagePercent float64       `json:"usage_percent"`
}

type NetworkStats struct {
	BytesSent       int64 `json:"bytes_sent"`
	BytesReceived   int64 `json:"bytes_received"`
	PacketsSent     int64 `json:"packets_sent"`
	PacketsReceived int64 `json:"packets_received"`
	ErrorCount      int64 `json:"error_count"`
}

type GCStats struct {
	PauseTotalNs uint64          `json:"pause_total_ns"`
	NumGC        uint32          `json:"num_gc"`
	LastGC       time.Time       `json:"last_gc"`
	NextGC       uint64          `json:"next_gc_bytes"`
	PauseHistory []time.Duration `json:"recent_pause_history"`
}

type MetricsSnapshot struct {
	Timestamp       time.Time             `json:"timestamp"`
	SystemMetrics   SystemMetrics         `json:"system_metrics"`
	SecurityMetrics types.SecurityMetrics `json:"security_metrics"`
	ConnectionCount int                   `json:"connection_count"`
	RoomCount       int                   `json:"room_count"`
	MessageRate     float64               `json:"message_rate"`
}

type MinimalStatus struct {
	Status            string    `json:"status"`
	Uptime            string    `json:"uptime"`
	ActiveConnections int       `json:"active_connections"`
	SecurityLevel     string    `json:"security_level"`
	LastUpdate        time.Time `json:"last_update"`
	Version           string    `json:"version"`
}

// Initialize monitoring subsystem
func InitializeMonitoring() {
	systemMetrics = &SystemMetrics{
		SecurityLevel: "maximum",
		ThreatLevel:   "low",
	}

	securityMetrics = &types.SecurityMetrics{
		TotalConnections:  0,
		ActiveConnections: 0,
	}

	alertHistory = make([]types.SecurityAlert, 0)
	metricsHistory = make([]MetricsSnapshot, 0)

	// Start background monitoring
	go startMetricsCollection()
	go startSecurityScanning()
	go startAlertProcessing()
}

// GetMinimalSystemStatus returns basic status with minimal information disclosure
func GetMinimalSystemStatus() []byte {
	mutex.RLock()
	defer mutex.RUnlock()

	status := MinimalStatus{
		Status:            "operational",
		Uptime:            time.Since(monitoringStartTime).Truncate(time.Second).String(),
		ActiveConnections: securityMetrics.ActiveConnections,
		SecurityLevel:     "maximum",
		LastUpdate:        time.Now(),
		Version:           "secure-messaging-v1",
	}

	// Return minimal information for OPSEC
	data, _ := json.Marshal(status)
	return data
}

// GetSecureMetrics returns detailed metrics for authorized access only
func GetSecureMetrics() []byte {
	mutex.RLock()
	defer mutex.RUnlock()

	// Update system metrics before returning
	updateSystemMetrics()

	snapshot := MetricsSnapshot{
		Timestamp:       time.Now(),
		SystemMetrics:   *systemMetrics,
		SecurityMetrics: *securityMetrics,
		ConnectionCount: securityMetrics.ActiveConnections,
		MessageRate:     calculateMessageRate(),
	}

	data, _ := json.Marshal(snapshot)
	return data
}

// RecordSecurityAlert adds a security alert to the monitoring system
func RecordSecurityAlert(alert types.SecurityAlert) {
	mutex.Lock()
	defer mutex.Unlock()

	alertHistory = append(alertHistory, alert)

	// Keep only last 1000 alerts
	if len(alertHistory) > 1000 {
		alertHistory = alertHistory[len(alertHistory)-1000:]
	}

	// Update threat level based on alert severity
	updateThreatLevel(alert)

	// Log critical alerts immediately
	if alert.IsCritical() {
		processCriticalAlert(alert)
	}
}

// UpdateSecurityMetrics updates the security metrics
func UpdateSecurityMetrics(metrics types.SecurityMetrics) {
	mutex.Lock()
	defer mutex.Unlock()

	securityMetrics = &metrics
}

// GetRecentAlerts returns recent security alerts
func GetRecentAlerts(since time.Time) []types.SecurityAlert {
	mutex.RLock()
	defer mutex.RUnlock()

	var recentAlerts []types.SecurityAlert
	for _, alert := range alertHistory {
		if alert.Timestamp.After(since) {
			recentAlerts = append(recentAlerts, alert)
		}
	}

	return recentAlerts
}

// GetMetricsHistory returns historical metrics
func GetMetricsHistory(hours int) []MetricsSnapshot {
	mutex.RLock()
	defer mutex.RUnlock()

	cutoff := time.Now().Add(time.Duration(-hours) * time.Hour)
	var history []MetricsSnapshot

	for _, snapshot := range metricsHistory {
		if snapshot.Timestamp.After(cutoff) {
			history = append(history, snapshot)
		}
	}

	return history
}

// Background monitoring functions

func startMetricsCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		mutex.Lock()
		updateSystemMetrics()

		// Take snapshot every 5 minutes
		if len(metricsHistory) == 0 || time.Since(metricsHistory[len(metricsHistory)-1].Timestamp) > 5*time.Minute {
			snapshot := MetricsSnapshot{
				Timestamp:       time.Now(),
				SystemMetrics:   *systemMetrics,
				SecurityMetrics: *securityMetrics,
				ConnectionCount: securityMetrics.ActiveConnections,
				MessageRate:     calculateMessageRate(),
			}

			metricsHistory = append(metricsHistory, snapshot)

			// Keep only last 24 hours of snapshots
			if len(metricsHistory) > 288 { // 24 hours * 12 snapshots per hour
				metricsHistory = metricsHistory[len(metricsHistory)-288:]
			}
		}
		mutex.Unlock()
	}
}

func startSecurityScanning() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		performSecurityScan()
	}
}

func startAlertProcessing() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		processAlerts()
	}
}

func updateSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	systemMetrics.MemoryUsage = MemoryStats{
		Allocated:  m.Alloc,
		TotalAlloc: m.TotalAlloc,
		System:     m.Sys,
		NumGC:      m.NumGC,
		HeapInUse:  m.HeapInuse,
		StackInUse: m.StackInuse,
	}

	systemMetrics.GoRoutines = runtime.NumGoroutine()
	systemMetrics.ServerUptime = time.Since(monitoringStartTime)

	// Update GC stats
	systemMetrics.GCStats = GCStats{
		PauseTotalNs: m.PauseTotalNs,
		NumGC:        m.NumGC,
		NextGC:       m.NextGC,
	}

	if m.NumGC > 0 {
		systemMetrics.GCStats.LastGC = time.Unix(0, int64(m.LastGC))

		// Get recent pause history (last 10 GC cycles)
		pauseHistory := make([]time.Duration, 0, 10)
		for i := int(m.NumGC) - 1; i >= 0 && i >= int(m.NumGC)-10; i-- {
			pauseHistory = append(pauseHistory, time.Duration(m.PauseNs[i%256]))
		}
		systemMetrics.GCStats.PauseHistory = pauseHistory
	}
}

func calculateMessageRate() float64 {
	if len(metricsHistory) < 2 {
		return 0.0
	}

	recent := metricsHistory[len(metricsHistory)-1]
	previous := metricsHistory[len(metricsHistory)-2]

	timeDiff := recent.Timestamp.Sub(previous.Timestamp).Seconds()
	if timeDiff == 0 {
		return 0.0
	}

	messageDiff := recent.SecurityMetrics.TotalMessages - previous.SecurityMetrics.TotalMessages
	return float64(messageDiff) / timeDiff
}

func updateThreatLevel(_ types.SecurityAlert) {
	// Simple threat level calculation based on recent alerts
	recentCritical := 0
	recentHigh := 0
	cutoff := time.Now().Add(-1 * time.Hour)

	for _, a := range alertHistory {
		if a.Timestamp.After(cutoff) {
			switch a.Severity {
			case types.SeverityCritical:
				recentCritical++
			case types.SeverityHigh:
				recentHigh++
			}
		}
	}

	if recentCritical > 0 {
		systemMetrics.ThreatLevel = "critical"
	} else if recentHigh > 3 {
		systemMetrics.ThreatLevel = "high"
	} else if recentHigh > 1 {
		systemMetrics.ThreatLevel = "medium"
	} else {
		systemMetrics.ThreatLevel = "low"
	}
}

func performSecurityScan() {
	mutex.Lock()
	systemMetrics.LastSecurityScan = time.Now()
	mutex.Unlock()

	// Perform various security checks
	checkMemoryUsage()
	checkConnectionLimits()
	checkErrorRates()
	checkAnomalousActivity()
}

func checkMemoryUsage() {
	memUsageMB := float64(systemMetrics.MemoryUsage.Allocated) / 1024 / 1024

	if memUsageMB > 500 { // Alert if using more than 500MB
		alert := types.NewSecurityAlert(
			"memory_usage",
			types.SeverityMedium,
			"system",
			fmt.Sprintf("High memory usage: %.2f MB", memUsageMB),
			map[string]interface{}{
				"memory_mb": memUsageMB,
				"threshold": 500,
			},
		)
		RecordSecurityAlert(alert)
	}
}

func checkConnectionLimits() {
	if securityMetrics.ActiveConnections > 80 { // 80% of max connections
		alert := types.NewSecurityAlert(
			"connection_limit",
			types.SeverityHigh,
			"system",
			fmt.Sprintf("Approaching connection limit: %d active", securityMetrics.ActiveConnections),
			map[string]interface{}{
				"active_connections": securityMetrics.ActiveConnections,
				"threshold":          80,
			},
		)
		RecordSecurityAlert(alert)
	}
}

func checkErrorRates() {
	if len(metricsHistory) < 2 {
		return
	}

	recent := metricsHistory[len(metricsHistory)-1]
	previous := metricsHistory[len(metricsHistory)-2]

	errorDiff := float64(recent.SecurityMetrics.ConnectionErrors - previous.SecurityMetrics.ConnectionErrors)
	timeDiff := recent.Timestamp.Sub(previous.Timestamp).Minutes()

	if timeDiff > 0 && errorDiff/timeDiff > 5 { // More than 5 errors per minute
		alert := types.NewSecurityAlert(
			"high_error_rate",
			types.SeverityHigh,
			"system",
			fmt.Sprintf("High error rate: %.2f errors/min", errorDiff/timeDiff),
			map[string]interface{}{
				"error_rate": errorDiff / timeDiff,
				"threshold":  5.0,
			},
		)
		RecordSecurityAlert(alert)
	}
}

func checkAnomalousActivity() {
	// Check for unusual patterns in connection behavior
	if securityMetrics.RejectedConnections > securityMetrics.TotalConnections/2 {
		alert := types.NewSecurityAlert(
			"anomalous_activity",
			types.SeverityCritical,
			"system",
			"High rejection rate indicates potential attack",
			map[string]interface{}{
				"rejected_connections": securityMetrics.RejectedConnections,
				"total_connections":    securityMetrics.TotalConnections,
				"rejection_rate":       float64(securityMetrics.RejectedConnections) / float64(securityMetrics.TotalConnections),
			},
		)
		RecordSecurityAlert(alert)
	}
}

func processCriticalAlert(alert types.SecurityAlert) {
	// Log critical alert immediately
	logger := security.NewSecureLogger()
	logger.Error("🚨 CRITICAL SECURITY ALERT", map[string]interface{}{
		"alert_id":    alert.ID,
		"alert_type":  alert.AlertType,
		"description": alert.Description,
		"source":      alert.Source,
		"metadata":    alert.Metadata,
	})

	// Could implement additional alerting mechanisms here:
	// - Send to webhook
	// - Write to secure log
	// - Trigger automated responses
}

func processAlerts() {
	mutex.RLock()
	unresolved := make([]types.SecurityAlert, 0)
	for _, alert := range alertHistory {
		if !alert.Resolved && time.Since(alert.Timestamp) < 24*time.Hour {
			unresolved = append(unresolved, alert)
		}
	}
	mutex.RUnlock()

	// Auto-resolve old low-severity alerts
	for i := range unresolved {
		if unresolved[i].Severity == types.SeverityLow && time.Since(unresolved[i].Timestamp) > 2*time.Hour {
			resolveAlert(unresolved[i].ID)
		}
	}
}

func resolveAlert(alertID string) {
	mutex.Lock()
	defer mutex.Unlock()

	for i := range alertHistory {
		if alertHistory[i].ID == alertID {
			now := time.Now()
			alertHistory[i].Resolved = true
			alertHistory[i].ResolvedAt = &now
			break
		}
	}
}

// Export functions for external monitoring tools

func ExportPrometheusMetrics() string {
	mutex.RLock()
	defer mutex.RUnlock()

	// Generate Prometheus-format metrics
	metrics := fmt.Sprintf(`# HELP secure_messaging_connections_active Active connections
# TYPE secure_messaging_connections_active gauge
secure_messaging_connections_active %d

# HELP secure_messaging_memory_bytes Memory usage in bytes
# TYPE secure_messaging_memory_bytes gauge
secure_messaging_memory_bytes %d

# HELP secure_messaging_messages_total Total messages processed
# TYPE secure_messaging_messages_total counter
secure_messaging_messages_total %d

# HELP secure_messaging_errors_total Total errors
# TYPE secure_messaging_errors_total counter
secure_messaging_errors_total %d

# HELP secure_messaging_uptime_seconds Server uptime in seconds
# TYPE secure_messaging_uptime_seconds counter
secure_messaging_uptime_seconds %f
`,
		securityMetrics.ActiveConnections,
		systemMetrics.MemoryUsage.Allocated,
		securityMetrics.TotalMessages,
		securityMetrics.ConnectionErrors,
		time.Since(monitoringStartTime).Seconds(),
	)

	return metrics
}

func GetHealthStatus() map[string]interface{} {
	mutex.RLock()
	defer mutex.RUnlock()

	var status string
	switch systemMetrics.ThreatLevel {
	case "critical":
		status = "critical"
	case "high":
		status = "degraded"
	default:
		status = "healthy"
	}

	return map[string]interface{}{
		"status":             status,
		"uptime_seconds":     time.Since(monitoringStartTime).Seconds(),
		"active_connections": securityMetrics.ActiveConnections,
		"memory_usage_mb":    float64(systemMetrics.MemoryUsage.Allocated) / 1024 / 1024,
		"threat_level":       systemMetrics.ThreatLevel,
		"last_security_scan": systemMetrics.LastSecurityScan.Format(time.RFC3339),
		"go_routines":        systemMetrics.GoRoutines,
		"gc_count":           systemMetrics.MemoryUsage.NumGC,
	}
}
