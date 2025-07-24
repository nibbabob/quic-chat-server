package monitoring

import (
	"encoding/json"
	"quic-chat-server/types"
	"strings"
	"testing"
	"time"
)

// setupMonitoringTest initializes the monitoring subsystem for testing.
func setupMonitoringTest() func() {
	InitializeMonitoring()

	cleanup := func() {
		// Reset global state after the test
		systemMetrics = nil
		securityMetrics = nil
		alertHistory = nil
		metricsHistory = nil
		monitoringStartTime = time.Now()
	}

	return cleanup
}

// hasAlert checks if an alert of a specific type exists in the alert history.
func hasAlert(alertType string) bool {
	for _, a := range alertHistory {
		if a.AlertType == alertType {
			return true
		}
	}
	return false
}

// TestInitializeMonitoring checks if the monitoring subsystem initializes correctly.
func TestInitializeMonitoring(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	if systemMetrics == nil {
		t.Fatal("InitializeMonitoring() did not initialize systemMetrics")
	}
	if securityMetrics == nil {
		t.Fatal("InitializeMonitoring() did not initialize securityMetrics")
	}
}

// TestGetMinimalSystemStatus tests the minimal status endpoint.
func TestGetMinimalSystemStatus(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	statusBytes := GetMinimalSystemStatus()
	var status MinimalStatus
	if err := json.Unmarshal(statusBytes, &status); err != nil {
		t.Fatalf("Failed to unmarshal minimal system status: %v", err)
	}

	if status.Status != "operational" {
		t.Errorf("Status = %s; want operational", status.Status)
	}
}

// TestGetSecureMetrics tests the secure metrics endpoint.
func TestGetSecureMetrics(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	metricsBytes := GetSecureMetrics()
	var metrics MetricsSnapshot
	if err := json.Unmarshal(metricsBytes, &metrics); err != nil {
		t.Fatalf("Failed to unmarshal secure metrics: %v", err)
	}

	if metrics.SystemMetrics.GoRoutines == 0 {
		t.Error("GoRoutines count should be greater than 0")
	}
}

// TestAlertsAndThreatLevels covers all alert recording and threat level scenarios.
func TestAlertsAndThreatLevels(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	t.Run("Initial State", func(t *testing.T) {
		if systemMetrics.ThreatLevel != "low" {
			t.Errorf("Initial ThreatLevel = %s; want low", systemMetrics.ThreatLevel)
		}
	})

	t.Run("Threat Escalation", func(t *testing.T) {
		// Escalate to Medium
		RecordSecurityAlert(types.NewSecurityAlert("test_high_1", types.SeverityHigh, "test", "d", nil))
		RecordSecurityAlert(types.NewSecurityAlert("test_high_2", types.SeverityHigh, "test", "d", nil))
		updateThreatLevel(types.SecurityAlert{}) // Manually trigger update
		if systemMetrics.ThreatLevel != "medium" {
			t.Errorf("ThreatLevel after 2 high alerts = %s; want medium", systemMetrics.ThreatLevel)
		}

		// Escalate to High
		RecordSecurityAlert(types.NewSecurityAlert("test_high_3", types.SeverityHigh, "test", "d", nil))
		RecordSecurityAlert(types.NewSecurityAlert("test_high_4", types.SeverityHigh, "test", "d", nil))
		updateThreatLevel(types.SecurityAlert{}) // Manually trigger update
		if systemMetrics.ThreatLevel != "high" {
			t.Errorf("ThreatLevel after 4 high alerts = %s; want high", systemMetrics.ThreatLevel)
		}

		// Escalate to Critical
		RecordSecurityAlert(types.NewSecurityAlert("test_critical", types.SeverityCritical, "test", "d", nil))
		updateThreatLevel(types.SecurityAlert{}) // Manually trigger update
		if systemMetrics.ThreatLevel != "critical" {
			t.Errorf("ThreatLevel after critical alert = %s; want critical", systemMetrics.ThreatLevel)
		}
	})
}

// TestSecurityScanning checks the logic of the security scanner.
func TestSecurityScanning(t *testing.T) {
	t.Run("High Memory Usage", func(t *testing.T) {
		cleanup := setupMonitoringTest()
		defer cleanup()
		systemMetrics.MemoryUsage.Allocated = 600 * 1024 * 1024 // 600 MB
		performSecurityScan()
		if !hasAlert("memory_usage") {
			t.Error("High memory usage did not trigger an alert")
		}
	})

	t.Run("Connection Limit", func(t *testing.T) {
		cleanup := setupMonitoringTest()
		defer cleanup()
		securityMetrics.ActiveConnections = 90
		performSecurityScan()
		if !hasAlert("connection_limit") {
			t.Error("Approaching connection limit did not trigger an alert")
		}
	})

	t.Run("Anomalous Activity", func(t *testing.T) {
		cleanup := setupMonitoringTest()
		defer cleanup()
		securityMetrics.TotalConnections = 100
		securityMetrics.RejectedConnections = 60
		performSecurityScan()
		if !hasAlert("anomalous_activity") {
			t.Error("Anomalous activity did not trigger an alert")
		}
	})
}

// TestMetricsHistoryAndRates tests history and rate calculation.
func TestMetricsHistoryAndRates(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	// 1. Add some mock history
	metricsHistory = append(metricsHistory, MetricsSnapshot{
		Timestamp:       time.Now().Add(-10 * time.Second),
		SecurityMetrics: types.SecurityMetrics{TotalMessages: 100, ConnectionErrors: 5},
	})
	metricsHistory = append(metricsHistory, MetricsSnapshot{
		Timestamp:       time.Now(),
		SecurityMetrics: types.SecurityMetrics{TotalMessages: 150, ConnectionErrors: 15},
	})

	t.Run("GetMetricsHistory", func(t *testing.T) {
		history := GetMetricsHistory(1) // Get last hour of history
		if len(history) != 2 {
			t.Errorf("GetMetricsHistory() returned %d snapshots; want 2", len(history))
		}
	})

	t.Run("CalculateMessageRate", func(t *testing.T) {
		rate := calculateMessageRate()
		if rate < 4.9 || rate > 5.1 { // Should be approx 50 msgs / 10s = 5 msg/s
			t.Errorf("calculateMessageRate() = %f; want ~5.0", rate)
		}
	})

	t.Run("High Error Rate Alert", func(t *testing.T) {
		// Reset history for a clean test
		metricsHistory = []MetricsSnapshot{
			{
				Timestamp:       time.Now().Add(-2 * time.Minute),
				SecurityMetrics: types.SecurityMetrics{ConnectionErrors: 0},
			},
			{
				Timestamp:       time.Now(),
				SecurityMetrics: types.SecurityMetrics{ConnectionErrors: 11},
			},
		}
		checkErrorRates() // Should trigger (11 errors / 2 min > 5 err/min)
		if !hasAlert("high_error_rate") {
			t.Error("High error rate was not detected")
		}
	})
}

// TestHealthAndPrometheusEndpoints tests the exported data functions.
func TestHealthAndPrometheusEndpoints(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	t.Run("GetHealthStatus", func(t *testing.T) {
		health := GetHealthStatus()
		if health["status"] != "healthy" {
			t.Errorf("Initial health status = %s; want healthy", health["status"])
		}
		systemMetrics.ThreatLevel = "critical"
		health = GetHealthStatus()
		if health["status"] != "critical" {
			t.Errorf("Health status with critical threat = %s; want critical", health["status"])
		}
	})

	t.Run("ExportPrometheusMetrics", func(t *testing.T) {
		promMetrics := ExportPrometheusMetrics()
		if !strings.Contains(promMetrics, "secure_messaging_connections_active") {
			t.Error("ExportPrometheusMetrics() is missing expected metrics")
		}
	})
}

// TestAlertProcessing covers alert resolution logic.
func TestAlertProcessing(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()
	// Add a low-severity alert that is old enough to be auto-resolved
	alertHistory = append(alertHistory, types.NewSecurityAlert("old_low", types.SeverityLow, "test", "d", nil))
	alertHistory[0].Timestamp = time.Now().Add(-3 * time.Hour)

	processAlerts()

	if !alertHistory[0].Resolved {
		t.Error("processAlerts() did not auto-resolve the old, low-severity alert")
	}
}

func TestRecordSecurityAlert(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	// 1. Test recording a critical alert
	criticalAlert := types.NewSecurityAlert("test_critical", types.SeverityCritical, "test_source", "critical event", nil)
	RecordSecurityAlert(criticalAlert)

	if len(alertHistory) != 1 {
		t.Fatal("Critical alert was not recorded")
	}
	if systemMetrics.ThreatLevel != "critical" {
		t.Error("ThreatLevel was not updated to critical")
	}

	// 2. Test recording a high-severity alert
	highAlert := types.NewSecurityAlert("test_high", types.SeverityHigh, "test_source", "high-severity event", nil)
	RecordSecurityAlert(highAlert)

	if len(alertHistory) != 2 {
		t.Fatal("High-severity alert was not recorded")
	}
}

func TestUpdateSecurityMetrics(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	newMetrics := types.SecurityMetrics{
		TotalConnections:  10,
		ActiveConnections: 5,
	}
	UpdateSecurityMetrics(newMetrics)

	if securityMetrics.TotalConnections != 10 {
		t.Errorf("TotalConnections = %d; want 10", securityMetrics.TotalConnections)
	}
	if securityMetrics.ActiveConnections != 5 {
		t.Errorf("ActiveConnections = %d; want 5", securityMetrics.ActiveConnections)
	}
}

// TestGetRecentAlerts tests the retrieval of recent alerts.
func TestGetRecentAlerts(t *testing.T) {
	cleanup := setupMonitoringTest()
	defer cleanup()

	// Record an old and a new alert
	alertHistory = append(alertHistory, types.SecurityAlert{Timestamp: time.Now().Add(-2 * time.Hour)})
	alertHistory = append(alertHistory, types.SecurityAlert{Timestamp: time.Now()})

	recentAlerts := GetRecentAlerts(time.Now().Add(-1 * time.Hour))
	if len(recentAlerts) != 1 {
		t.Errorf("GetRecentAlerts() returned %d alerts; want 1", len(recentAlerts))
	}
}
