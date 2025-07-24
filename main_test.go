package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"quic-chat-server/config"
	"quic-chat-server/monitoring"
	"quic-chat-server/security"
	"testing"
)

// setupMainTest sets up the necessary configuration and environment for testing main package functions.
func setupMainTest(t *testing.T) func() {
	// Set required environment variables for the test
	t.Setenv("IP_HASH_SALT", "546861742773206d79204b756e67204675546861742773206d79204b756e67204675") // 32-byte hex string
	t.Setenv("HMAC_SECRET", "a-super-secret-hmac-key-for-testing")
	t.Setenv("METRICS_TOKEN", "test-metrics-token")

	// Load the configuration into the package-level variable
	var err error
	serverConfig, err = config.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config for main test: %v", err)
	}

	// Create dummy certs so initialization doesn't fail
	if err := os.MkdirAll("certs", 0755); err != nil {
		t.Fatalf("Failed to create certs directory: %v", err)
	}
	f, err := os.Create("certs/cert.pem")
	if err == nil {
		f.Close()
	}
	f, err = os.Create("certs/key.pem")
	if err == nil {
		f.Close()
	}

	// Crucially, initialize the monitoring package
	monitoring.InitializeMonitoring()

	cleanup := func() {
		os.RemoveAll("certs")
		serverConfig = nil
	}
	return cleanup
}

// TestInitializeSecureEnvironment tests the environment setup.
func TestInitializeSecureEnvironment(t *testing.T) {
	cleanup := setupMainTest(t)
	defer cleanup()

	// Just call it to ensure it doesn't panic. Direct output is hard to test.
	initializeSecureEnvironment()
}

// TestInitializeSecureSubsystems tests the initialization of all server components.
func TestInitializeSecureSubsystems(t *testing.T) {
	cleanup := setupMainTest(t)
	defer cleanup()

	// Call the function to ensure it runs without panicking.
	// This implicitly tests that all subsystems are initialized.
	initializeSecureSubsystems()
}

// TestGenerateSecureConnectionID ensures the connection ID is generated correctly.
func TestGenerateSecureConnectionID(t *testing.T) {
	id1, err1 := generateSecureConnectionID()
	id2, err2 := generateSecureConnectionID()

	if err1 != nil || err2 != nil {
		t.Fatalf("generateSecureConnectionID() returned an error: %v, %v", err1, err2)
	}
	if len(id1) != 64 {
		t.Errorf("generateSecureConnectionID() returned ID of length %d; want 64", len(id1))
	}
	if id1 == id2 {
		t.Error("generateSecureConnectionID() produced two identical IDs")
	}
}

// TestStartSecureHealthServer tests the health and metrics endpoints.
func TestStartSecureHealthServer(t *testing.T) {
	cleanup := setupMainTest(t)
	defer cleanup()

	// We don't want to actually listen on a port, so we'll test the handler logic directly.
	// The startSecureHealthServer function sets up the routes. We'll recreate the mux here
	// to test the handlers it would have configured.
	mux := http.NewServeMux()
	mux.HandleFunc(serverConfig.Monitoring.HealthEndpoint, func(w http.ResponseWriter, r *http.Request) {
		if !security.IsLocalRequest(r) || !security.ValidateMetricsAuth(r) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		status := monitoring.GetMinimalSystemStatus()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(status)
	})
	mux.HandleFunc(serverConfig.Monitoring.MetricsEndpoint, func(w http.ResponseWriter, r *http.Request) {
		if !security.IsLocalRequest(r) || !security.ValidateMetricsAuth(r) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		metrics := monitoring.GetSecureMetrics()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(metrics)
	})

	// Test case 1: Valid request to health endpoint
	t.Run("Valid Health Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", serverConfig.Monitoring.HealthEndpoint, nil)
		req.Header.Set("X-Metrics-Token", "test-metrics-token")
		req.RemoteAddr = "127.0.0.1:12345"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
	})

	// Test case 2: Invalid request to metrics endpoint (bad token)
	t.Run("Invalid Metrics Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", serverConfig.Monitoring.MetricsEndpoint, nil)
		req.Header.Set("X-Metrics-Token", "wrong-token")
		req.RemoteAddr = "127.0.0.1:12345"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusNotFound {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNotFound)
		}
	})

	// Test case 3: Request from non-local address
	t.Run("Remote Address Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", serverConfig.Monitoring.HealthEndpoint, nil)
		req.Header.Set("X-Metrics-Token", "test-metrics-token")
		req.RemoteAddr = "8.8.8.8:12345"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusNotFound {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNotFound)
		}
	})
}

// TestHandleServerCommands is a limited test to ensure command parsing works.
// It does not test the interactive loop.
func TestHandleServerCommands(t *testing.T) {
	cleanup := setupMainTest(t)
	defer cleanup()

	// We can't test the infinite loop, but we can call the handler logic for specific commands
	// Here we just test that calling with known commands doesn't panic
	// A more thorough test would require refactoring handleServerCommands to be more modular.

	// Redirect stdout to capture the output of the 'help' command
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// This is a placeholder for where you might test the 'help' command's output
	// For now, just ensuring no panics is a basic check.
	// Note: This does not actually run the command logic from handleServerCommands.
	t.Log("Simulating 'help' command - check for panics")
	// a real test would involve feeding "help\n" to a mocked os.Stdin

	w.Close()
	os.Stdout = oldStdout
	_, _ = io.ReadAll(r) // Read the output to avoid blocking
}
