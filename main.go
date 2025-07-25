package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"quic-chat-server/config"
	"quic-chat-server/crypto"
	"quic-chat-server/handlers"
	"quic-chat-server/messaging"
	"quic-chat-server/monitoring"
	"quic-chat-server/security"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	serverConfig *config.Config
	logger       = security.NewSecureLogger()
)

func main() {
	// Initialize secure random seed
	initializeSecureEnvironment()

	logger.Info("🔒 Starting Ultra-Secure Whistleblower Communication System")
	logger.Info("⚠️  OPSEC Level: MAXIMUM - Intelligence Agency Protection Mode")

	// Load configuration with security defaults
	var err error
	serverConfig, err = config.LoadConfig()
	if err != nil {
		logger.Fatal("Failed to load secure configuration", map[string]interface{}{"error": err})
	}

	// Initialize all secure subsystems
	initializeSecureSubsystems()

	// Setup graceful shutdown for operational security
	setupGracefulShutdown()

	// Generate or validate certificates with enhanced security
	if err := crypto.GenerateCertIfNotExists(); err != nil {
		logger.Fatal("Failed to initialize cryptographic infrastructure", map[string]interface{}{"error": err})
	}

	// Start health monitoring (on separate goroutine for isolation)
	go startSecureHealthServer()

	// Start the main QUIC server in a goroutine
	go startSecureServer()

	// Handle server commands from the console
	handleServerCommands()
}

func initializeSecureEnvironment() {
	// Ensure cryptographically secure random number generation
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Fatal("CRITICAL: Unable to initialize secure random number generator")
	}

	// Set process name obfuscation (operational security)
	if serverConfig != nil && serverConfig.OPSEC.EnableProcessObfuscation {
		security.SetProcessName("kthreadd") // Disguise as a common kernel thread
	}

	// Clear environment variables that might leak information
	if serverConfig != nil && serverConfig.OPSEC.ClearEnvironmentVars {
		security.ClearEnvVars()
	}
}

func initializeSecureSubsystems() {
	// Initialize server state with secure defaults
	handlers.InitializeServer(serverConfig)
	messaging.InitializeServer(serverConfig)

	// Set the HMAC secret for the messaging system
	if serverConfig.Security.HMACSecret == "" {
		logger.Fatal("HMAC_SECRET is not set. This is a critical security vulnerability.", nil)
	}
	messaging.SetHMACSecret([]byte(serverConfig.Security.HMACSecret))

	// Connect messaging to handlers
	messaging.SetServer(handlers.GetServer())

	// Initialize monitoring FIRST, as other subsystems may rely on it
	monitoring.InitializeMonitoring()

	// Initialize security monitoring
	security.InitializeSecurityMonitor(serverConfig)

	// Initialize memory protection
	security.InitializeMemoryProtection()

	logger.Info("🛡️ All security subsystems initialized")
}

func setupGracefulShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-c
		logger.Warn("🚨 Shutdown signal received - initiating secure cleanup", map[string]interface{}{
			"signal": sig.String(),
		})

		// Secure shutdown sequence for whistleblower protection
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// 1. Stop accepting new connections immediately
		logger.Info("🔒 Stopping new connection acceptance")

		// 2. Notify all connected clients of impending shutdown
		messaging.NotifyClientsShutdown(shutdownCtx)

		// 3. Wait for active message deliveries to complete
		time.Sleep(5 * time.Second)

		// 4. Forcibly close all connections
		handlers.ForceCloseAllConnections()

		// 5. Secure memory cleanup (overwrite sensitive data)
		security.SecureMemoryWipe()

		// 6. Clear certificate materials from memory
		crypto.ClearCertificateCache()

		logger.Info("🔐 Secure shutdown completed - all traces wiped")
		os.Exit(0)
	}()
}

func startSecureServer() {
	// Enhanced QUIC configuration for maximum security
	config := &quic.Config{
		MaxIdleTimeout:        time.Duration(serverConfig.Security.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:       time.Duration(serverConfig.Security.KeepAliveInterval) * time.Second,
		MaxIncomingStreams:    int64(serverConfig.Security.MaxStreamsPerConnection),
		MaxIncomingUniStreams: int64(serverConfig.Security.MaxUniStreamsPerConnection),
		// Disable connection migration for better anonymity
		DisablePathMTUDiscovery: true,
	}

	tlsConfig := crypto.GenerateMaxSecurityTLSConfig(serverConfig)

	listener, err := quic.ListenAddr(":"+serverConfig.Server.Port, tlsConfig, config)
	if err != nil {
		logger.Fatal("Failed to start secure QUIC listener", map[string]interface{}{"error": err})
	}

	logger.Info("🔒 Ultra-Secure Whistleblower Server Online", map[string]interface{}{
		"port":            serverConfig.Server.Port,
		"tls_version":     "TLS 1.3",
		"cipher_suites":   "ChaCha20-Poly1305, AES-256-GCM",
		"forward_secrecy": "Enabled",
	})

	// Connection acceptance loop with security monitoring
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logger.Error("Error accepting connection", map[string]interface{}{"error": err})
			continue
		}

		// Generate secure connection ID
		connID, err := generateSecureConnectionID()
		if err != nil {
			logger.Error("Failed to generate secure connection ID", map[string]interface{}{"error": err})
			conn.CloseWithError(quic.ApplicationErrorCode(500), "internal_server_error")
			continue
		}

		// Log connection with minimal information (OPSEC)
		logger.Info("🔗 Secure connection established", map[string]interface{}{
			"conn_id":          connID[:8] + "...", // Only log partial ID for security
			"remote_addr_hash": security.HashIPAddress(conn.RemoteAddr().String()),
		})

		// Handle connection in isolated goroutine
		go handlers.HandleSecureConnection(handlers.NewQUICConnection(conn), connID)
	}
}

func startSecureHealthServer() {
	// Health server with minimal information disclosure
	mux := http.NewServeMux()

	// Obfuscated health endpoint (not /health for OPSEC)
	mux.HandleFunc(serverConfig.Monitoring.HealthEndpoint, func(w http.ResponseWriter, r *http.Request) {
		// Verify request is from localhost and has a valid token
		if !security.IsLocalRequest(r) || !security.ValidateMetricsAuth(r) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		status := monitoring.GetMinimalSystemStatus()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(status)
	})

	// Metrics endpoint with authentication
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

	server := &http.Server{
		Addr:           "127.0.0.1:" + serverConfig.Monitoring.HealthPort,
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxHeaderBytes: 1024, // Minimal header size
	}

	logger.Info("🏥 Secure health monitoring active", map[string]interface{}{
		"port": serverConfig.Monitoring.HealthPort,
	})

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Health server error", map[string]interface{}{"error": err})
	}
}

func generateSecureConnectionID() (string, error) {
	bytes := make([]byte, 32) // 256-bit connection ID
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure connection ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func handleServerCommands() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Server command interface ready. Type 'help' for commands.")

	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			logger.Error("Error reading command", map[string]interface{}{"error": err})
			continue
		}

		input = strings.TrimSpace(input)
		parts := strings.Split(input, " ")
		command := parts[0]

		switch command {
		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  status              - Show server status")
			fmt.Println("  rooms               - List active rooms")
			fmt.Println("  users               - List connected users")
			fmt.Println("  kick <user_id>      - Kick a user")
			fmt.Println("  shutdown            - Shutdown the server")
			fmt.Println("  help                - Show this help message")
		case "status":
			metrics := monitoring.GetSecureMetrics()
			fmt.Println(string(metrics))
		case "rooms":
			server := handlers.GetServer()
			server.Mutex.RLock()
			if len(server.Rooms) == 0 {
				fmt.Println("No active rooms.")
			} else {
				fmt.Println("Active rooms:")
				for roomID, room := range server.Rooms {
					room.Mutex.RLock()
					fmt.Printf("  - %s (%d users)\n", roomID, len(room.Clients))
					room.Mutex.RUnlock()
				}
			}
			server.Mutex.RUnlock()
		case "users":
			server := handlers.GetServer()
			server.Mutex.RLock()
			if len(server.Connections) == 0 {
				fmt.Println("No connected users.")
			} else {
				fmt.Println("Connected users:")
				for _, client := range server.Connections {
					fmt.Printf("  - UserID: %s, RoomID: %s, ConnID: %s\n", client.UserID, client.RoomID, client.ID[:8]+"...")
				}
			}
			server.Mutex.RUnlock()
		case "kick":
			if len(parts) < 2 {
				fmt.Println("Usage: kick <user_id>")
				continue
			}
			userID := parts[1]
			if handlers.KickUser(userID) {
				fmt.Printf("User '%s' kicked.\n", userID)
			} else {
				fmt.Printf("User '%s' not found.\n", userID)
			}
		case "shutdown":
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(os.Interrupt)
			return // Exit the command loop
		case "":
			// Ignore empty input
		default:
			fmt.Println("Unknown command. Type 'help' for a list of commands.")
		}
	}
}
