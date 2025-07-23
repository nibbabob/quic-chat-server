package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Server     ServerConfig     `json:"server"`
	Security   SecurityConfig   `json:"security"`
	Crypto     CryptoConfig     `json:"crypto"`
	Monitoring MonitoringConfig `json:"monitoring"`
	OPSEC      OPSECConfig      `json:"opsec"`
}

type ServerConfig struct {
	Port              string `json:"port"`
	MaxConnections    int    `json:"max_connections"`
	MaxRoomsPerServer int    `json:"max_rooms_per_server"`
	MaxUsersPerRoom   int    `json:"max_users_per_room"`
	ConnectionTimeout int    `json:"connection_timeout_seconds"`
}

type SecurityConfig struct {
	MaxIdleTimeout              int    `json:"max_idle_timeout_seconds"`
	KeepAliveInterval           int    `json:"keep_alive_interval_seconds"`
	MaxStreamsPerConnection     int    `json:"max_streams_per_connection"`
	MaxUniStreamsPerConnection  int    `json:"max_uni_streams_per_connection"`
	RateLimitMessagesPerMinute  int    `json:"rate_limit_messages_per_minute"`
	RateLimitBytesPerMinute     int64  `json:"rate_limit_bytes_per_minute"`
	MaxMessageSize              int    `json:"max_message_size_bytes"`
	RequireClientAuth           bool   `json:"require_client_authentication"`
	EnablePerfectForwardSecrecy bool   `json:"enable_perfect_forward_secrecy"`
	AntiReplayWindowSize        int    `json:"anti_replay_window_size"`
	MaxFailedAuthAttempts       int    `json:"max_failed_auth_attempts"`
	AuthBanDurationMinutes      int    `json:"auth_ban_duration_minutes"`
	HMACSecret                  string `json:"hmac_secret"`
}

type CryptoConfig struct {
	CertificatePath          string   `json:"certificate_path"`
	PrivateKeyPath           string   `json:"private_key_path"`
	KeyRotationIntervalHours int      `json:"key_rotation_interval_hours"`
	AllowedCipherSuites      []string `json:"allowed_cipher_suites"`
	MinTLSVersion            string   `json:"min_tls_version"`
	CertificateValidityDays  int      `json:"certificate_validity_days"`
	KeyStrength              int      `json:"rsa_key_strength_bits"`
	UseECDSA                 bool     `json:"use_ecdsa_instead_of_rsa"`
	ECDSACurve               string   `json:"ecdsa_curve"`
}

type MonitoringConfig struct {
	HealthPort              string `json:"health_port"`
	EnableMetrics           bool   `json:"enable_metrics"`
	MetricsRetentionHours   int    `json:"metrics_retention_hours"`
	LogLevel                string `json:"log_level"`
	EnableSecurityAuditing  bool   `json:"enable_security_auditing"`
	AuditLogPath            string `json:"audit_log_path"`
	MaxLogFileSizeMB        int    `json:"max_log_file_size_mb"`
	LogRotationIntervalDays int    `json:"log_rotation_interval_days"`
	HealthEndpoint          string `json:"health_endpoint"`
	MetricsEndpoint         string `json:"metrics_endpoint"`
}

type OPSECConfig struct {
	EnableProcessObfuscation bool     `json:"enable_process_obfuscation"`
	ClearEnvironmentVars     bool     `json:"clear_environment_variables"`
	EnableMemoryProtection   bool     `json:"enable_memory_protection"`
	SecureDeleteTempFiles    bool     `json:"secure_delete_temp_files"`
	DisableCoreDumps         bool     `json:"disable_core_dumps"`
	EnableCanaryTokens       bool     `json:"enable_canary_tokens"`
	AllowedClientCountries   []string `json:"allowed_client_countries"`
	BlockedClientCountries   []string `json:"blocked_client_countries"`
	EnableGeoBlocking        bool     `json:"enable_geo_blocking"`
	MaxDailyConnections      int      `json:"max_daily_connections_per_ip"`
}

// LoadConfig loads configuration with secure defaults for whistleblower protection
func LoadConfig() (*Config, error) {
	config := getSecureDefaults()

	// Try to load from config file if it exists
	if configFile := os.Getenv("SECURE_CONFIG_PATH"); configFile != "" {
		if data, err := os.ReadFile(configFile); err == nil {
			if err := json.Unmarshal(data, config); err != nil {
				return nil, err
			}
		}
	}

	// Override with environment variables for operational security
	overrideWithEnvironment(config)

	return config, nil
}

// getSecureDefaults returns maximum security configuration for whistleblower protection
func getSecureDefaults() *Config {
	return &Config{
		Server: ServerConfig{
			Port:              "4433",
			MaxConnections:    100, // Limit to reduce server fingerprinting
			MaxRoomsPerServer: 50,  // Reasonable limit for small operation
			MaxUsersPerRoom:   10,  // Small groups for better anonymity
			ConnectionTimeout: 300, // 5 minutes
		},
		Security: SecurityConfig{
			MaxIdleTimeout:              180,         // 3 minutes - reduce exposure time
			KeepAliveInterval:           30,          // 30 seconds
			MaxStreamsPerConnection:     5,           // Limit stream usage
			MaxUniStreamsPerConnection:  2,           // Minimal unidirectional streams
			RateLimitMessagesPerMinute:  30,          // Conservative rate limiting
			RateLimitBytesPerMinute:     1024 * 1024, // 1MB per minute
			MaxMessageSize:              32768,       // 32KB max message
			RequireClientAuth:           true,        // Always require authentication
			EnablePerfectForwardSecrecy: true,        // Critical for whistleblower protection
			AntiReplayWindowSize:        1000,        // Large replay protection window
			MaxFailedAuthAttempts:       3,           // Strict auth limits
			AuthBanDurationMinutes:      60,          // 1 hour ban for failed auth
		},
		Crypto: CryptoConfig{
			CertificatePath:          "certs/cert.pem",
			PrivateKeyPath:           "certs/key.pem",
			KeyRotationIntervalHours: 24, // Daily key rotation
			AllowedCipherSuites: []string{
				"TLS_CHACHA20_POLY1305_SHA256", // Preferred for mobile/low-power
				"TLS_AES_256_GCM_SHA384",       // Strong alternative
			},
			MinTLSVersion:           "1.3",   // Only TLS 1.3
			CertificateValidityDays: 30,      // Short-lived certificates
			KeyStrength:             4096,    // Strong RSA keys
			UseECDSA:                true,    // ECDSA preferred for performance
			ECDSACurve:              "P-384", // High security curve
		},
		Monitoring: MonitoringConfig{
			HealthPort:              "8080",
			EnableMetrics:           true,
			MetricsRetentionHours:   24,     // Short retention for privacy
			LogLevel:                "WARN", // Minimal logging for OPSEC
			EnableSecurityAuditing:  true,
			AuditLogPath:            "/var/log/secure-messaging/audit.log",
			MaxLogFileSizeMB:        10, // Small log files
			LogRotationIntervalDays: 1,  // Daily rotation
			HealthEndpoint:          "/sys/status",
			MetricsEndpoint:         "/sys/metrics",
		},
		OPSEC: OPSECConfig{
			EnableProcessObfuscation: true,
			ClearEnvironmentVars:     true,
			EnableMemoryProtection:   true,
			SecureDeleteTempFiles:    true,
			DisableCoreDumps:         true,
			EnableCanaryTokens:       false,      // Disable for initial deployment
			AllowedClientCountries:   []string{}, // Empty = allow all initially
			BlockedClientCountries: []string{
				// Known adversarial countries for intelligence agencies
				"CN", "RU", "KP", "IR",
			},
			EnableGeoBlocking:   false, // Disabled initially (can block legitimate sources)
			MaxDailyConnections: 50,    // Conservative limit per IP
		},
	}
}

// overrideWithEnvironment allows runtime configuration via environment variables
func overrideWithEnvironment(config *Config) {
	// Server overrides
	if port := os.Getenv("SECURE_PORT"); port != "" {
		config.Server.Port = port
	}

	// Security overrides
	if logLevel := os.Getenv("SECURE_LOG_LEVEL"); logLevel != "" {
		config.Monitoring.LogLevel = logLevel
	}
	if hmacSecret := os.Getenv("HMAC_SECRET"); hmacSecret != "" {
		config.Security.HMACSecret = hmacSecret
	}

	// Certificate path overrides (for custom deployment)
	if certPath := os.Getenv("SECURE_CERT_PATH"); certPath != "" {
		config.Crypto.CertificatePath = certPath
	}
	if keyPath := os.Getenv("SECURE_KEY_PATH"); keyPath != "" {
		config.Crypto.PrivateKeyPath = keyPath
	}
}

// SaveConfig saves the current configuration to a file (for operational use)
func (c *Config) SaveConfig(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600) // Secure file permissions
}

// ValidateConfig ensures all configuration values are within secure ranges
func (c *Config) ValidateConfig() error {
	// Validate security constraints
	if c.Security.MaxMessageSize > 1024*1024 { // 1MB limit
		c.Security.MaxMessageSize = 1024 * 1024
	}

	if c.Security.RateLimitMessagesPerMinute > 100 {
		c.Security.RateLimitMessagesPerMinute = 100
	}

	if c.Crypto.KeyStrength < 2048 {
		c.Crypto.KeyStrength = 2048 // Minimum acceptable
	}

	// Ensure TLS 1.3 minimum
	if c.Crypto.MinTLSVersion != "1.3" {
		c.Crypto.MinTLSVersion = "1.3"
	}

	return nil
}
