package config

import (
	"encoding/json"
	"os"
	"testing"
)

// TestLoadConfigWithDefaults tests if the configuration loads correctly with default values.
func TestLoadConfigWithDefaults(t *testing.T) {
	// Unset environment variables to ensure a clean test
	os.Unsetenv("SECURE_CONFIG_PATH")
	os.Unsetenv("HMAC_SECRET")

	// Set a dummy HMAC secret to pass validation
	t.Setenv("HMAC_SECRET", "test-secret")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() with defaults failed: %v", err)
	}

	// Check a few default values
	if cfg.Server.Port != "4433" {
		t.Errorf("Default port = %s; want 4433", cfg.Server.Port)
	}
	if !cfg.Security.RequireClientAuth {
		t.Error("Default RequireClientAuth should be true")
	}
	if cfg.Crypto.ECDSACurve != "P-521" {
		t.Errorf("Default ECDSACurve = %s; want P-521", cfg.Crypto.ECDSACurve)
	}
}

// TestLoadConfigWithEnvOverrides tests if environment variables correctly override default values.
func TestLoadConfigWithEnvOverrides(t *testing.T) {
	// Set environment variables for the test
	t.Setenv("SECURE_PORT", "9999")
	t.Setenv("SECURE_LOG_LEVEL", "DEBUG")
	t.Setenv("HMAC_SECRET", "env-secret")
	t.Setenv("SECURE_CERT_PATH", "/tmp/cert.pem")
	t.Setenv("SECURE_KEY_PATH", "/tmp/key.pem")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() with env overrides failed: %v", err)
	}

	if cfg.Server.Port != "9999" {
		t.Errorf("Port override = %s; want 9999", cfg.Server.Port)
	}
	if cfg.Monitoring.LogLevel != "DEBUG" {
		t.Errorf("LogLevel override = %s; want DEBUG", cfg.Monitoring.LogLevel)
	}
	if cfg.Security.HMACSecret != "env-secret" {
		t.Errorf("HMACSecret override = %s; want env-secret", cfg.Security.HMACSecret)
	}
	if cfg.Crypto.CertificatePath != "/tmp/cert.pem" {
		t.Errorf("CertificatePath override = %s; want /tmp/cert.pem", cfg.Crypto.CertificatePath)
	}
	if cfg.Crypto.PrivateKeyPath != "/tmp/key.pem" {
		t.Errorf("PrivateKeyPath override = %s; want /tmp/key.pem", cfg.Crypto.PrivateKeyPath)
	}
}

// TestLoadConfigFromFile tests loading a configuration from a JSON file.
func TestLoadConfigFromFile(t *testing.T) {
	// Create a temporary config file
	configFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Define a custom config
	customConfig := getSecureDefaults()
	customConfig.Server.Port = "8888"
	customConfig.Monitoring.LogLevel = "FATAL"
	customConfig.Security.HMACSecret = "file-secret"

	// Write custom config to file
	configData, _ := json.Marshal(customConfig)
	if _, err := configFile.Write(configData); err != nil {
		t.Fatalf("Failed to write to temp config file: %v", err)
	}
	configFile.Close()

	// Set environment variable to point to the temp file
	t.Setenv("SECURE_CONFIG_PATH", configFile.Name())
	// HMAC secret still needs to be set via env for this test case
	t.Setenv("HMAC_SECRET", "file-secret")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() from file failed: %v", err)
	}

	if cfg.Server.Port != "8888" {
		t.Errorf("Port from file = %s; want 8888", cfg.Server.Port)
	}
	if cfg.Monitoring.LogLevel != "FATAL" {
		t.Errorf("LogLevel from file = %s; want FATAL", cfg.Monitoring.LogLevel)
	}
	if cfg.Security.HMACSecret != "file-secret" {
		t.Errorf("HMACSecret from file = %s; want file-secret", cfg.Security.HMACSecret)
	}
}

// TestLoadConfigFromUnreadableFile tests the error handling when a config file is unreadable.
func TestLoadConfigFromUnreadableFile(t *testing.T) {
	// Create a temporary config file
	configFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Write invalid JSON to the file
	if _, err := configFile.Write([]byte("{ not json }")); err != nil {
		t.Fatalf("Failed to write to temp config file: %v", err)
	}
	configFile.Close()

	// Set environment variable to point to the temp file
	t.Setenv("SECURE_CONFIG_PATH", configFile.Name())

	// Expect an error because the file is not valid JSON
	_, err = LoadConfig()
	if err == nil {
		t.Error("LoadConfig() should have failed with an unreadable file, but it did not")
	}
}

// TestConfigValidation checks the custom validation logic in the Config struct.
func TestConfigValidation(t *testing.T) {
	tests := map[string]struct {
		modifier func(*Config)
		wantErr  bool
	}{
		"Valid Config": {
			modifier: func(c *Config) {}, // No changes needed
			wantErr:  false,
		},
		"Invalid RSA Key Strength": {
			modifier: func(c *Config) {
				c.Crypto.UseECDSA = false
				c.Crypto.KeyStrength = 2048
			},
			wantErr: true,
		},
		"Invalid TLS Version": {
			modifier: func(c *Config) {
				c.Crypto.MinTLSVersion = "1.2"
			},
			wantErr: true,
		},
		"Missing HMAC Secret": {
			modifier: func(c *Config) {
				c.Security.HMACSecret = ""
			},
			wantErr: true,
		},
		"Message size too large (should be capped)": {
			modifier: func(c *Config) {
				c.Security.MaxMessageSize = 2000000 // 2MB
			},
			wantErr: false, // This will be corrected, not return an error
		},
		"Rate limit too high (should be capped)": {
			modifier: func(c *Config) {
				c.Security.RateLimitMessagesPerMinute = 2000
			},
			wantErr: false, // This will be corrected, not return an error
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := getSecureDefaults()
			// Always set a default valid secret
			cfg.Security.HMACSecret = "valid-secret"

			// Apply the modification for the current test case
			tc.modifier(cfg)

			err := cfg.ValidateConfig()

			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tc.wantErr)
			}

			// Test the capping logic
			if name == "Message size too large (should be capped)" {
				if cfg.Security.MaxMessageSize != 1024*1024 {
					t.Errorf("MaxMessageSize was not capped correctly: got %d", cfg.Security.MaxMessageSize)
				}
			}
			if name == "Rate limit too high (should be capped)" {
				if cfg.Security.RateLimitMessagesPerMinute != 1000 {
					t.Errorf("RateLimitMessagesPerMinute was not capped correctly: got %d", cfg.Security.RateLimitMessagesPerMinute)
				}
			}
		})
	}
}

// TestSaveConfig tests if the config can be saved to a file.
func TestSaveConfig(t *testing.T) {
	cfg := getSecureDefaults()
	configFile, err := os.CreateTemp("", "save-config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file for saving: %v", err)
	}
	defer os.Remove(configFile.Name())

	if err := cfg.SaveConfig(configFile.Name()); err != nil {
		t.Errorf("SaveConfig() returned an unexpected error: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(configFile.Name()); os.IsNotExist(err) {
		t.Error("SaveConfig() did not create the file")
	}
}
