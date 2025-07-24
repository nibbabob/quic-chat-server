package types

import (
	"quic-chat-server/utils"
	"sync"
	"time"
)

// Message structures for end-to-end encrypted messaging with enhanced security
type Message struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "message", "join", "leave", "key_exchange", "heartbeat", "key_rotation"
	Metadata  Metadata  `json:"metadata"`
	Encrypted bool      `json:"encrypted"`
	Signature string    `json:"signature,omitempty"`
	HMAC      string    `json:"hmac,omitempty"`     // Message authentication code
	Nonce     string    `json:"nonce,omitempty"`    // Anti-replay nonce
	Sequence  uint64    `json:"sequence,omitempty"` // Message sequence number
	Timestamp time.Time `json:"timestamp"`
}

// Enhanced Metadata with security features
type Metadata struct {
	// E2EE content mapping: recipient_username -> encrypted_content
	Content map[string]string `json:"content,omitempty"`

	// Single content for broadcast messages or single encrypted payload
	SingleContent string `json:"single_content,omitempty"`

	// Author information
	Author   string `json:"author"`
	AuthorID string `json:"author_id"`

	// Timestamps for audit trail
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
	DeletedAt *string `json:"deleted_at,omitempty"`

	// Channel information
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`

	// Cryptographic data
	PublicKey string `json:"public_key,omitempty"`

	// User management
	ExistingUsers map[string]string `json:"existing_users,omitempty"`

	// Authentication and security
	AuthChallenge string `json:"auth_challenge,omitempty"`
	AuthResponse  string `json:"auth_response,omitempty"`
	RequiresAuth  bool   `json:"requires_auth,omitempty"`
	MessageID     string `json:"message_id,omitempty"`

	// Security metadata
	SecurityLevel  string                 `json:"security_level,omitempty"`  // "standard", "high", "maximum"
	EncryptionAlgo string                 `json:"encryption_algo,omitempty"` // Algorithm used for encryption
	KeyFingerprint string                 `json:"key_fingerprint,omitempty"` // Public key fingerprint
	CustomHeaders  map[string]interface{} `json:"custom_headers,omitempty"`  // Additional metadata
}

// Server state for managing connections and rooms with enhanced security
type Server struct {
	Connections map[string]*ClientConnection
	Rooms       map[string]*Room
	Mutex       sync.RWMutex

	// Security monitoring
	SecurityMetrics SecurityMetrics
	StartTime       time.Time

	// Operational security
	ShutdownRequested bool
	MaintenanceMode   bool
}

// Enhanced ClientConnection with comprehensive security features
type ClientConnection struct {
	// Basic connection info
	ID     string
	Conn   Connection
	UserID string
	RoomID string

	// Cryptographic data
	PublicKey      string
	KeyFingerprint string

	// Authentication
	AuthChallenge   string
	Authenticated   bool
	AuthAttempts    int
	LastAuthAttempt time.Time

	// Activity tracking
	JoinTime      time.Time
	LastActivity  time.Time
	MessageCount  int64
	BytesSent     int64
	BytesReceived int64

	// Rate limiting
	RateLimiter RateLimiter

	// Security flags
	IsSuspicious   bool
	ViolationCount int
	SecurityLevel  string // "standard", "high", "maximum"
	CountryCode    string
	UserAgent      string

	// Connection metadata
	TLSVersion     string
	CipherSuite    string
	RemoteAddr     string
	ConnectionTime time.Duration
}

// Enhanced Room with security features
type Room struct {
	ID      string
	Clients map[string]*ClientConnection
	Mutex   sync.RWMutex

	// Room metadata
	CreatedAt    time.Time
	LastActivity time.Time
	MessageCount int64

	// Security settings
	SecurityLevel     string   // "standard", "high", "maximum"
	MaxUsers          int      // Room-specific user limit
	RequireInvite     bool     // Invitation-only room
	AllowedUsers      []string // Whitelist of allowed users
	BlockedUsers      []string // Blacklist of blocked users
	ModerationEnabled bool     // Enable content moderation

	// Encryption settings
	ForwardSecrecy      bool          // Require perfect forward secrecy
	KeyRotationInterval time.Duration // Automatic key rotation
	LastKeyRotation     time.Time

	// Audit trail
	AuditLog []AuditEntry
}

// Rate limiting structure with enhanced tracking
type RateLimiter struct {
	// Message rate limiting
	MessageCount int
	ByteCount    int64
	WindowStart  time.Time
	LastMessage  time.Time

	// Violation tracking
	ViolationCount        int
	LastViolation         time.Time
	ConsecutiveViolations int

	// Adaptive rate limiting
	BaseLimit    int
	CurrentLimit int
	AdaptiveMode bool

	// Burst protection
	BurstTokens     int
	LastTokenRefill time.Time
}

// Security metrics for monitoring
type SecurityMetrics struct {
	// Connection metrics
	TotalConnections    int64
	ActiveConnections   int
	RejectedConnections int64

	// Authentication metrics
	AuthenticationAttempts int64
	FailedAuthentications  int64
	BannedIPs              int

	// Message metrics
	TotalMessages       int64
	EncryptedMessages   int64
	RateLimitViolations int64

	// Security events
	SuspiciousActivity int64
	SecurityAlerts     int64
	LastSecurityEvent  time.Time

	// Performance metrics
	AverageLatency    time.Duration
	MessageThroughput float64

	// Error metrics
	ConnectionErrors    int64
	MessageErrors       int64
	CryptographicErrors int64
}

// Audit entry for security logging
type AuditEntry struct {
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"` // "join", "leave", "message", "auth_fail", etc.
	UserID       string                 `json:"user_id"`
	ConnectionID string                 `json:"connection_id"`
	RoomID       string                 `json:"room_id"`
	Details      map[string]interface{} `json:"details"`
	Severity     string                 `json:"severity"` // "low", "medium", "high", "critical"
	IPHash       string                 `json:"ip_hash"`  // Hashed IP for privacy
}

// Security alert structure
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AlertType   string                 `json:"alert_type"` // "rate_limit", "auth_fail", "suspicious_content", etc.
	Severity    string                 `json:"severity"`   // "low", "medium", "high", "critical"
	Source      string                 `json:"source"`     // IP hash or user ID
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

// Configuration for different security levels
type SecurityLevelConfig struct {
	Level               string
	MaxMessageSize      int
	RateLimit           int
	RequireAuth         bool
	ForwardSecrecy      bool
	KeyRotationInterval time.Duration
	AuditLevel          string // "minimal", "standard", "comprehensive"
}

// Predefined security levels
var SecurityLevels = map[string]SecurityLevelConfig{
	"standard": {
		Level:               "standard",
		MaxMessageSize:      32768, // 32KB
		RateLimit:           30,    // 30 msgs/min
		RequireAuth:         false,
		ForwardSecrecy:      true,
		KeyRotationInterval: 24 * time.Hour,
		AuditLevel:          "standard",
	},
	"high": {
		Level:               "high",
		MaxMessageSize:      16384, // 16KB
		RateLimit:           20,    // 20 msgs/min
		RequireAuth:         true,
		ForwardSecrecy:      true,
		KeyRotationInterval: 12 * time.Hour,
		AuditLevel:          "comprehensive",
	},
	"maximum": {
		Level:               "maximum",
		MaxMessageSize:      8192, // 8KB
		RateLimit:           10,   // 10 msgs/min
		RequireAuth:         true,
		ForwardSecrecy:      true,
		KeyRotationInterval: 4 * time.Hour,
		AuditLevel:          "comprehensive",
	},
}

// Operational security configuration
type OpSecConfig struct {
	// Process security
	EnableProcessObfuscation bool
	ClearEnvironmentVars     bool
	DisableCoreDumps         bool

	// Memory security
	EnableMemoryProtection bool
	SecureDeleteTempFiles  bool
	OverwriteMemoryOnExit  bool

	// Network security
	EnableGeoBlocking   bool
	AllowedCountries    []string
	BlockedCountries    []string
	MaxDailyConnections int

	// Logging security
	MinimalLogging    bool
	EncryptLogs       bool
	LogRetentionHours int
	SecureLogDeletion bool

	// Monitoring
	EnableCanaryTokens bool
	EnableHoneypots    bool
	AlertWebhookURL    string
}

// Message validation configuration
type MessageValidationConfig struct {
	// Size limits
	MaxMessageSize int
	MaxFieldLength int
	MaxFieldCount  int

	// Content validation
	EnableContentFiltering bool
	SuspiciousPatterns     []string
	AllowedContentTypes    []string

	// Rate limiting
	RateLimitWindow      time.Duration
	MaxMessagesPerWindow int
	MaxBytesPerWindow    int64

	// Anti-spam
	MaxRepetitionPercentage   float64
	MaxSimilarMessagesPerHour int
	EnableBayesianFiltering   bool
}

// Helper methods for security levels

func (c *ClientConnection) GetSecurityLevel() SecurityLevelConfig {
	if config, exists := SecurityLevels[c.SecurityLevel]; exists {
		return config
	}
	return SecurityLevels["standard"]
}

func (r *Room) GetSecurityLevel() SecurityLevelConfig {
	if config, exists := SecurityLevels[r.SecurityLevel]; exists {
		return config
	}
	return SecurityLevels["standard"]
}

func (a *AuditEntry) IsCritical() bool {
	return a.Severity == "critical"
}

func (a *SecurityAlert) IsCritical() bool {
	return a.Severity == "critical"
}

// Security validation helpers

func (m *Message) IsValid() bool {
	if m.ID == "" || m.Type == "" {
		return false
	}

	if len(m.Type) > 50 {
		return false
	}

	// Validate timestamp (not too far in future or past)
	now := time.Now()
	if m.Timestamp.After(now.Add(5*time.Minute)) || m.Timestamp.Before(now.Add(-24*time.Hour)) {
		return false
	}

	return true
}

func (m *Message) RequiresAuthentication() bool {
	sensitiveTypes := []string{"message", "key_rotation", "admin"}
	for _, t := range sensitiveTypes {
		if m.Type == t {
			return true
		}
	}
	return false
}

func (c *ClientConnection) IsRateLimited() bool {
	config := c.GetSecurityLevel()
	now := time.Now()

	// Reset window if expired
	if now.Sub(c.RateLimiter.WindowStart) > time.Minute {
		c.RateLimiter.MessageCount = 0
		c.RateLimiter.ByteCount = 0
		c.RateLimiter.WindowStart = now
	}

	return c.RateLimiter.MessageCount >= config.RateLimit
}

func (c *ClientConnection) UpdateActivity() {
	c.LastActivity = time.Now()
	c.MessageCount++
}

func (r *Room) AddAuditEntry(entry AuditEntry) {
	r.AuditLog = append(r.AuditLog, entry)

	// Keep only last 1000 entries to prevent memory bloat
	if len(r.AuditLog) > 1000 {
		r.AuditLog = r.AuditLog[len(r.AuditLog)-1000:]
	}
}

func (r *Room) NeedsKeyRotation() bool {
	if r.KeyRotationInterval == 0 {
		return false
	}
	return time.Since(r.LastKeyRotation) > r.KeyRotationInterval
}

func (s *SecurityMetrics) IncrementConnections() {
	s.TotalConnections++
	s.ActiveConnections++
}

func (s *SecurityMetrics) DecrementConnections() {
	if s.ActiveConnections > 0 {
		s.ActiveConnections--
	}
}

func (s *SecurityMetrics) RecordSecurityEvent(eventType string) {
	s.SecurityAlerts++
	s.LastSecurityEvent = time.Now()

	if eventType == "suspicious_activity" {
		s.SuspiciousActivity++
	}
}

// Factory functions for creating secure instances

func NewSecureMessage(msgType string, author string) *Message {
	return &Message{
		ID:        utils.GenerateSecureID(),
		Type:      msgType,
		Timestamp: time.Now(),
		Metadata: Metadata{
			Author:    author,
			CreatedAt: time.Now().Format(time.RFC3339),
		},
	}
}

func NewSecureRoom(roomID string, securityLevel string) *Room {
	config := SecurityLevels[securityLevel]
	if config.Level == "" {
		config = SecurityLevels["standard"]
	}

	return &Room{
		ID:                  roomID,
		Clients:             make(map[string]*ClientConnection),
		CreatedAt:           time.Now(),
		LastActivity:        time.Now(),
		SecurityLevel:       securityLevel,
		MaxUsers:            10, // Default room size
		ForwardSecrecy:      config.ForwardSecrecy,
		KeyRotationInterval: config.KeyRotationInterval,
		LastKeyRotation:     time.Now(),
		AuditLog:            make([]AuditEntry, 0),
	}
}

func NewSecureClientConnection(connID string, conn Connection, userID string) *ClientConnection {
	now := time.Now()
	return &ClientConnection{
		ID:            connID,
		Conn:          conn,
		UserID:        userID,
		JoinTime:      now,
		LastActivity:  now,
		SecurityLevel: "standard",
		RateLimiter: RateLimiter{
			WindowStart:     now,
			BaseLimit:       30,
			CurrentLimit:    30,
			BurstTokens:     5,
			LastTokenRefill: now,
		},
		RemoteAddr: conn.RemoteAddr().String(),
	}
}

func NewAuditEntry(eventType, userID, connID, roomID string, severity string, details map[string]interface{}) AuditEntry {
	return AuditEntry{
		Timestamp:    time.Now(),
		EventType:    eventType,
		UserID:       userID,
		ConnectionID: connID,
		RoomID:       roomID,
		Details:      details,
		Severity:     severity,
	}
}

func NewSecurityAlert(alertType, severity, source, description string, metadata map[string]interface{}) SecurityAlert {
	return SecurityAlert{
		ID:          utils.GenerateSecureID(),
		Timestamp:   time.Now(),
		AlertType:   alertType,
		Severity:    severity,
		Source:      source,
		Description: description,
		Metadata:    metadata,
		Resolved:    false,
	}
}

// Utility functions

// generateSecureID has been removed as it was insecure.
// All calls should now use utils.GenerateSecureID()

// Security validation interfaces

type MessageValidator interface {
	ValidateMessage(msg *Message) error
	ValidateContent(content []byte) error
	ValidateMetadata(metadata *Metadata) error
}

type ConnectionValidator interface {
	ValidateConnection(conn *ClientConnection) error
	ValidateAuthentication(conn *ClientConnection, challenge, response string) error
	ValidateRateLimit(conn *ClientConnection) error
}

type RoomValidator interface {
	ValidateRoomAccess(room *Room, userID string) error
	ValidateRoomCapacity(room *Room) error
	ValidateSecurityLevel(room *Room, requiredLevel string) error
}

// Security event types
const (
	EventTypeJoin              = "join"
	EventTypeLeave             = "leave"
	EventTypeMessage           = "message"
	EventTypeAuthSuccess       = "auth_success"
	EventTypeAuthFailure       = "auth_failure"
	EventTypeRateLimit         = "rate_limit_exceeded"
	EventTypeSuspiciousContent = "suspicious_content"
	EventTypeKeyRotation       = "key_rotation"
	EventTypeSecurityAlert     = "security_alert"
	EventTypeConnectionClosed  = "connection_closed"
	EventTypeRoomCreated       = "room_created"
	EventTypeRoomDestroyed     = "room_destroyed"
)

// Alert types
const (
	AlertTypeRateLimit          = "rate_limit"
	AlertTypeAuthFailure        = "auth_failure"
	AlertTypeSuspiciousContent  = "suspicious_content"
	AlertTypeUnauthorizedAccess = "unauthorized_access"
	AlertTypeConnectionFlood    = "connection_flood"
	AlertTypeCryptoError        = "cryptographic_error"
	AlertTypeSystemAnomaly      = "system_anomaly"
	AlertTypeSecurityBreach     = "security_breach"
)

// Severity levels
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Security levels
const (
	SecurityLevelStandard = "standard"
	SecurityLevelHigh     = "high"
	SecurityLevelMaximum  = "maximum"
)
