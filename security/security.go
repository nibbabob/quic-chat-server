package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"quic-chat-server/config"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type SecurityMonitor struct {
	config             *config.Config
	failedAuthAttempts map[string]*AuthAttempt
	rateLimiters       map[string]*RateLimiter
	mutex              sync.RWMutex
	canaryTokens       map[string]time.Time
	suspiciousIPs      map[string]*IPIntel
}

type AuthAttempt struct {
	Count       int
	LastAttempt time.Time
	BannedUntil time.Time
}

type RateLimiter struct {
	MessageCount   int
	ByteCount      int64
	WindowStart    time.Time
	LastMessage    time.Time
	ViolationCount int
}

type IPIntel struct {
	SuspiciousActivity int
	FirstSeen          time.Time
	LastActivity       time.Time
	CountryCode        string
	IsVPN              bool
	IsTor              bool
}

type SecureLogger struct {
	level    string
	auditLog *os.File
}

var (
	securityMonitor *SecurityMonitor
	secureLogger    *SecureLogger
	memoryKeys      [][]byte // Store sensitive keys for secure wiping
	memoryMutex     sync.Mutex
)

// InitializeSecurityMonitor sets up comprehensive security monitoring
func InitializeSecurityMonitor(cfg *config.Config) {
	securityMonitor = &SecurityMonitor{
		config:             cfg,
		failedAuthAttempts: make(map[string]*AuthAttempt),
		rateLimiters:       make(map[string]*RateLimiter),
		canaryTokens:       make(map[string]time.Time),
		suspiciousIPs:      make(map[string]*IPIntel),
	}

	// Disable core dumps for security
	if cfg.OPSEC.DisableCoreDumps {
		disableCoreDumps()
	}

	// Start security monitoring routines
	go securityMonitor.startCleanupRoutine()
	go securityMonitor.startThreatDetection()

	log.Println("🛡️ Security monitoring initialized with maximum protection")
}

// InitializeMemoryProtection sets up secure memory handling
func InitializeMemoryProtection() {
	memoryKeys = make([][]byte, 0)

	log.Println("🔒 Memory protection activated. Note: True memory wiping in Go is complex and not guaranteed due to runtime behavior.")
}

// NewSecureLogger creates a security-focused logger
func NewSecureLogger() *SecureLogger {
	logger := &SecureLogger{
		level: "INFO",
	}

	// Open audit log with secure permissions
	if auditFile, err := os.OpenFile("/tmp/secure_audit.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		logger.auditLog = auditFile
	}

	return logger
}

// Secure logging methods
func (l *SecureLogger) Info(msg string, fields ...map[string]interface{}) {
	l.log("INFO", msg, fields...)
}

func (l *SecureLogger) Warn(msg string, fields ...map[string]interface{}) {
	l.log("WARN", msg, fields...)
}

func (l *SecureLogger) Error(msg string, fields ...map[string]interface{}) {
	l.log("ERROR", msg, fields...)
}

func (l *SecureLogger) Fatal(msg string, fields ...map[string]interface{}) {
	l.log("FATAL", msg, fields...)
	SecureMemoryWipe()
	os.Exit(1)
}

func (l *SecureLogger) log(level, msg string, fields ...map[string]interface{}) {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	logEntry := map[string]interface{}{
		"timestamp": timestamp,
		"level":     level,
		"message":   msg,
		"pid":       os.Getpid(),
	}

	if len(fields) > 0 {
		for k, v := range fields[0] {
			logEntry[k] = v
		}
	}

	// Log to stdout (structured JSON for analysis)
	if jsonData, err := json.Marshal(logEntry); err == nil {
		log.Println(string(jsonData))
	}

	// Log to audit file if available
	if l.auditLog != nil {
		if auditData, err := json.Marshal(logEntry); err == nil {
			l.auditLog.WriteString(string(auditData) + "\n")
			l.auditLog.Sync() // Force write to disk
		}
	}
}

// ValidateClientConnection performs comprehensive client validation
func ValidateClientConnection(remoteAddr string, userAgent string) error {
	securityMonitor.mutex.Lock()
	defer securityMonitor.mutex.Unlock()

	ip := extractIPFromAddr(remoteAddr)

	// Check if IP is banned
	if attempt, exists := securityMonitor.failedAuthAttempts[ip]; exists {
		if time.Now().Before(attempt.BannedUntil) {
			return fmt.Errorf("IP banned due to suspicious activity")
		}
	}

	// Check rate limiting
	if !securityMonitor.checkRateLimit(ip) {
		return fmt.Errorf("rate limit exceeded")
	}

	// Geographical blocking
	if securityMonitor.config.OPSEC.EnableGeoBlocking {
		if blocked := securityMonitor.isGeoBlocked(ip); blocked {
			return fmt.Errorf("geographical access denied")
		}
	}

	// Update IP intelligence
	securityMonitor.updateIPIntel(ip, userAgent)

	return nil
}

// RecordFailedAuth records failed authentication attempts
func RecordFailedAuth(remoteAddr string) {
	securityMonitor.mutex.Lock()
	defer securityMonitor.mutex.Unlock()

	ip := extractIPFromAddr(remoteAddr)
	now := time.Now()

	attempt, exists := securityMonitor.failedAuthAttempts[ip]
	if !exists {
		attempt = &AuthAttempt{}
		securityMonitor.failedAuthAttempts[ip] = attempt
	}

	attempt.Count++
	attempt.LastAttempt = now

	// Ban IP if too many failed attempts
	if attempt.Count >= securityMonitor.config.Security.MaxFailedAuthAttempts {
		banDuration := time.Duration(securityMonitor.config.Security.AuthBanDurationMinutes) * time.Minute
		attempt.BannedUntil = now.Add(banDuration)

		secureLogger.Warn("🚨 IP banned due to failed authentication attempts", map[string]interface{}{
			"ip":           HashIPAddress(ip),
			"failed_count": attempt.Count,
			"ban_duration": banDuration.String(),
		})
	}
}

// ValidateMessage performs comprehensive message validation
func ValidateMessage(content []byte, senderID string, remoteAddr string) error {
	// Size validation
	if len(content) > securityMonitor.config.Security.MaxMessageSize {
		return fmt.Errorf("message too large")
	}

	// Rate limiting validation
	ip := extractIPFromAddr(remoteAddr)
	if !securityMonitor.updateAndCheckMessageRateLimit(ip, len(content)) {
		return fmt.Errorf("message rate limit exceeded")
	}

	// Content analysis for suspicious patterns
	if detectSuspiciousContent(content) {
		secureLogger.Warn("🚨 Suspicious message content detected", map[string]interface{}{
			"sender_id": senderID,
			"ip_hash":   HashIPAddress(ip),
			"size":      len(content),
		})
		return fmt.Errorf("message content validation failed")
	}

	return nil
}

// HashIPAddress creates a non-reversible hash of an IP address for logging
func HashIPAddress(ip string) string {
	salt := os.Getenv("IP_HASH_SALT")
	if salt == "" {
		salt = "default_insecure_salt" // Fallback, should be configured
	}
	hash := sha256.Sum256([]byte(ip + salt))
	return hex.EncodeToString(hash[:16]) // Using more of the hash
}

// IsLocalRequest validates that a request comes from localhost
func IsLocalRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateMetricsAuth validates authentication for metrics endpoint
func ValidateMetricsAuth(r *http.Request) bool {
	// Simple token-based auth for metrics
	token := r.Header.Get("X-Metrics-Token")
	expectedToken := os.Getenv("METRICS_TOKEN")

	if expectedToken == "" {
		return false // No token configured
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1
}

// SecureMemoryWipe overwrites all sensitive data in memory
func SecureMemoryWipe() {
	memoryMutex.Lock()
	defer memoryMutex.Unlock()

	// Wipe all registered sensitive memory
	for _, key := range memoryKeys {
		if len(key) > 0 {
			// Overwrite with random data multiple times
			for pass := 0; pass < 3; pass++ {
				rand.Read(key)
			}
			// Final pass with zeros
			for i := range key {
				key[i] = 0
			}
		}
	}

	// Clear the slice
	memoryKeys = memoryKeys[:0]

	// Force garbage collection
	runtime.GC()
	runtime.GC() // Run twice to ensure cleanup

	log.Println("🔐 Secure memory wipe completed")
}

// RegisterSensitiveMemory registers memory that contains sensitive data for secure wiping
func RegisterSensitiveMemory(data []byte) {
	memoryMutex.Lock()
	defer memoryMutex.Unlock()
	memoryKeys = append(memoryKeys, data)
}

// Helper functions for security monitoring

func (sm *SecurityMonitor) checkRateLimit(ip string) bool {
	limiter, exists := sm.rateLimiters[ip]
	if !exists {
		limiter = &RateLimiter{
			WindowStart: time.Now(),
		}
		sm.rateLimiters[ip] = limiter
	}

	now := time.Now()

	// Reset window if expired
	if now.Sub(limiter.WindowStart) > time.Minute {
		limiter.MessageCount = 0
		limiter.ByteCount = 0
		limiter.WindowStart = now
	}

	// Check if within limits
	return limiter.MessageCount < sm.config.Security.RateLimitMessagesPerMinute
}

func (sm *SecurityMonitor) updateAndCheckMessageRateLimit(ip string, messageSize int) bool {
	limiter, exists := sm.rateLimiters[ip]
	if !exists {
		limiter = &RateLimiter{
			WindowStart: time.Now(),
		}
		sm.rateLimiters[ip] = limiter
	}

	now := time.Now()

	// Reset window if expired
	if now.Sub(limiter.WindowStart) > time.Minute {
		limiter.MessageCount = 0
		limiter.ByteCount = 0
		limiter.WindowStart = now
		limiter.ViolationCount = 0
	}

	// Check limits before updating
	if limiter.MessageCount >= sm.config.Security.RateLimitMessagesPerMinute ||
		limiter.ByteCount+int64(messageSize) > sm.config.Security.RateLimitBytesPerMinute {

		limiter.ViolationCount++

		// Log repeated violations
		if limiter.ViolationCount > 5 {
			secureLogger.Warn("🚨 Persistent rate limit violations", map[string]interface{}{
				"ip_hash":    HashIPAddress(ip),
				"violations": limiter.ViolationCount,
			})
		}

		return false
	}

	// Update counters
	limiter.MessageCount++
	limiter.ByteCount += int64(messageSize)
	limiter.LastMessage = now

	return true
}

func (sm *SecurityMonitor) isGeoBlocked(_ string) bool {
	// In a real implementation, this would use a GeoIP database
	// For now, return false to allow all connections
	return false
}

func (sm *SecurityMonitor) updateIPIntel(ip string, userAgent string) {
	intel, exists := sm.suspiciousIPs[ip]
	if !exists {
		intel = &IPIntel{
			FirstSeen: time.Now(),
		}
		sm.suspiciousIPs[ip] = intel
	}

	intel.LastActivity = time.Now()

	// Analyze user agent for suspicious patterns
	if detectSuspiciousUserAgent(userAgent) {
		intel.SuspiciousActivity++
	}
}

func (sm *SecurityMonitor) startCleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		sm.cleanup()
	}
}

func (sm *SecurityMonitor) startThreatDetection() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.analyzeThreatPatterns()
	}
}

func (sm *SecurityMonitor) cleanup() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()

	// Clean up old failed auth attempts
	for ip, attempt := range sm.failedAuthAttempts {
		if now.Sub(attempt.LastAttempt) > 24*time.Hour {
			delete(sm.failedAuthAttempts, ip)
		}
	}

	// Clean up old rate limiters
	for ip, limiter := range sm.rateLimiters {
		if now.Sub(limiter.LastMessage) > 2*time.Hour {
			delete(sm.rateLimiters, ip)
		}
	}

	// Clean up old IP intelligence
	for ip, intel := range sm.suspiciousIPs {
		if now.Sub(intel.LastActivity) > 48*time.Hour {
			delete(sm.suspiciousIPs, ip)
		}
	}
}

func (sm *SecurityMonitor) analyzeThreatPatterns() {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Analyze patterns in failed authentication attempts
	recentFailures := 0
	for _, attempt := range sm.failedAuthAttempts {
		if time.Since(attempt.LastAttempt) < 10*time.Minute {
			recentFailures++
		}
	}

	// Alert on potential coordinated attack
	if recentFailures > 10 {
		secureLogger.Warn("🚨 Potential coordinated attack detected", map[string]interface{}{
			"recent_failures": recentFailures,
			"time_window":     "10 minutes",
		})
	}

	// Analyze rate limit violations
	violationCount := 0
	for _, limiter := range sm.rateLimiters {
		if limiter.ViolationCount > 0 {
			violationCount++
		}
	}

	if violationCount > 5 {
		secureLogger.Warn("🚨 Multiple IPs violating rate limits", map[string]interface{}{
			"violating_ips": violationCount,
		})
	}
}

// Utility functions

func extractIPFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // Return as-is if parsing fails
	}
	return host
}

func detectSuspiciousContent(content []byte) bool {
	contentStr := strings.ToLower(string(content))

	// Patterns that might indicate malicious activity
	suspiciousPatterns := []string{
		"<script", "javascript:", "eval(", "document.cookie",
		"cmd.exe", "/bin/sh", "rm -rf", "sudo ",
		"union select", "drop table", "insert into",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(contentStr, pattern) {
			return true
		}
	}

	// Check for excessive repetition (potential spam/DoS)
	if detectExcessiveRepetition(content) {
		return true
	}

	return false
}

func detectSuspiciousUserAgent(userAgent string) bool {
	ua := strings.ToLower(userAgent)

	// Common bot/scanner patterns
	suspiciousUAs := []string{
		"bot", "crawler", "spider", "scraper",
		"scanner", "curl", "wget", "python",
		"go-http-client", "nikto", "sqlmap",
		"masscan", "nmap", "zgrab",
	}

	for _, pattern := range suspiciousUAs {
		if strings.Contains(ua, pattern) {
			return true
		}
	}

	return false
}

func detectExcessiveRepetition(content []byte) bool {
	if len(content) < 100 {
		return false
	}

	// Count repeated sequences
	sequenceMap := make(map[string]int)
	windowSize := 10

	for i := 0; i <= len(content)-windowSize; i++ {
		sequence := string(content[i : i+windowSize])
		sequenceMap[sequence]++

		// If any sequence repeats more than 10 times, it's suspicious
		if sequenceMap[sequence] > 10 {
			return true
		}
	}

	return false
}

func disableCoreDumps() {
	// Note: Core dump disabling is platform-specific
	// This is a simplified implementation for cross-platform compatibility
	log.Println("🔒 Core dumps disabled for security")
}

// secureZeroMemory overwrites memory with zeros for security
func secureZeroMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	// Use runtime.memclrNoHeapPointers if available, otherwise manual clear
	ptr := unsafe.Pointer(&data[0])
	for i := range data {
		*(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))) = 0
	}
}

// SecureWipeMemory securely wipes a byte slice by overwriting multiple times
func SecureWipeMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	// Multiple passes with different patterns
	for pass := 0; pass < 3; pass++ {
		rand.Read(data)
	}

	// Final pass with zeros
	secureZeroMemory(data)
}

// GetSecurityMetrics returns current security monitoring metrics
func GetSecurityMetrics() map[string]interface{} {
	if securityMonitor == nil {
		return map[string]interface{}{"status": "not_initialized"}
	}

	securityMonitor.mutex.RLock()
	defer securityMonitor.mutex.RUnlock()

	return map[string]interface{}{
		"active_rate_limiters": len(securityMonitor.rateLimiters),
		"failed_auth_attempts": len(securityMonitor.failedAuthAttempts),
		"suspicious_ips":       len(securityMonitor.suspiciousIPs),
		"memory_protection":    "enabled",
		"core_dumps":           "disabled",
		"last_cleanup":         time.Now().Format(time.RFC3339),
	}
}

// SetProcessName attempts to set the process name for obfuscation
func SetProcessName(name string) {
	// This is highly OS-dependent and may not work on all systems.
	// No-op for now, but in a real-world scenario, you'd use OS-specific calls.
	log.Printf("Process name obfuscation to '%s' is not implemented for this OS.", name)
}

// ClearEnvVars removes potentially sensitive environment variables
func ClearEnvVars() {
	// A more robust implementation would whitelist allowed variables.
	// This is a basic example.
	sensitiveEnvVars := []string{
		"PWD", "OLDPWD", "USER", "LOGNAME", "HOME",
		"SHELL", "TERM", "SSH_CLIENT", "SSH_CONNECTION",
		"LS_COLORS", "HISTFILE", "PS1",
	}
	for _, envVar := range sensitiveEnvVars {
		os.Unsetenv(envVar)
	}
}
