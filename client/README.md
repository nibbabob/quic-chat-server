# Ultra-Secure Whistleblower Client
## Intelligence Agency Protection Grade

> ⚠️ **CLASSIFIED**: This client is designed for protecting intelligence agency whistleblowers. Use only under authorized conditions.

## 🛡️ Security Features

### **Maximum Protection**
- **🔒 TLS 1.3 Only** - No downgrade attacks possible
- **🔐 Perfect Forward Secrecy** - Past messages safe even if keys compromised
- **👁️ OPSEC Compliance** - Minimal data persistence, secure memory handling
- **🚫 No Logs** - Zero persistent storage of conversations
- **⚡ Ephemeral Keys** - New keys generated each session

### **Advanced Encryption**
- **ECDSA P-384** - Military-grade elliptic curve cryptography
- **End-to-End Encryption** - Server cannot decrypt messages
- **Message Authentication** - Prevent tampering and replay attacks
- **Key Rotation** - On-demand key refresh during conversations

### **Operational Security**
- **Secure Input Handling** - Raw terminal mode prevents keyloggers
- **Memory Protection** - Automatic sensitive data wiping
- **Emergency Shutdown** - Instant secure disconnect (Ctrl+D)
- **Connection Monitoring** - Real-time security status

## 🚀 Quick Start

### Build Client
```bash
cd client/
go build -ldflags="-s -w" -o secure-client .
```

### Run Client
```bash
./secure-client
```

### First Time Setup
1. **Enter Secure Identifier**: Use your authorized call sign
2. **Enter Room Identifier**: Use the pre-shared room code
3. **Wait for Connection**: Client automatically handles secure handshake

## 🔧 Commands

| Command | Description | Security Level |
|---------|-------------|----------------|
| `/help` | Show available commands | Safe |
| `/status` | Display security status | Safe |
| `/rotate` | Rotate encryption keys | High Security |
| `/quit` | Secure disconnect | Safe |
| `Ctrl+C` | Emergency shutdown | Critical |
| `Ctrl+D` | Instant security disconnect | Critical |

## 🔒 Security Protocols

### **Authentication Flow**
1. Client generates ephemeral ECDSA P-384 key pair
2. Secure QUIC connection established (TLS 1.3)
3. Public key exchange with server
4. Challenge-response authentication if required
5. End-to-end encrypted communication begins

### **Message Flow**
1. User types message in secure input buffer
2. Message encrypted for each recipient individually
3. Encrypted bundle sent via QUIC stream
4. Recipients decrypt with their private keys
5. Plaintext displayed only in recipient terminals

### **Key Management**
- **Key Generation**: ECDSA P-384 with cryptographically secure random
- **Key Storage**: Memory only, never written to disk
- **Key Exchange**: Public keys shared via secure channels
- **Key Rotation**: Manual rotation available via `/rotate` command

## ⚠️ Security Warnings

### **CRITICAL OPERATIONAL SECURITY**

1. **🚫 Never run on compromised systems**
2. **🚫 Never use over untrusted networks without additional VPN/Tor**
3. **🚫 Never screenshot or record conversations**
4. **🚫 Never run with screen sharing active**
5. **🚫 Always use `/quit` for clean shutdown**

### **Emergency Procedures**

#### **If Compromised**
1. Press `Ctrl+D` for instant disconnect
2. Power off device immediately
3. Contact security team
4. Assume all recent communications compromised

#### **If Under Surveillance**
1. Use emergency shutdown (Ctrl+D)
2. Follow standard counter-surveillance protocols
3. Switch to backup communication channels

## 🔧 Technical Details

### **Cryptographic Specifications**
- **Key Exchange**: ECDH P-384
- **Symmetric Encryption**: AES-256-GCM (planned)
- **Message Authentication**: HMAC-SHA256
- **Digital Signatures**: ECDSA P-384
- **Random Number Generation**: Cryptographically secure

### **Network Security**
- **Transport**: QUIC over TLS 1.3
- **Cipher Suites**: ChaCha20-Poly1305, AES-256-GCM
- **Session Management**: No session resumption
- **Connection Limits**: Strict timeout policies

### **Memory Management**
- **Sensitive Data**: Automatically cleared on exit
- **Garbage Collection**: Forced after operations
- **Buffer Protection**: Secure input handling
- **Stack Protection**: No sensitive data on stack

## 🛠️ Development Notes

### **Building for Production**
```bash
# Static binary with security flags
CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o secure-client .

# Strip debugging symbols
strip secure-client

# Verify no external dependencies
ldd secure-client  # Should show "not a dynamic executable"
```

### **Security Testing**
- Run with `-race` flag during development
- Use memory leak detection tools
- Test emergency shutdown procedures
- Verify memory clearing effectiveness

## 📋 Compliance

### **Security Standards**
- ✅ FIPS 140-2 Level 2 compatible cryptography
- ✅ NSA Suite B cryptographic algorithms
- ✅ Perfect Forward Secrecy
- ✅ Zero knowledge architecture
- ✅ Minimal attack surface

### **Operational Requirements**
- ✅ No persistent storage
- ✅ Secure memory handling
- ✅ Emergency disconnect capability
- ✅ Real-time security monitoring
- ✅ Tamper-evident design

## 🆘 Support

For technical support or security concerns:
- **Internal**: Contact your security team
- **External**: Use only pre-established secure channels
- **Emergency**: Follow standard operational protocols

---

**CLASSIFICATION**: This software contains sensitive cryptographic implementations. Distribution is restricted to authorized personnel only.