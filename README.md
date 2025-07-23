# Ultra-Secure Whistleblower Communication Server
## Deployment Guide for Intelligence Agency Protection

> ⚠️ **CRITICAL SECURITY NOTICE**: This system is designed for protecting intelligence agency whistleblowers. Follow ALL security procedures exactly. Lives may depend on proper deployment.

## 🎯 Security Objectives

- **Perfect Forward Secrecy**: All communications use ephemeral keys
- **End-to-End Encryption**: Server cannot decrypt user messages
- **Operational Security**: Minimal logging, process obfuscation, secure memory handling
- **Anonymous Operation**: No persistent user data, minimal metadata collection
- **Attack Resistance**: Rate limiting, DDoS protection, geographic blocking

## 🚀 Quick Secure Deployment

### Prerequisites

```bash
# Ensure Go 1.21+ is installed
go version

# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential git curl

# For production: Install fail2ban and firewall
sudo apt install -y ufw fail2ban
```

### 1. Secure Server Setup

```bash
# Clone to secure location
git clone [repository] /opt/secure-messaging
cd /opt/secure-messaging

# Set secure permissions
sudo chown -R root:root .
sudo chmod -R 755 .
sudo chmod 600 certs/*.pem 2>/dev/null || true

# Build with security flags
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o secure-server .
```

### 2. Environment Configuration

Create secure configuration:

```bash
# Create secure config directory
sudo mkdir -p /etc/secure-messaging
sudo chmod 700 /etc/secure-messaging

# Generate configuration
cat > /etc/secure-messaging/config.json << 'EOF'
{
  "server": {
    "port": "4433",
    "max_connections": 50,
    "max_rooms_per_server": 25,
    "max_users_per_room": 8,
    "connection_timeout_seconds": 180
  },
  "security": {
    "max_idle_timeout_seconds": 120,
    "keep_alive_interval_seconds": 30,
    "rate_limit_messages_per_minute": 15,
    "rate_limit_bytes_per_minute": 524288,
    "max_message_size_bytes": 16384,
    "require_client_authentication": true,
    "enable_perfect_forward_secrecy": true,
    "anti_replay_window_size": 1000,
    "max_failed_auth_attempts": 2,
    "auth_ban_duration_minutes": 120
  },
  "crypto": {
    "certificate_path": "/etc/secure-messaging/cert.pem",
    "private_key_path": "/etc/secure-messaging/key.pem",
    "key_rotation_interval_hours": 12,
    "min_tls_version": "1.3",
    "certificate_validity_days": 14,
    "use_ecdsa_instead_of_rsa": true,
    "ecdsa_curve": "P-384"
  },
  "monitoring": {
    "health_port": "8080",
    "enable_metrics": true,
    "log_level": "WARN",
    "enable_security_auditing": true,
    "max_log_file_size_mb": 5,
    "log_rotation_interval_days": 1
  },
  "opsec": {
    "enable_process_obfuscation": true,
    "clear_environment_variables": true,
    "enable_memory_protection": true,
    "secure_delete_temp_files": true,
    "disable_core_dumps": true,
    "blocked_client_countries": ["CN", "RU", "KP", "IR"],
    "max_daily_connections_per_ip": 25
  }
}
EOF

sudo chmod 600 /etc/secure-messaging/config.json
```

### 3. Systemd Service Setup

```bash
# Create systemd service
sudo cat > /etc/systemd/system/secure-messaging.service << 'EOF'
[Unit]
Description=Ultra-Secure Whistleblower Communication Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/secure-messaging/secure-server
WorkingDirectory=/opt/secure-messaging
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

# Environment
Environment=SECURE_CONFIG_PATH=/etc/secure-messaging/config.json
Environment=SECURE_LOG_LEVEL=WARN
Environment=GOMAXPROCS=2

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable secure-messaging
sudo systemctl start secure-messaging
```

### 4. Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (change port if needed)
sudo ufw allow 22/tcp

# Allow secure messaging port
sudo ufw allow 4433/tcp

# Allow health monitoring (localhost only)
sudo ufw allow from 127.0.0.1 to any port 8080

# Enable firewall
sudo ufw --force enable

# Configure fail2ban
sudo cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
bantime = 7200
EOF

sudo systemctl restart fail2ban
```

## 🔒 Advanced Security Configuration

### Certificate Management

```bash
# Generate production certificates (replace with your domain)
openssl req -new -x509 -days 14 -nodes -out /etc/secure-messaging/cert.pem \
  -keyout /etc/secure-messaging/key.pem \
  -subj "/C=XX/ST=/L=/O=Secure Communications/OU=Whistleblower Protection/CN=secure-messaging.local"

# Set secure permissions
sudo chmod 600 /etc/secure-messaging/*.pem
sudo chown root:root /etc/secure-messaging/*.pem
```

### Log Management

```bash
# Create secure log directory
sudo mkdir -p /var/log/secure-messaging
sudo chmod 750 /var/log/secure-messaging

# Configure logrotate
sudo cat > /etc/logrotate.d/secure-messaging << 'EOF'
/var/log/secure-messaging/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        # Securely delete old logs
        find /var/log/secure-messaging -name "*.log.*" -mtime +1 -exec shred -vfz -n 3 {} \;
    endscript
}
EOF
```

### Memory Protection

```bash
# Disable swap to prevent key material from hitting disk
sudo swapoff -a
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab

# Configure kernel parameters for security
sudo cat >> /etc/sysctl.conf << 'EOF'
# Security hardening for whistleblower protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

sudo sysctl -p
```

## 🌐 Network Security

### Tor Hidden Service (Recommended)

```bash
# Install Tor
sudo apt install tor

# Configure hidden service
sudo cat >> /etc/tor/torrc << 'EOF'
# Secure messaging hidden service
HiddenServiceDir /var/lib/tor/secure-messaging/
HiddenServicePort 4433 127.0.0.1:4433
HiddenServiceVersion 3

# Security settings
HiddenServiceMaxStreams 50
HiddenServiceMaxStreamsCloseCircuit 1
EOF

# Restart Tor and get onion address
sudo systemctl restart tor
sudo cat /var/lib/tor/secure-messaging/hostname
```

### VPN/Proxy Setup

```bash
# Example: Configure with WireGuard VPN
sudo apt install wireguard

# Generate server keys
wg genkey | sudo tee /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
sudo chmod 600 /etc/wireguard/private.key
```

## 📊 Monitoring and Alerting

### Health Monitoring

```bash
# Create monitoring script
sudo cat > /opt/secure-messaging/monitor.sh << 'EOF'
#!/bin/bash
# Secure messaging health monitor

HEALTH_URL="http://127.0.0.1:8080/sys/status"
LOG_FILE="/var/log/secure-messaging/health.log"

# Check service health
if curl -sf "$HEALTH_URL" > /dev/null; then
    echo "$(date): Service healthy" >> "$LOG_FILE"
else
    echo "$(date): Service unhealthy - restarting" >> "$LOG_FILE"
    systemctl restart secure-messaging
fi

# Check for security alerts
METRICS_URL="http://127.0.0.1:8080/sys/metrics"
if command -v jq >/dev/null; then
    THREAT_LEVEL=$(curl -sf "$METRICS_URL" | jq -r '.system_metrics.threat_level // "unknown"')
    if [ "$THREAT_LEVEL" = "critical" ]; then
        echo "$(date): CRITICAL THREAT DETECTED" >> "$LOG_FILE"
        # Add alerting logic here
    fi
fi
EOF

sudo chmod +x /opt/secure-messaging/monitor.sh

# Add to crontab
echo "*/5 * * * * /opt/secure-messaging/monitor.sh" | sudo crontab -
```

### Security Alerting

```bash
# Create alert script for critical events
sudo cat > /opt/secure-messaging/alert.sh << 'EOF'
#!/bin/bash
# Security alert handler

LOG_FILE="/var/log/secure-messaging/security.log"
ALERT_EMAIL="security@yourdomain.com"

# Monitor for security events
tail -f /var/log/secure-messaging/audit.log | while read line; do
    if echo "$line" | grep -q "CRITICAL"; then
        echo "$(date): $line" >> "$LOG_FILE"
        
        # Send alert (configure mail server first)
        # echo "$line" | mail -s "Security Alert" "$ALERT_EMAIL"
        
        # Consider automatic countermeasures
        if echo "$line" | grep -q "security_breach"; then
            echo "$(date): Initiating emergency shutdown" >> "$LOG_FILE"
            systemctl stop secure-messaging
        fi
    fi
done &
EOF

sudo chmod +x /opt/secure-messaging/alert.sh
```

## 🛡️ Operational Security Procedures

### Daily Operations

1. **Check System Health**
   ```bash
   sudo systemctl status secure-messaging
   curl -s http://127.0.0.1:8080/sys/status | jq
   ```

2. **Review Security Logs**
   ```bash
   sudo tail -50 /var/log/secure-messaging/security.log
   sudo journalctl -u secure-messaging -n 50
   ```

3. **Monitor Resource Usage**
   ```bash
   free -h
   df -h
   top -p $(pgrep secure-server)
   ```

### Incident Response

1. **Emergency Shutdown**
   ```bash
   sudo systemctl stop secure-messaging
   sudo pkill -9 secure-server
   ```

2. **Secure Log Collection**
   ```bash
   sudo tar -czf incident-logs-$(date +%Y%m%d).tar.gz /var/log/secure-messaging/
   sudo shred -vfz -n 3 /var/log/secure-messaging/*.log
   ```

3. **Certificate Rotation**
   ```bash
   sudo rm /etc/secure-messaging/*.pem
   sudo systemctl restart secure-messaging  # Will auto-generate new certs
   ```

## 🔧 Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   sudo journalctl -u secure-messaging -f
   sudo systemctl status secure-messaging
   ```

2. **Connection Issues**
   ```bash
   sudo netstat -tulpn | grep 4433
   sudo ufw status
   ```

3. **Memory Issues**
   ```bash
   free -h
   sudo sysctl vm.swappiness=1
   ```

### Performance Tuning

```bash
# Optimize for high security workload
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 16777216'