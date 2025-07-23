#!/bin/bash

# Ultra-Secure Whistleblower Communication System
# Startup Script

set -e

echo "🔒 Ultra-Secure Whistleblower Communication System"
echo "⚠️  Intelligence Agency Protection Grade"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to clean up on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}🧹 Cleaning up processes...${NC}"
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        echo -e "${GREEN}✅ Server stopped${NC}"
    fi
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed. Please install Go 1.21+ first.${NC}"
    exit 1
fi

echo -e "${CYAN}🔧 Building secure components...${NC}"

# Build server
echo -e "${YELLOW}📦 Building server...${NC}"
if ! CGO_ENABLED=0 go build -ldflags="-s -w" -o secure-server .; then
    echo -e "${RED}❌ Failed to build server${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Server built successfully${NC}"

# Build client
echo -e "${YELLOW}📦 Building client...${NC}"
if [ ! -d "client" ]; then
    echo -e "${RED}❌ Client directory not found. Please ensure client code is in ./client/${NC}"
    exit 1
fi

cd client/
if ! CGO_ENABLED=0 go build -ldflags="-s -w" -o secure-client .; then
    echo -e "${RED}❌ Failed to build client${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Client built successfully${NC}"
cd ..

# Create minimal config for testing
echo -e "${YELLOW}⚙️  Creating test configuration...${NC}"
cat > test-config.json << 'EOF'
{
  "server": {
    "port": "4433",
    "max_connections": 10,
    "max_rooms_per_server": 5,
    "max_users_per_room": 4
  },
  "security": {
    "require_client_authentication": true,
    "enable_perfect_forward_secrecy": true,
    "rate_limit_messages_per_minute": 30,
	"hmac_secret": "a-secure-secret-for-hmac-should-be-generated-and-long"
  },
  "crypto": {
    "use_ecdsa_instead_of_rsa": true,
    "ecdsa_curve": "P-384"
  },
  "monitoring": {
    "health_port": "8080",
    "log_level": "INFO"
  },
  "opsec": {
    "enable_memory_protection": true,
    "clear_environment_variables": false
  }
}
EOF

echo -e "${GREEN}✅ Configuration created${NC}"

# Start server
echo ""
echo -e "${CYAN}🚀 Starting secure server...${NC}"
SECURE_CONFIG_PATH=test-config.json ./secure-server &
SERVER_PID=$!

# Wait for server to start
echo -e "${YELLOW}⏳ Waiting for server initialization...${NC}"
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}❌ Server failed to start${NC}"
    exit 1
fi

# Check server health
if command -v curl &> /dev/null; then
    if curl -s http://localhost:8080/sys/status > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server is healthy and ready${NC}"
    else
        echo -e "${YELLOW}⚠️  Server health check unavailable${NC}"
    fi
fi

echo ""
echo -e "${GREEN}🎉 System Ready!${NC}"
echo ""
echo -e "${CYAN}📋 Instructions:${NC}"
echo -e "  1. Open ${YELLOW}TWO${NC} new terminals"
echo -e "  2. In terminal 1: ${BLUE}cd client && ./secure-client${NC}"
echo -e "  3. In terminal 2: ${BLUE}cd client && ./secure-client${NC}"
echo -e "  4. Use same room name in both clients"
echo -e "  5. Start chatting securely!"
echo ""
echo -e "${CYAN}🔧 Example Client Setup:${NC}"
echo -e "  Secure identifier: ${GREEN}alice${NC} / ${GREEN}bob${NC}"
echo -e "  Room identifier: ${GREEN}secret_room${NC}"
echo ""
echo -e "${CYAN}💡 Tips:${NC}"
echo -e "  • Type ${BLUE}/help${NC} in client for commands"
echo -e "  • Type ${BLUE}/status${NC} to check security"
echo -e "  • Use ${BLUE}Ctrl+C${NC} for secure exit"
echo ""
echo -e "${YELLOW}🏃 Server running with PID: $SERVER_PID${NC}"
echo -e "${YELLOW}📊 Monitor at: http://localhost:8080/sys/status${NC}"
echo ""
echo -e "${RED}Press Ctrl+C to stop the system${NC}"

# Keep script running
wait $SERVER_PID