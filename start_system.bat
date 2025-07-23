@echo off
setlocal

title Ultra-Secure Whistleblower Communication System

echo.
echo ================================================================
echo     🔒 ULTRA-SECURE WHISTLEBLOWER COMMUNICATION SYSTEM
echo        Intelligence Agency Protection Grade
echo ================================================================
echo.

REM Check if Go is installed
go version >nul 2>&1
if errorlevel 1 (
    echo ❌ Go is not installed. Please install Go 1.21+ first.
    pause
    exit /b 1
)

REM Create certs directory if it doesn't exist
if not exist "certs" (
    echo 🔧 Creating certs directory...
    mkdir certs
)


echo 🔧 Building secure components...
echo.
REM Build server
echo 📦 Building server...
set CGO_ENABLED=0
go build -ldflags="-s -w" -o secure-server.exe .
if errorlevel 1 (
    echo ❌ Failed to build server
    pause
    exit /b 1
)
echo ✅ Server built successfully

REM Build client
echo 📦 Building client...
if not exist "client" (
    echo ❌ Client directory not found. Please ensure client code is in .\client\
    pause
    exit /b 1
)

cd client
go build -ldflags="-s -w" -o secure-client.exe .
if errorlevel 1 (
    echo ❌ Failed to build client
    pause
    exit /b 1
)
echo ✅ Client built successfully
cd ..

REM Generate secure secrets
echo 🔑 Generating secure HMAC_SECRET and IP_HASH_SALT...
for /f "tokens=*" %%a in ('powershell -Command "-join ((0..63) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })"') do set "HMAC_SECRET=%%a"
for /f "tokens=*" %%a in ('powershell -Command "-join ((0..63) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })"') do set "IP_HASH_SALT=%%a"

if not defined HMAC_SECRET (
    echo ❌ Failed to generate HMAC_SECRET.
    pause
    exit /b 1
)
if not defined IP_HASH_SALT (
    echo ❌ Failed to generate IP_HASH_SALT.
    pause
    exit /b 1
)
echo ✅ Secure secrets generated.

REM Create test configuration
echo ⚙️  Creating test configuration...
(
    echo {
    echo   "server": {
    echo     "port": "4433",
    echo     "max_connections": 10,
    echo     "max_rooms_per_server": 5,
    echo     "max_users_per_room": 4
    echo   },
    echo   "security": {
    echo     "require_client_authentication": false,
    echo     "enable_perfect_forward_secrecy": true,
    echo     "rate_limit_messages_per_minute": 30,
    echo     "hmac_secret": "%HMAC_SECRET%"
    echo   },
    echo   "crypto": {
    echo     "use_ecdsa_instead_of_rsa": true,
    echo     "ecdsa_curve": "P-384"
    echo   },
    echo   "monitoring": {
    echo     "health_port": "8080",
    echo     "log_level": "INFO"
    echo   },
    echo   "opsec": {
    echo     "enable_memory_protection": true,
    echo     "clear_environment_variables": false
    echo   }
    echo }
) > test-config.json

echo ✅ Configuration created
echo.
REM Start server
echo 🚀 Starting secure server...
set SECURE_CONFIG_PATH=test-config.json
set IP_HASH_SALT=%IP_HASH_SALT%
start "Secure Server" secure-server.exe

REM Wait for server to start
echo ⏳ Waiting for server initialization...
timeout /t 3 /nobreak >nul

echo.
echo 🎉 System Ready!
echo.
echo ================================================================
echo                        📋 INSTRUCTIONS
echo ================================================================
echo.
echo  1. Open TWO new Command Prompt windows
echo  2. In first window:  cd client ^&^& secure-client.exe
echo  3. In second window: cd client ^&^& secure-client.exe  
echo  4. Use same room name in both clients
echo  5. Start chatting securely!
echo.
echo ================================================================
echo                     🔧 EXAMPLE CLIENT SETUP
echo ================================================================
echo.
echo  Secure identifier: alice / bob
echo  Room identifier:   secret_room
echo.
echo ================================================================
echo                          💡 TIPS
echo ================================================================
echo.
echo  • Type /help in client for commands
echo  • Type /status to check security
echo  • Use Ctrl+C for secure exit
echo.
echo 📊 Monitor server at: http://localhost:8080/sys/status
echo.
echo Press any key to stop the system...
pause >nul

REM Cleanup
echo.
echo 🧹 Stopping server...
taskkill /f /im secure-server.exe >nul 2>&1
echo ✅ System stopped

pause