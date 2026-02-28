#!/bin/bash

set -e

echo "[*] Starting installation..."

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo ./install.sh"
  exit 1
fi

if command -v apt >/dev/null 2>&1; then
    echo "[*] Updating package lists..."
    apt update

    # Install arpspoof (from dsniff) if missing
    if ! command -v arpspoof >/dev/null 2>&1; then
        echo "[*] Installing dependency: dsniff (arpspoof)..."
        apt install -y dsniff
    else
        echo "[+] arpspoof already installed."
    fi

    # Install build tools and libpcap development files
    echo "[*] Installing build-essential and libpcap-dev..."
    apt install -y build-essential libpcap-dev
else
    echo "Unsupported distribution. Install dsniff, build-essential, and libpcap-dev manually."
    exit 1
fi

echo "[*] Building tool from http_capture.c..."
gcc -o portSniff http_capture.c -lpcap

echo "[*] Installing binary..."
cp portSniff /usr/local/bin/
chmod +x /usr/local/bin/portSniff

echo "[+] Installation complete."
echo "You can now run: portSniff"
