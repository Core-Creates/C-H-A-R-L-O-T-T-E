#!/bin/bash
set -e

# Install JDK 21
if ! java -version 2>&1 | grep '21.'; then
  echo "[+] Installing OpenJDK 21..."
  sudo apt-get update && sudo apt-get install -y openjdk-21-jdk
fi

GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20240501.zip"
GHIDRA_ZIP="/tmp/ghidra_10.4_PUBLIC.zip"
GHIDRA_DIR="/opt/ghidra_10.4_PUBLIC"

if [ ! -d "$GHIDRA_DIR" ]; then
  echo "[+] Downloading Ghidra..."
  wget -O "$GHIDRA_ZIP" "$GHIDRA_URL"
  echo "[+] Extracting Ghidra..."
  sudo unzip -q "$GHIDRA_ZIP" -d /opt/
fi

if ! grep -q GHIDRA_PATH /etc/environment; then
  echo "[+] Setting GHIDRA_PATH environment variable..."
  echo "GHIDRA_PATH=$GHIDRA_DIR" | sudo tee -a /etc/environment
fi

echo "[+] Installation complete. Launch with: $GHIDRA_DIR/ghidraRun"
