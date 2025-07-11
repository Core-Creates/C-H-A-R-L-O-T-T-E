# Ghidra Installer for CHARLOTTE

This script automates the installation of Ghidra (official release) and JDK 21 for Windows and Linux.

## Usage
- Windows: Run in PowerShell as administrator
- Linux: Run in bash shell as root or with sudo

---

## Windows (PowerShell)

```powershell
# ghidra_installer.ps1
$ErrorActionPreference = 'Stop'

Write-Host "[+] Installing JDK 21..."
winget install --id Oracle.JavaRuntimeEnvironment.21 --accept-package-agreements --accept-source-agreements

$ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20240501.zip"
$ghidraZip = "$env:TEMP\ghidra_10.4_PUBLIC.zip"
$ghidraDir = "C:\ghidra_10.4_PUBLIC"

Write-Host "[+] Downloading Ghidra..."
Invoke-WebRequest -Uri $ghidraUrl -OutFile $ghidraZip

Write-Host "[+] Extracting Ghidra..."
Expand-Archive -Path $ghidraZip -DestinationPath "C:\"

Write-Host "[+] Setting GHIDRA_PATH environment variable..."
[System.Environment]::SetEnvironmentVariable('GHIDRA_PATH', $ghidraDir, [System.EnvironmentVariableTarget]::Machine)

Write-Host "[+] Installation complete. Launch with: C:\ghidra_10.4_PUBLIC\ghidraRun.bat"
```

---

## Linux (Bash)

```bash
# ghidra_installer.sh
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
```

---

## Manual Steps (if needed)
- Download JDK 21 (64-bit) from Oracle or OpenJDK
- Download Ghidra release from https://ghidra-sre.org/
- Extract to C:\ghidra_10.4_PUBLIC (Windows) or /opt/ghidra_10.4_PUBLIC (Linux)
- Set GHIDRA_PATH environment variable
- Launch with ghidraRun(.bat)

For building from source, see the official Ghidra Developer Guide.
