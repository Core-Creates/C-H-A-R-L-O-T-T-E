#!/bin/bash
set -e

# Detect operating system
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
else
    echo "[!] Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "[CHARLOTTE Installer] Installing OWASP ZAP on $OS..."

# OWASP ZAP installation variables
ZAP_VERSION="2.14.0"
ZAP_DIR="/opt/zaproxy"
ZAP_URL=""
ZAP_ARCHIVE=""

# Set download URL and archive name based on OS
if [[ "$OS" == "linux" ]]; then
    ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
    ZAP_ARCHIVE="/tmp/ZAP_${ZAP_VERSION}_Linux.tar.gz"
elif [[ "$OS" == "macos" ]]; then
    ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_macOS.tar.gz"
    ZAP_ARCHIVE="/tmp/ZAP_${ZAP_VERSION}_macOS.tar.gz"
fi

# Check if ZAP is already installed
if [[ -d "$ZAP_DIR" && -f "$ZAP_DIR/zap.sh" ]]; then
    echo "[+] OWASP ZAP is already installed at $ZAP_DIR"
    echo "[*] Checking if ZAP is in PATH..."
    
    # Check if ZAP is in PATH
    if command -v zap.sh &> /dev/null; then
        echo "[+] OWASP ZAP is already in PATH"
        echo "[✓] Installation complete. You can launch ZAP with: zap.sh"
        exit 0
    else
        echo "[*] Adding OWASP ZAP to PATH..."
        
        # Add to PATH in shell profile
        if [[ "$OS" == "linux" ]]; then
            if ! grep -q "export PATH.*zaproxy" /etc/environment; then
                echo "PATH=\"\$PATH:$ZAP_DIR\"" | sudo tee -a /etc/environment
            fi
        elif [[ "$OS" == "macos" ]]; then
            # Add to .zshrc or .bash_profile
            if [[ -f "$HOME/.zshrc" ]]; then
                if ! grep -q "export PATH.*zaproxy" "$HOME/.zshrc"; then
                    echo "export PATH=\"\$PATH:$ZAP_DIR\"" >> "$HOME/.zshrc"
                fi
            elif [[ -f "$HOME/.bash_profile" ]]; then
                if ! grep -q "export PATH.*zaproxy" "$HOME/.bash_profile"; then
                    echo "export PATH=\"\$PATH:$ZAP_DIR\"" >> "$HOME/.bash_profile"
                fi
            else
                echo "export PATH=\"\$PATH:$ZAP_DIR\"" >> "$HOME/.zshrc"
            fi
        fi
        
        echo "[+] OWASP ZAP added to PATH"
        echo "[✓] Installation complete. You can launch ZAP with: zap.sh"
        echo "[*] Note: You may need to restart your terminal for PATH changes to take effect"
        exit 0
    fi
fi

# Create installation directory
echo "[+] Creating installation directory..."
sudo mkdir -p "$ZAP_DIR"

# Download OWASP ZAP
echo "[+] Downloading OWASP ZAP..."
if ! wget -O "$ZAP_ARCHIVE" "$ZAP_URL"; then
    echo "[!] Failed to download OWASP ZAP"
    echo "[*] Please visit https://www.zaproxy.org/download/ to download manually"
    exit 1
fi

# Extract OWASP ZAP
echo "[+] Extracting OWASP ZAP..."
if ! sudo tar -xzf "$ZAP_ARCHIVE" -C /opt/; then
    echo "[!] Failed to extract OWASP ZAP"
    exit 1
fi

# Set proper permissions
echo "[+] Setting permissions..."
sudo chmod +x "$ZAP_DIR/zap.sh"

# Add to PATH
echo "[+] Adding OWASP ZAP to PATH..."
if [[ "$OS" == "linux" ]]; then
    if ! grep -q "export PATH.*zaproxy" /etc/environment; then
        echo "PATH=\"\$PATH:$ZAP_DIR\"" | sudo tee -a /etc/environment
    fi
elif [[ "$OS" == "macos" ]]; then
    # Add to .zshrc or .bash_profile
    if [[ -f "$HOME/.zshrc" ]]; then
        if ! grep -q "export PATH.*zaproxy" "$HOME/.zshrc"; then
            echo "export PATH=\"\$PATH:$ZAP_DIR\"" >> "$HOME/.zshrc"
        fi
    elif [[ -f "$HOME/.bash_profile" ]]; then
        if ! grep -q "export PATH.*zaproxy" "$HOME/.bash_profile"; then
            echo "export PATH=\"\$PATH:$ZAP_DIR\"" >> "$HOME/.bash_profile"
        fi
    else
        echo "export PATH=\"\$PATH:$ZAP_DIR\"" >> "$HOME/.zshrc"
    fi
fi

# Clean up archive
if [[ -f "$ZAP_ARCHIVE" ]]; then
    rm "$ZAP_ARCHIVE"
    echo "[+] Cleaned up archive file"
fi

# Verify installation
if [[ -f "$ZAP_DIR/zap.sh" ]]; then
    echo "[✓] OWASP ZAP installed successfully at $ZAP_DIR"
    echo "[✓] OWASP ZAP added to PATH"
    echo "[✓] You can launch ZAP with: zap.sh"
    echo "[*] Note: You may need to restart your terminal for PATH changes to take effect"
else
    echo "[!] Installation verification failed. ZAP may not be properly installed."
    exit 1
fi