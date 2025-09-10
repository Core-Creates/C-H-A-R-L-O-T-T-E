#!/usr/bin/env python3
"""
CHARLOTTE Nikto Installer

This installer helps users install Nikto web vulnerability scanner
for use with the CHARLOTTE Nikto plugin.

Supported platforms:
- macOS (via Homebrew)
- Ubuntu/Debian (via apt)
- CentOS/RHEL (via yum/dnf)
- Manual installation from GitHub

Author: CHARLOTTE Security Framework
"""

import os
import sys
import platform
import subprocess
import webbrowser
import shutil
from pathlib import Path

# Ensure project root is in sys.path for package imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

def is_windows():
    return platform.system() == "Windows"

def is_macos():
    return platform.system() == "Darwin"

def is_linux():
    return platform.system() == "Linux"

def check_nikto_installed():
    """Check if Nikto is already installed and accessible."""
    try:
        result = subprocess.run(['nikto', '-Version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_info = result.stdout.strip()
            print(f"[+] Nikto is already installed: {version_info}")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        pass
    
    # Also check common installation paths
    common_paths = [
        '/usr/bin/nikto',
        '/usr/local/bin/nikto',
        '/opt/nikto/nikto.pl',
        '/usr/share/nikto/nikto.pl'
    ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(f"[+] Nikto found at: {path}")
            return True
    
    return False

def check_homebrew():
    """Check if Homebrew is installed on macOS."""
    try:
        subprocess.run(['brew', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_via_homebrew():
    """Install Nikto via Homebrew on macOS."""
    print("[*] Installing Nikto via Homebrew...")
    try:
        subprocess.run(['brew', 'install', 'nikto'], check=True)
        print("[+] Nikto installed successfully via Homebrew!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Homebrew installation failed: {e}")
        return False

def check_apt():
    """Check if apt package manager is available."""
    try:
        subprocess.run(['apt', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_via_apt():
    """Install Nikto via apt on Ubuntu/Debian."""
    print("[*] Installing Nikto via apt...")
    try:
        # Update package list first
        subprocess.run(['sudo', 'apt', 'update'], check=True)
        subprocess.run(['sudo', 'apt', 'install', '-y', 'nikto'], check=True)
        print("[+] Nikto installed successfully via apt!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] apt installation failed: {e}")
        return False

def check_yum():
    """Check if yum or dnf package manager is available."""
    for pkg_mgr in ['dnf', 'yum']:
        try:
            subprocess.run([pkg_mgr, '--version'], capture_output=True, check=True)
            return pkg_mgr
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None

def install_via_yum(pkg_mgr):
    """Install Nikto via yum/dnf on CentOS/RHEL."""
    print(f"[*] Installing Nikto via {pkg_mgr}...")
    try:
        if pkg_mgr == 'dnf':
            subprocess.run(['sudo', 'dnf', 'install', '-y', 'nikto'], check=True)
        else:
            subprocess.run(['sudo', 'yum', 'install', '-y', 'nikto'], check=True)
        print(f"[+] Nikto installed successfully via {pkg_mgr}!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] {pkg_mgr} installation failed: {e}")
        return False

def open_manual_install():
    """Open browser to Nikto GitHub page for manual installation."""
    print("[*] Opening Nikto GitHub page for manual installation...")
    webbrowser.open("https://github.com/sullo/nikto")
    print("\n[MANUAL INSTALLATION INSTRUCTIONS]")
    print("1. Download Nikto from the GitHub page that just opened")
    print("2. Extract the archive to a directory (e.g., /opt/nikto)")
    print("3. Make sure nikto.pl is executable: chmod +x nikto.pl")
    print("4. Add the directory to your PATH or create a symlink:")
    print("   sudo ln -s /path/to/nikto/nikto.pl /usr/local/bin/nikto")
    print("5. Install Perl dependencies if needed:")
    print("   - cpan Net::SSLeay")
    print("   - cpan LWP::UserAgent")
    print("   - cpan HTTP::Cookies")

def check_perl_dependencies():
    """Check if required Perl modules are available."""
    required_modules = ['Net::SSLeay', 'LWP::UserAgent', 'HTTP::Cookies']
    missing_modules = []
    
    for module in required_modules:
        try:
            result = subprocess.run(['perl', '-M' + module, '-e', '1'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                missing_modules.append(module)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_modules.append(module)
    
    if missing_modules:
        print(f"[!] Missing Perl modules: {', '.join(missing_modules)}")
        print("[*] Install them with: cpan " + " ".join(missing_modules))
        return False
    
    print("[+] All required Perl modules are available")
    return True

def main():
    """Main installer function."""
    print("=" * 60)
    print("CHARLOTTE Nikto Installer")
    print("=" * 60)
    print("This installer will help you install Nikto web vulnerability scanner")
    print("for use with the CHARLOTTE Nikto plugin.\n")
    
    # Check if Nikto is already installed
    if check_nikto_installed():
        print("[+] Nikto is already installed and ready to use!")
        return
    
    print("[*] Nikto not found. Proceeding with installation...\n")
    
    # Detect operating system and install accordingly
    if is_macos():
        print("[+] macOS detected")
        if check_homebrew():
            print("[+] Homebrew found")
            if install_via_homebrew():
                return
        else:
            print("[!] Homebrew not found. Please install Homebrew first:")
            print("    /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
            print("\n[*] Opening manual installation page as fallback...")
            open_manual_install()
    
    elif is_linux():
        print("[+] Linux detected")
        
        # Try apt first (Ubuntu/Debian)
        if check_apt():
            print("[+] apt package manager found")
            if install_via_apt():
                return
        
        # Try yum/dnf (CentOS/RHEL)
        pkg_mgr = check_yum()
        if pkg_mgr:
            print(f"[+] {pkg_mgr} package manager found")
            if install_via_yum(pkg_mgr):
                return
        
        # Fallback to manual installation
        print("[!] No supported package manager found")
        print("[*] Opening manual installation page...")
        open_manual_install()
    
    elif is_windows():
        print("[+] Windows detected")
        print("[!] Nikto is primarily a Unix/Linux tool")
        print("[*] Consider using WSL (Windows Subsystem for Linux) or opening manual installation page...")
        open_manual_install()
    
    else:
        print(f"[!] Unsupported platform: {platform.system()}")
        print("[*] Opening manual installation page...")
        open_manual_install()
    
    # Check Perl dependencies
    print("\n[*] Checking Perl dependencies...")
    if not check_perl_dependencies():
        print("[!] Some Perl modules are missing. Please install them before using Nikto.")
    
    print("\n" + "=" * 60)
    print("Installation process completed!")
    print("Please verify Nikto installation by running: nikto -Version")
    print("=" * 60)

if __name__ == "__main__":
    main()
