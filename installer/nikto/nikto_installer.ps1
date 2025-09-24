# CHARLOTTE Nikto Installer PowerShell Script
# 
# This script helps Windows users install Nikto web vulnerability scanner
# for use with the CHARLOTTE Nikto plugin.
#
# Note: Nikto is primarily a Unix/Linux tool. This script provides
# guidance for Windows users, including WSL installation.

param(
    [switch]$Help
)

# Colors for output
$ErrorColor = "Red"
$WarningColor = "Yellow"
$InfoColor = "Cyan"
$SuccessColor = "Green"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor $InfoColor
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor $SuccessColor
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor $WarningColor
}

function Write-Error {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor $ErrorColor
}

function Show-Help {
    Write-Host "CHARLOTTE Nikto Installer for Windows" -ForegroundColor $InfoColor
    Write-Host ""
    Write-Host "This installer helps Windows users install Nikto web vulnerability scanner."
    Write-Host "Since Nikto is primarily a Unix/Linux tool, this script provides guidance for:"
    Write-Host "1. Installing WSL (Windows Subsystem for Linux)"
    Write-Host "2. Installing Nikto within WSL"
    Write-Host "3. Manual installation options"
    Write-Host ""
    Write-Host "Usage: .\nikto_installer.ps1"
    Write-Host "       .\nikto_installer.ps1 -Help"
}

function Test-WSLInstalled {
    try {
        $wslVersion = wsl --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }
    catch {
        # WSL not found
    }
    
    # Check for older WSL versions
    try {
        $wslStatus = wsl --status 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }
    catch {
        # WSL not found
    }
    
    return $false
}

function Install-WSL {
    Write-Status "Installing WSL (Windows Subsystem for Linux)..."
    
    try {
        # Enable WSL feature
        Write-Status "Enabling WSL feature..."
        dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
        
        # Enable Virtual Machine Platform
        Write-Status "Enabling Virtual Machine Platform..."
        dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
        
        Write-Success "WSL features enabled. Please restart your computer and run this script again."
        Write-Warning "After restart, you'll need to install a Linux distribution from Microsoft Store."
        return $true
    }
    catch {
        Write-Error "Failed to enable WSL features: $_"
        return $false
    }
}

function Install-NiktoInWSL {
    Write-Status "Installing Nikto in WSL..."
    
    $installScript = @"
#!/bin/bash
# Install Nikto in WSL
if command -v apt &> /dev/null; then
    echo 'Installing Nikto via apt...'
    sudo apt update
    sudo apt install -y nikto
elif command -v yum &> /dev/null; then
    echo 'Installing Nikto via yum...'
    sudo yum install -y nikto
elif command -v dnf &> /dev/null; then
    echo 'Installing Nikto via dnf...'
    sudo dnf install -y nikto
else
    echo 'No supported package manager found. Please install Nikto manually.'
    exit 1
fi

# Verify installation
if command -v nikto &> /dev/null; then
    echo 'Nikto installed successfully!'
    nikto -Version
else
    echo 'Nikto installation failed.'
    exit 1
fi
"@
    
    # Create temporary script
    $tempScript = [System.IO.Path]::GetTempFileName() + ".sh"
    $installScript | Out-File -FilePath $tempScript -Encoding UTF8
    
    try {
        # Execute script in WSL
        wsl bash $tempScript
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Nikto installed successfully in WSL!"
            return $true
        } else {
            Write-Error "Failed to install Nikto in WSL"
            return $false
        }
    }
    catch {
        Write-Error "Failed to execute installation script in WSL: $_"
        return $false
    }
    finally {
        # Clean up temporary script
        if (Test-Path $tempScript) {
            Remove-Item $tempScript -Force
        }
    }
}

function Show-ManualInstallInstructions {
    Write-Status "Manual installation options for Windows:"
    Write-Host ""
    Write-Host "Option 1: Use WSL (Recommended)"
    Write-Host "1. Install WSL: wsl --install"
    Write-Host "2. Install a Linux distribution from Microsoft Store"
    Write-Host "3. Install Nikto in WSL: sudo apt install nikto"
    Write-Host ""
    Write-Host "Option 2: Use Docker"
    Write-Host "1. Install Docker Desktop for Windows"
    Write-Host "2. Run Nikto in container: docker run --rm sullo/nikto -h"
    Write-Host ""
    Write-Host "Option 3: Use Git Bash or Cygwin"
    Write-Host "1. Install Git for Windows (includes Git Bash)"
    Write-Host "2. Download Nikto from: https://github.com/sullo/nikto"
    Write-Host "3. Install Perl and required modules"
    Write-Host "4. Run Nikto from Git Bash"
    Write-Host ""
    Write-Host "Option 4: Use Windows Subsystem for Linux (WSL)"
    Write-Host "1. Enable WSL: dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all"
    Write-Host "2. Install Ubuntu or another Linux distribution"
    Write-Host "3. Install Nikto: sudo apt install nikto"
}

function Test-NiktoInWSL {
    try {
        $niktoVersion = wsl nikto -Version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Nikto is available in WSL: $niktoVersion"
            return $true
        }
    }
    catch {
        # Nikto not found in WSL
    }
    
    return $false
}

function Main {
    if ($Help) {
        Show-Help
        return
    }
    
    Write-Host "============================================================" -ForegroundColor $InfoColor
    Write-Host "CHARLOTTE Nikto Installer for Windows" -ForegroundColor $InfoColor
    Write-Host "============================================================" -ForegroundColor $InfoColor
    Write-Host "This installer helps Windows users install Nikto web vulnerability scanner"
    Write-Host "for use with the CHARLOTTE Nikto plugin."
    Write-Host ""
    
    # Check if Nikto is already available in WSL
    if (Test-NiktoInWSL) {
        Write-Success "Nikto is already available in WSL and ready to use!"
        return
    }
    
    # Check if WSL is installed
    if (Test-WSLInstalled) {
        Write-Success "WSL is already installed"
        
        # Try to install Nikto in WSL
        if (Install-NiktoInWSL) {
            return
        } else {
            Write-Warning "Failed to install Nikto in WSL. Showing manual installation options..."
            Show-ManualInstallInstructions
        }
    } else {
        Write-Status "WSL not found. Installing WSL..."
        
        if (Install-WSL) {
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor $InfoColor
            Write-Host "WSL installation initiated!"
            Write-Host "Please restart your computer and run this script again."
            Write-Host "After restart, install a Linux distribution from Microsoft Store."
            Write-Host "============================================================" -ForegroundColor $InfoColor
        } else {
            Write-Error "Failed to install WSL. Showing manual installation options..."
            Show-ManualInstallInstructions
        }
    }
}

# Run main function
Main
