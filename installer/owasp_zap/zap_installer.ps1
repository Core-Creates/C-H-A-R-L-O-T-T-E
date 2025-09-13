# Ensure script runs as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "[!] Please run this script as Administrator." -ForegroundColor Red
    exit
}

# OWASP ZAP installation variables
$zapUrl = "https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_windows.exe"
$zapInstaller = "$env:TEMP\ZAP_2.14.0_windows.exe"
$zapDir = "C:\Program Files\OWASP\Zed Attack Proxy"

Write-Host "[CHARLOTTE Installer] Installing OWASP ZAP on Windows..." -ForegroundColor Green

# Check if ZAP is already installed
if (Test-Path "$zapDir\zap.bat") {
    Write-Host "[+] OWASP ZAP is already installed at $zapDir" -ForegroundColor Yellow
    Write-Host "[*] Checking if ZAP is in PATH..."
    
    # Check if ZAP is in PATH
    $zapInPath = $env:PATH -split ';' | Where-Object { $_ -like "*OWASP*ZAP*" }
    if ($zapInPath) {
        Write-Host "[+] OWASP ZAP is already in PATH" -ForegroundColor Green
        Write-Host "[✓] Installation complete. You can launch ZAP with: zap.bat"
        exit 0
    } else {
        Write-Host "[*] Adding OWASP ZAP to PATH..." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable("PATH", "$env:PATH;$zapDir", [System.EnvironmentVariableTarget]::Machine)
        Write-Host "[+] OWASP ZAP added to PATH" -ForegroundColor Green
        Write-Host "[✓] Installation complete. You can launch ZAP with: zap.bat"
        exit 0
    }
}

# Download OWASP ZAP installer
Write-Host "[+] Downloading OWASP ZAP installer..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $zapUrl -OutFile $zapInstaller -UseBasicParsing
    Write-Host "[+] Download completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to download OWASP ZAP installer: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[*] Please visit https://www.zaproxy.org/download/ to download manually" -ForegroundColor Yellow
    exit 1
}

# Install OWASP ZAP silently
Write-Host "[+] Installing OWASP ZAP..." -ForegroundColor Yellow
try {
    $installArgs = "/S /D=`"$zapDir`""
    Start-Process -FilePath $zapInstaller -ArgumentList $installArgs -Wait
    Write-Host "[+] Installation completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to install OWASP ZAP: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Add ZAP to PATH
Write-Host "[+] Adding OWASP ZAP to PATH..." -ForegroundColor Yellow
try {
    [Environment]::SetEnvironmentVariable("PATH", "$env:PATH;$zapDir", [System.EnvironmentVariableTarget]::Machine)
    Write-Host "[+] OWASP ZAP added to PATH" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to add OWASP ZAP to PATH: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[*] You may need to manually add $zapDir to your PATH" -ForegroundColor Yellow
}

# Clean up installer
if (Test-Path $zapInstaller) {
    Remove-Item $zapInstaller -Force
    Write-Host "[+] Cleaned up installer file" -ForegroundColor Green
}

# Verify installation
if (Test-Path "$zapDir\zap.bat") {
    Write-Host "[✓] OWASP ZAP installed successfully at $zapDir" -ForegroundColor Green
    Write-Host "[✓] OWASP ZAP added to PATH" -ForegroundColor Green
    Write-Host "[✓] You can launch ZAP with: zap.bat" -ForegroundColor Green
    Write-Host "[*] Note: You may need to restart your terminal for PATH changes to take effect" -ForegroundColor Yellow
} else {
    Write-Host "[!] Installation verification failed. ZAP may not be properly installed." -ForegroundColor Red
    exit 1
}