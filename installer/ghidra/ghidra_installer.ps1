# Ensure script runs as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "[!] Please run this script as Administrator." -ForegroundColor Red
    exit
}

$ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20240501.zip"
$ghidraZip = "$env:TEMP\ghidra_10.4.zip"
$ghidraDir = "C:\ghidra_10.4_PUBLIC"

if (!(Test-Path $ghidraDir)) {
    Write-Host "[+] Downloading Ghidra..."
    Invoke-WebRequest -Uri $ghidraUrl -OutFile $ghidraZip

    Write-Host "[+] Extracting Ghidra..."
    Expand-Archive -Path $ghidraZip -DestinationPath "C:\"
}

# Set GHIDRA_PATH system environment variable
[Environment]::SetEnvironmentVariable("GHIDRA_PATH", $ghidraDir, [System.EnvironmentVariableTarget]::Machine)

Write-Host "[+] Ghidra installed at $ghidraDir"
Write-Host "[+] GHIDRA_PATH environment variable set."
Write-Host "[✓] You can launch it with: C:\ghidra_10.4_PUBLIC\ghidraRun.bat"

