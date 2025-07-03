# launch_burp_service.ps1
# Usage: .\launch_burp_service.ps1
# Launch the Burp plugin Java service

$ErrorActionPreference = "Stop"

$jarFile = Join-Path (Get-Location) "dist\burp-helper-1.0.0.jar"
$py4jJar = Join-Path (Get-Location) "libs\py4j0.10.9.7.jar"  # Adjust path if needed

if (-Not (Test-Path $jarFile)) {
    Write-Host "[!] JAR not found. Run 'gradle build' first." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Launching BurpHelper service..." -ForegroundColor Cyan
$process = Start-Process "java" -ArgumentList "-cp `"$jarFile;$py4jJar`" com.charlotte.BurpHelper" -NoNewWindow -Wait -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "[*] BurpHelper service started successfully." -ForegroundColor Green
} else {
    Write-Host "[!] Failed to start BurpHelper service." -ForegroundColor Red
    exit 1
}
