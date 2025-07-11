import os
import sys
import platform
import subprocess
import webbrowser
from unittest import result

def is_windows():
    return platform.system() == "Windows"

def elevate_windows():
    powershell_script = os.path.abspath("ghidra_installer.ps1")
    cmd = [
        "powershell",
        "-Command",
        f'Start-Process powershell -ArgumentList \'-NoProfile -ExecutionPolicy Bypass -File "{powershell_script}"\' -Verb RunAs'
    ]
    subprocess.run(" ".join(cmd), shell=True)

def run_linux_installer():
    script_path = os.path.abspath("./ghidra_installer.sh")
    subprocess.run(["bash", script_path], check=True)

def has_jdk_21_or_higher():
    try:
        output = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True)
        # Look for version string like '"21.0.1"' or higher
        import re
        match = re.search(r'version "(\d+)', output)
        if match:
            version = int(match.group(1))
            return version >= 21
    except Exception:
        pass
    return False

if __name__ == "__main__":
    if not has_jdk_21_or_higher():
        print("[CHARLOTTE Installer] No JDK 21+ detected. Opening Adoptium Temurin JDK download page...")
        webbrowser.open("https://adoptium.net/temurin/releases")
    else:
        print("[CHARLOTTE Installer] JDK 21+ detected.")

    print("[CHARLOTTE Installer] Detecting OS...")
    if is_windows():
        print("[+] Detected Windows. Elevating PowerShell...")
        elevate_windows()
    else:
        print("[+] Detected Linux/macOS. Running bash installer...")
        run_linux_installer()
        print(f"[CHARLOTTE] Ghidra headless analysis completed successfully:\n{result.stdout}")
