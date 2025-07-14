import os
import sys
import platform
import subprocess
import webbrowser

def is_windows():
    return platform.system() == "Windows"

def elevate_windows():
    powershell_script = os.path.abspath("ghidra_installer.ps1")
    if not os.path.exists(powershell_script):
        print(f"[!] PowerShell script not found: {powershell_script}")
        sys.exit(1)

    cmd = [
        "powershell",
        "-Command",
        f'Start-Process powershell -ArgumentList \'-NoProfile -ExecutionPolicy Bypass -File "{powershell_script}"\' -Verb RunAs'
    ]
    print("[*] Launching Ghidra installer PowerShell script with admin privileges...")
    subprocess.run(" ".join(cmd), shell=True)

def run_linux_installer():
    script_path = os.path.abspath("ghidra_installer.sh")
    if not os.path.exists(script_path):
        print(f"[!] Bash installer script not found: {script_path}")
        sys.exit(1)

    print("[*] Running Ghidra bash installer...")
    subprocess.run(["bash", script_path], check=True)

def has_jdk_21_or_higher():
    try:
        output = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True)
        import re
        match = re.search(r'version "(\d+)', output)
        if match:
            version = int(match.group(1))
            return version >= 21
    except Exception as e:
        print(f"[!] Failed to check JDK version: {e}")
    return False

def main():
    print("[CHARLOTTE Installer] Checking for JDK 21+...")
    if not has_jdk_21_or_higher():
        print("[!] JDK 21+ not detected. Opening Temurin download page...")
        webbrowser.open("https://adoptium.net/temurin/releases")
        input("[*] Press Enter after JDK installation is complete...")
    else:
        print("[+] JDK 21+ detected.")

    print("[CHARLOTTE Installer] Detecting operating system...")
    if is_windows():
        print("[+] Windows detected.")
        elevate_windows()
    else:
        print("[+] Linux/macOS detected.")
        try:
            run_linux_installer()
            print("[CHARLOTTE Installer] Ghidra installation completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[!] Ghidra installer script failed with error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
# Ensure project root is in sys.path for package imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# This allows importing modules from the core package  