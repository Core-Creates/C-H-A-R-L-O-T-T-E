import platform
import subprocess
import os
import sys

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

if __name__ == "__main__":
    print("[CHARLOTTE Installer] Detecting OS...")
    if is_windows():
        print("[+] Detected Windows. Elevating PowerShell...")
        elevate_windows()
    else:
        print("[+] Detected Linux/macOS. Running bash installer...")
        run_linux_installer()
        print(f"[CHARLOTTE] Ghidra headless analysis completed successfully:\n{result.stdout}")
