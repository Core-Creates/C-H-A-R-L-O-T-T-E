import os
import sys
import platform
import subprocess
import webbrowser

def is_windows():
    return platform.system() == "Windows"

def elevate_windows():
    powershell_script = os.path.join(os.path.dirname(__file__), "zap_installer.ps1")
    if not os.path.exists(powershell_script):
        print(f"[!] PowerShell script not found: {powershell_script}")
        sys.exit(1)

    cmd = [
        "powershell",
        "-Command",
        f'Start-Process powershell -ArgumentList \'-NoProfile -ExecutionPolicy Bypass -File "{powershell_script}"\' -Verb RunAs'
    ]
    print("[*] Launching OWASP ZAP installer PowerShell script with admin privileges...")
    subprocess.run(" ".join(cmd), shell=True)

def run_linux_installer():
    script_path = os.path.abspath("zap_installer.sh")
    if not os.path.exists(script_path):
        print(f"[!] Bash installer script not found: {script_path}")
        sys.exit(1)

    print("[*] Running OWASP ZAP bash installer...")
    subprocess.run(["bash", script_path], check=True)

def run_macos_installer():
    script_path = os.path.abspath("zap_installer.sh")
    if not os.path.exists(script_path):
        print(f"[!] Bash installer script not found: {script_path}")
        sys.exit(1)

    print("[*] Running OWASP ZAP macOS installer...")
    subprocess.run(["bash", script_path], check=True)

def check_java_requirement():
    """Check if Java 11+ is available for ZAP"""
    try:
        output = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True)
        import re
        match = re.search(r'version "(\d+)', output)
        if match:
            version = int(match.group(1))
            return version >= 11
    except Exception as e:
        print(f"[!] Failed to check Java version: {e}")
    return False

def main():
    print("[CHARLOTTE Installer] OWASP ZAP Installation")
    print("=" * 50)
    
    # Check Java requirement
    print("[*] Checking for Java 11+ requirement...")
    if not check_java_requirement():
        print("[!] Java 11+ not detected. OWASP ZAP requires Java 11 or higher.")
        print("[*] Opening Java download page...")
        webbrowser.open("https://adoptium.net/temurin/releases")
        input("[*] Press Enter after Java installation is complete...")
        
        # Re-check after user input
        if not check_java_requirement():
            print("[!] Java 11+ still not detected. Please install Java and try again.")
            sys.exit(1)
    else:
        print("[+] Java 11+ detected.")

    print("[CHARLOTTE Installer] Detecting operating system...")
    system = platform.system()
    
    if system == "Windows":
        print("[+] Windows detected.")
        elevate_windows()
    elif system == "Linux":
        print("[+] Linux detected.")
        try:
            run_linux_installer()
            print("[CHARLOTTE Installer] OWASP ZAP installation completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[!] OWASP ZAP installer script failed with error: {e}")
            sys.exit(1)
    elif system == "Darwin":
        print("[+] macOS detected.")
        try:
            run_macos_installer()
            print("[CHARLOTTE Installer] OWASP ZAP installation completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[!] OWASP ZAP installer script failed with error: {e}")
            sys.exit(1)
    else:
        print(f"[!] Unsupported operating system: {system}")
        print("[*] Please visit https://www.zaproxy.org/download/ to download OWASP ZAP manually.")
        sys.exit(1)

if __name__ == "__main__":
    main()