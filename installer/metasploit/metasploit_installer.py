import platform
import webbrowser

def get_metasploit_url():
    if platform.system() == "Windows":
        # Use the main download page for Windows
        return "https://windows.metasploit.com/metasploitframework-latest.msi"
    elif platform.system() == "Linux":
        # Use the main download page for Linux
        return "https://osx.metasploit.com/metasploitframework-latest.pkg"
    elif platform.system() == "Darwin":
        # Use the main download page for macOS
        return "https://osx.metasploit.com/metasploit-framework-latest.pkg"
    else:
        # Fallback to the main Metasploit download page
        print("[!] Unsupported platform for Metasploit download.")
        return "https://www.metasploit.com/download/"

if __name__ == "__main__":
    url = get_metasploit_url()
    print(f"[CHARLOTTE Installer] Opening Metasploit download: {url}")
    webbrowser.open(url)