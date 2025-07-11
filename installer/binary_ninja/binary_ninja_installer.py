
import platform
import webbrowser

def get_binary_ninja_free_url():
    system = platform.system()
    if system == "Windows":
        # Windows installer direct link (as of July 2025)
        return "https://cdn.binary.ninja/installers/BinaryNinja-free-windows.exe"
    elif system == "Darwin":
        # macOS installer direct link
        return "https://cdn.binary.ninja/installers/BinaryNinja-free-macos.dmg"
    elif system == "Linux":
        # Linux installer direct link
        return "https://cdn.binary.ninja/installers/BinaryNinja-free-linux.zip"
    else:
        # Fallback to main download page
        return "https://binary.ninja/free/"

if __name__ == "__main__":
    url = get_binary_ninja_free_url()
    print(f"[CHARLOTTE Installer] Opening Binary Ninja download: {url}")
    webbrowser.open(url)
