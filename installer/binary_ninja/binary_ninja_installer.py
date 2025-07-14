
import platform
import webbrowser

def get_binary_ninja_free_url():
    # Always use the main download page for reliability
    return "https://binary.ninja/free/"


if __name__ == "__main__":
    url = get_binary_ninja_free_url()
    print(f"[CHARLOTTE Installer] Opening Binary Ninja download: {url}")
    webbrowser.open(url)
