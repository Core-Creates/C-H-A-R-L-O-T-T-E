import webbrowser


def get_cobalt_strike_url():
    # Always use the main download page for reliability
    return "https://www.cobaltstrike.com/download/"


if __name__ == "__main__":
    url = get_cobalt_strike_url()
    print("[CHARLOTTE Installer] Must have license key to download Cobalt Strike.")
    print(f"[CHARLOTTE Installer] Opening Cobalt Strike download: {url}")
    webbrowser.open(url)
