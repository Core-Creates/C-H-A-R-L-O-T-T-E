# google_dorks.py
# Simple starter stub for working with Exploit-DB's Google Hacking Database (GHDB)

import requests
from bs4 import BeautifulSoup

def google_dorks():
    """
    Fetch Google Dorks from Exploit-DB's Google Hacking Database.
    Returns a list of dictionaries with title + URL.
    """
    db = []
    database_url = "https://www.exploit-db.com/google-hacking-database"

    try:
        # Get the page
        response = requests.get(database_url, timeout=10)
        response.raise_for_status()

        # Parse HTML
        soup = BeautifulSoup(response.text, "html.parser")
        rows = soup.find_all("tr")

        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 2:
                link = cols[1].find("a")
                if link:
                    db.append({
                        "title": link.get_text(strip=True),
                        "url": "https://www.exploit-db.com" + link["href"]
                    })

    except Exception as e:
        print(f"[!] Error fetching dorks: {e}")

    return db

if __name__ == "__main__":
    dorks = google_dorks()
    for d in dorks[:10]:  # show only first 10 for sanity
        print(f"{d['title']}: {d['url']}")
# Optional compatibility entrypoint
def run_plugin(args=None):
    return google_dorks()