import subprocess
import os
import time
import platform
from py4j.java_gateway import JavaGateway, GatewayParameters

class BurpIntegration:
    def __init__(self, host="127.0.0.1", port=25333):
        self.gateway = None
        self.java_process = None
        self.host = host
        self.port = port

        self.launch_java_service()
        self.connect_to_gateway()

    def launch_java_service(self):
        scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
        system = platform.system()

        if system == "Windows":
            launch_script = os.path.join(scripts_dir, "launch_burp_service.ps1")
            if not os.path.exists(launch_script):
                raise FileNotFoundError(f"[!] Could not find PowerShell script at {launch_script}")
            print("[*] Detected Windows. Launching Burp Java plugin using PowerShell...")
            self.java_process = subprocess.Popen(
                ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", launch_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        else:
            launch_script = os.path.join(scripts_dir, "launch_burp_service.sh")
            if not os.path.exists(launch_script):
                raise FileNotFoundError(f"[!] Could not find shell script at {launch_script}")
            print("[*] Detected Linux/macOS. Launching Burp Java plugin using bash...")
            self.java_process = subprocess.Popen(
                ["bash", launch_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

        # Optional: wait for Py4J server to initialize
        time.sleep(2)

    def connect_to_gateway(self):
        try:
            self.gateway = JavaGateway(gateway_parameters=GatewayParameters(address=self.host, port=self.port))
            self.helper = self.gateway.entry_point
            print("[*] Connected to BurpHelper via Py4J.")
        except Exception as e:
            print(f"[!] Failed to connect to BurpHelper: {e}")
            raise

    def scan_url(self, url):
        return self.helper.scanUrl(url)

    def shutdown(self):
        if self.gateway:
            self.gateway.shutdown()
        if self.java_process:
            self.java_process.terminate()
            print("[*] Burp Java service terminated.")

# Demo usage
if __name__ == "__main__":
    burp = BurpIntegration()
    try:
        results = burp.scan_url("http://example.com")
        print(f"Scan Results: {results}")
    finally:
        burp.shutdown()
