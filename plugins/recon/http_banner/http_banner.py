# plugins/recon/http_banner.py
from __future__ import annotations

import os
import socket
import ssl
import json
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Paths (prefer utils.paths; safe fallback)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from utils.paths import p, ensure_parent, display_path
except Exception:

    def p(*parts) -> str:
        return os.path.abspath(os.path.join(*parts))

    def ensure_parent(*parts) -> str:
        path = p(*parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def display_path(path: str, base: str | None = None) -> str:
        return str(path).replace("\\", "/")


DEFAULT_PORTS = [80, 8080, 8000, 8443, 443]
TIMEOUT_S = float(os.environ.get("HTTP_BANNER_TIMEOUT_S", "4.0"))


def _head_request(host: str, port: int, use_tls: bool) -> str:
    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    with socket.create_connection((host, port), timeout=TIMEOUT_S) as sock:
        if use_tls:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.sendall(req)
                return ss.recv(4096).decode(errors="replace")
        else:
            sock.sendall(req)
            return sock.recv(4096).decode(errors="replace")


def run_banner_grab(host: str, ports: list[int], outdir: str) -> dict[str, Any]:
    result: dict[str, Any] = {"host": host, "banners": []}
    for port in ports:
        use_tls = port == 443 or port == 8443
        try:
            banner = _head_request(host, port, use_tls)
            path = ensure_parent(outdir, f"http_banner_{host}_{port}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(banner)
            print(f"[HTTP] Banner for {host}:{port} saved to {display_path(path)}")
            result["banners"].append({"port": port, "tls": use_tls, "path": path})
        except Exception as e:
            print(f"[!] Banner grab failed for {host}:{port} — {e}")
    return result


def run_plugin(
    targets: list[str] | None = None,
    output_dir: str = p("data", "findings"),
    ports: list[int] | None = None,
) -> dict[str, Any]:
    """
    Programmatic & manager entry point.
    Example:
        run_plugin(targets=["example.com","1.2.3.4"], output_dir="...", ports=[80,443])
    """
    os.makedirs(output_dir, exist_ok=True)
    if not targets:
        raw = input("Targets (comma-separated hostnames/IPs): ").strip()
        targets = [t.strip() for t in raw.split(",") if t.strip()]
    ports = ports or DEFAULT_PORTS

    combined: dict[str, Any] = {"task": "http_banner", "status": "ok", "results": []}
    for host in targets:
        res = run_banner_grab(host, ports, output_dir)
        combined["results"].append(res)

    # Save combined JSON
    out_json = ensure_parent(output_dir, "http_banners_summary.json")
    tmp = out_json + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False)
    os.replace(tmp, out_json)
    print(f"[HTTP] Completed banner grabs for {len(targets)} hosts.")
    print(f"[HTTP] Summary saved to {display_path(out_json)}")

    return combined


if __name__ == "__main__":
    run_plugin()
