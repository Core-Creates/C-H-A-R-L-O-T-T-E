# plugins/recon/amass/owasp_amass.py
# CHARLOTTE plugin for OWASP Amass - Subdomain Enumeration
from __future__ import annotations

import subprocess
import os
import json
import shutil
from datetime import datetime
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


OUTPUT_DIR = p("data", "findings")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _is_windows() -> bool:
    return os.name == "nt"


def _devnull() -> str:
    return "NUL" if _is_windows() else "/dev/null"


def _which_amass() -> str | None:
    return shutil.which("amass")


def run_amass_enum(
    domain: str, passive: bool = True, output_format: str = "json"
) -> tuple[str | None, str | None]:
    """
    Executes Amass for subdomain enumeration.
    Returns (output_path, folder) or (None, None) on failure.
    """
    if not _which_amass():
        print(
            "[!] Amass not found on PATH. Install OWASP Amass: https://github.com/owasp-amass/amass"
        )
        return None, None

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = p(OUTPUT_DIR, f"amass_{domain}_{timestamp}")
    os.makedirs(folder, exist_ok=True)

    output_path = p(
        folder, f"{domain}_{'passive' if passive else 'active'}.{output_format}"
    )
    base_cmd = ["amass", "enum", "-d", domain]

    # Output flags
    if output_format == "json":
        cmd = base_cmd + ["-json", output_path]
    elif output_format == "csv":
        cmd = base_cmd + ["-csv", output_path]
    elif output_format == "txt":
        # amass -o only supports line output; suppress stdout otherwise
        cmd = base_cmd + ["-o", output_path]
    else:
        print(f"[!] Unsupported output_format: {output_format}")
        return None, None

    if passive:
        cmd.append("-passive")

    # Ensure file’s parent directory exists
    ensure_parent(output_path)

    try:
        print(
            f"[CHARLOTTE] Running Amass ({'passive' if passive else 'active'}) on {domain}..."
        )
        # On txt/json/csv: Amass writes directly; suppress extra stdout
        with open(_devnull(), "w") as devnull:
            subprocess.run(cmd, check=True, stdout=devnull, stderr=devnull)
        print(f"[CHARLOTTE] Output saved to: {display_path(output_path)}")
        return output_path, folder
    except subprocess.CalledProcessError as e:
        print(f"[!] Amass execution failed: {e}")
        return None, None


def parse_amass_json(json_path: str) -> list[dict[str, Any]]:
    """
    Parses Amass JSON (line-delimited) to CHARLOTTE-compatible format.
    """
    results: list[dict[str, Any]] = []
    if not os.path.exists(json_path):
        print(f"[!] File not found: {json_path}")
        return results

    with open(json_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(
                    {
                        "plugin": "owasp_amass",
                        "type": "subdomain",
                        "domain": obj.get("name"),
                        "addresses": obj.get("addresses", []),
                        "source": (obj.get("sources") or [{}])[0].get(
                            "name", "unknown"
                        ),
                        "timestamp": obj.get("timestamp"),
                        "tags": obj.get("tag") or obj.get("tags") or [],
                    }
                )
            except json.JSONDecodeError:
                continue
    return results


def print_summary(records: list[dict[str, Any]]):
    print("\n🔍 CHARLOTTE Recon Summary:")
    print(f"  Total subdomains found: {len(records)}\n")
    for entry in records[:10]:
        name = entry.get("domain") or "(unknown)"
        ips = ", ".join([addr.get("ip", "?") for addr in entry.get("addresses", [])])
        print(f"  • {name}  ➝  {ips}")


def run_plugin(chain_followups: bool = True, args: dict[str, Any] | None = None):
    """
    CLI & programmatic entry point.
    If args provided, uses: {"domain": "...", "mode": "passive"|"active"}
    """
    if args and args.get("domain"):
        domain = args["domain"]
        passive_mode = args.get("mode", "passive") == "passive"
    else:
        from InquirerPy import inquirer

        domain = inquirer.text(message="🌐 Target domain to scan:").execute()
        mode = inquirer.select(
            message="🛠️ Amass mode:", choices=["passive", "active"]
        ).execute()
        passive_mode = mode == "passive"

    json_output, folder = run_amass_enum(
        domain, passive=passive_mode, output_format="json"
    )
    if not json_output:
        return {
            "task": "owasp_amass",
            "status": "error",
            "error": "Amass failed or no output.",
        }

    results = parse_amass_json(json_output)
    print_summary(results)

    summary_path = p(
        folder,
        f"charlotte_subdomains_{domain}_{'passive' if passive_mode else 'active'}.json",
    )
    tmp = summary_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    os.replace(tmp, summary_path)
    print(f"[✓] Results saved to: {display_path(summary_path)}")

    # 🔗 CHAINING
    if chain_followups:
        try:
            from core.plugin_manager import run_plugin as run_next_plugin

            unique_hosts = set()
            for item in results:
                if item.get("domain"):
                    unique_hosts.add(item["domain"])
                for addr in item.get("addresses", []):
                    ip = addr.get("ip")
                    if ip:
                        unique_hosts.add(ip)

            target_list = sorted(unique_hosts)
            print(
                f"\n🔗 Chaining {len(target_list)} hosts into Nmap and HTTP Banner plugins..."
            )
            run_next_plugin("nmap_plugin", targets=target_list, output_dir=folder)
            run_next_plugin("http_banner", targets=target_list, output_dir=folder)
        except Exception as e:
            print(f"[!] Chaining failed: {e}")

    return {
        "task": "owasp_amass",
        "status": "ok",
        "folder": folder,
        "summary": summary_path,
        "records": len(results),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run OWASP Amass Plugin")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--active", action="store_true", help="Use active mode (default passive)"
    )
    ns = parser.parse_args()
    run_plugin(
        chain_followups=True,
        args={"domain": ns.domain, "mode": "active" if ns.active else "passive"},
    )
