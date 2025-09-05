# ******************************************************************************************
# plugins/servicenow/servicenow_client.py
# ServiceNow API client for CHARLOTTE
# Supports incident creation and logic for determining critical issues
# ******************************************************************************************

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==========================================================================================
# CONSTANT: SERVICENOW_CONFIG_PATH
# ==========================================================================================
SERVICENOW_CONFIG_PATH = "data/servicenow_config.json"

__all__ = [
    "ServiceNowConfig",
    "load_config",
    "should_create_ticket_for",
    "create_incident",
    "maybe_create_tickets",
]


# ==========================================================================================
# CONFIG
# ==========================================================================================
@dataclass(frozen=True)
class ServiceNowConfig:
    """Strongly-typed config for ServiceNow credentials and instance URL."""

    instance_url: str
    username: str
    password: str

    @staticmethod
    def _clean_url(raw: str) -> str:
        raw = (raw or "").strip()
        if not raw:
            raise ValueError("ServiceNow 'instance_url' is missing or empty")
        # Normalize and strip trailing slash
        return raw.rstrip("/")

    @classmethod
    def from_mapping(cls, m: dict[str, Any]) -> ServiceNowConfig:
        try:
            return cls(
                instance_url=cls._clean_url(str(m.get("instance_url", ""))),
                username=str(m.get("username", "")).strip(),
                password=str(m.get("password", "")).strip(),
            )
        except Exception as e:
            raise ValueError(f"Invalid ServiceNow config: {e}") from e


def load_config(path: str = SERVICENOW_CONFIG_PATH) -> ServiceNowConfig:
    """
    Load ServiceNow credentials and instance URL from JSON.
    Environment overrides (if set) take precedence:
      - SERVICENOW_INSTANCE_URL
      - SERVICENOW_USERNAME
      - SERVICENOW_PASSWORD
    """
    data: dict[str, Any] = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

    # Allow env overrides
    env_overrides = {
        "instance_url": os.getenv("SERVICENOW_INSTANCE_URL", data.get("instance_url")),
        "username": os.getenv("SERVICENOW_USERNAME", data.get("username")),
        "password": os.getenv("SERVICENOW_PASSWORD", data.get("password")),
    }
    return ServiceNowConfig.from_mapping(env_overrides)


# ==========================================================================================
# HTTP SESSION (retries, timeouts)
# ==========================================================================================
def _build_session(cfg: ServiceNowConfig) -> requests.Session:
    """
    Create a session with basic auth and sane retries. Safe for reuse.
    """
    session = requests.Session()
    session.auth = (cfg.username, cfg.password)

    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CHARLOTTE-ServiceNowClient/1.0",
        }
    )
    return session


# ==========================================================================================
# DECISION LOGIC
# ==========================================================================================
def should_create_ticket_for(vuln: dict[str, Any]) -> bool:
    """
    Determines whether a finding meets criteria for ticketing.
    Default rule: CVSS >= 9.0 OR impact == 'RCE' (case-insensitive).
    """
    try:
        cvss = float(vuln.get("cvss", 0) or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    impact = str(vuln.get("impact", "")).strip().upper()
    return cvss >= 9.0 or impact == "RCE"


# ==========================================================================================
# INCIDENT CREATION
# ==========================================================================================
def create_incident(
    short_description: str,
    description: str,
    urgency: str = "2",
    impact: str = "2",
    *,
    config: ServiceNowConfig | None = None,
    session: requests.Session | None = None,
    timeout: float = 15.0,
) -> dict[str, Any] | None:
    """
    Creates a ServiceNow incident from a given finding.
    Returns the incident record dict on success, or None on failure.

    Parameters
    ----------
    short_description : str
    description       : str
    urgency           : str   ('1' = High, '2' = Medium, '3' = Low, etc., per your SN setup)
    impact            : str
    config            : ServiceNowConfig (optional)
    session           : requests.Session (optional, reused for efficiency)
    timeout           : float (per-request timeout seconds)
    """
    cfg = config or load_config()
    sess = session or _build_session(cfg)

    api_url = f"{cfg.instance_url}/api/now/table/incident"
    payload = {
        "short_description": short_description,
        "description": description,
        "urgency": urgency,
        "impact": impact,
    }

    try:
        resp = sess.post(api_url, json=payload, timeout=timeout)  # nosec: external call intended
        # 201 Created is typical for table insert; still handle 2xx generally
        if 200 <= resp.status_code < 300:
            data = resp.json()
            result = data.get("result") if isinstance(data, dict) else None
            if result:
                # Optional: log/print the created number
                number = result.get("number", "<unknown>")
                print(f"[✓] Created incident: {number}")
                return result
            print("[!] ServiceNow response JSON missing 'result' field")
            return None

        # Non-2xx: provide debug info without raising
        print(f"[!] Failed to create incident: HTTP {resp.status_code}")
        try:
            print(resp.text)
        except Exception:
            pass
        return None

    except requests.RequestException as e:
        print(f"[!] Network error during ticket creation: {e}")
        return None
    except ValueError as e:
        # JSON decode issues or config validation
        print(f"[!] Value error during ticket creation: {e}")
        return None


# ==========================================================================================
# BATCH CREATION FROM FINDINGS
# ==========================================================================================
def maybe_create_tickets(findings: Iterable[dict[str, Any]]) -> None:
    """
    Loops through triaged findings and creates tickets for critical ones.
    """
    try:
        cfg = load_config()
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] ServiceNow config error: {e}. Run setup before using this feature.")
        return

    sess = _build_session(cfg)
    print("[*] Checking for critical findings to ticket...")

    for vuln in findings:
        if should_create_ticket_for(vuln):
            short_desc = f"[CHARLOTTE] Critical: {vuln.get('id', 'Unknown ID')}"
            full_desc = (
                "CHARLOTTE identified a critical vulnerability.\n\n"
                f"CVE: {vuln.get('id', 'N/A')}\n"
                f"CVSS: {vuln.get('cvss', 'N/A')}\n"
                f"Impact: {vuln.get('impact', 'N/A')}\n"
                f"CWE: {vuln.get('cwe', 'N/A')}\n"
                f"Description: {vuln.get('description', 'No details provided.')}"
            )
            create_incident(
                short_desc,
                full_desc,
                urgency="1" if float(vuln.get("cvss", 0) or 0) >= 9.5 else "2",
                impact="1"
                if str(vuln.get("impact", "")).strip().upper() == "RCE"
                else "2",
                config=cfg,
                session=sess,
            )

    print("[*] Ticket creation process completed.")
