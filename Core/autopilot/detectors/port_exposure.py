# ******************************************************************************************
# PortExposureDetector — throttled, friendly network exposure snapshot
# ******************************************************************************************
from __future__ import annotations
import shutil
import subprocess
from typing import Any
import xml.etree.ElementTree as ET

from ..issues import Issue
from ..rate_limit import TokenBucketLimiter
from ..netmon import BandwidthMonitor


class PortExposureDetector:
    def __init__(
        self,
        cfg: dict[str, Any],
        limiter: TokenBucketLimiter,
        netmon: BandwidthMonitor,
        logger,
    ):
        self.cfg = cfg or {}
        self.limiter = limiter
        self.netmon = netmon
        self.logger = logger.getChild("portscan")
        self._last_run = 0.0
        self._metrics = {"last_targets": 0, "last_top": 0}

    def metrics(self) -> dict[str, Any]:
        return dict(self._metrics)

    def run(self) -> list[Issue]:
        cidr = self.cfg.get("target_cidr", "192.168.0.0/24")
        topn = int(self.cfg.get("scan_top_n", 100))
        intensity = (self.cfg.get("intensity", "slow") or "slow").lower()
        timing = {"slow": "-T2", "normal": "-T3", "fast": "-T4"}.get(intensity, "-T2")

        # Respect bandwidth limiter: ~150 bytes per port probe (very rough)
        approx_cost = max(10_000, topn * 150)
        self.limiter.acquire(approx_cost)

        issues: list[Issue] = []
        if shutil.which("nmap"):
            cmd = ["nmap", timing, "--top-ports", str(topn), "-oX", "-", cidr]
            self.logger.info("nmap %s", " ".join(cmd))
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                opened = self._parse_nmap_xml(out.decode("utf-8", errors="ignore"))
                for host, ports in opened.items():
                    # flag commonly abused/system ports and privileged ports
                    flagged = [
                        p for p in ports if p in (21, 23, 445, 3389, 5900) or p < 1024
                    ]
                    if flagged:
                        shown = flagged[:6]
                        title = (
                            f"Exposed services on {host}: {shown}…"
                            if len(flagged) > 6
                            else f"Exposed services on {host}: {flagged}"
                        )
                        issues.append(
                            Issue(
                                title=title,
                                severity="high",
                                details={"host": host, "open_ports": ports},
                                hint="Lock down or move to DMZ; verify firewall rules; consider auto-patch hardening.",
                            )
                        )
                self._metrics.update({"last_targets": len(opened), "last_top": topn})
            except subprocess.CalledProcessError as e:
                self.logger.warning("nmap failed: %s", e)
            except Exception as e:
                self.logger.exception("nmap parsing error: %s", e)
        else:
            self.logger.info("nmap not found; skipping port exposure scan")
        return issues

    def _parse_nmap_xml(self, xml: str) -> dict[str, list[int]]:
        """
        Tiny, forgiving parse using the stdlib XML parser.
        Returns { ip: [open_port, ...] } for TCP/UDP where state='open'.
        """
        hosts: dict[str, list[int]] = {}
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return hosts

        for host in root.findall(".//host"):
            ip = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                    break
            if not ip:
                continue
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                try:
                    portid = int(port_el.get("portid", "0"))
                except ValueError:
                    continue
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    hosts.setdefault(ip, []).append(portid)

        # normalize & sort for stable output
        for k in list(hosts.keys()):
            hosts[k] = sorted(set(hosts[k]))
        return hosts
