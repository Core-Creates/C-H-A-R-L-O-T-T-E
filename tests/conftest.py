# tests/conftest.py
import json
import sys
import pytest
from pathlib import Path
import importlib.util

# Ensure the repo root is in sys.path for imports
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (may be slow)"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (may take several minutes)"
    )


@pytest.fixture(scope="session")
def patch_planner():
    spec = importlib.util.spec_from_file_location(
        "patch_planner",
        str(Path(__file__).resolve().parents[1] / "agents" / "patch_planner.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


@pytest.fixture
def triage_sample():
    # Mixed exposures/tiers, KEV vs non-KEV, and different scores
    return [
        {
            "cve": "CVE-2024-0001",
            "asset": "db-01",
            "epss": 0.5,
            "kev": True,
            "cvss": 9.1,
            "exposure": "internet",
            "criticality": "tier-0",
            "package": "openssl",
            "version": "1.1.1",
            "fix_version": "1.1.1x",
        },
        {
            "cve": "CVE-2023-0002",
            "asset": "web-01",
            "epss": 0.2,
            "kev": False,
            "cvss": 7.5,
            "exposure": "internet",
            "criticality": "tier-1",
            "package": "nginx",
            "version": "1.18.0",
        },
        {
            "cve": "CVE-2022-0003",
            "asset": "app-01",
            "epss": 0.05,
            "kev": False,
            "cvss": 5.0,
            "exposure": "internal",
            "criticality": "tier-2",
            "package": "python",
            "version": "3.9.0",
        },
        {
            "cve": "CVE-2021-0004",
            "asset": "mac-01",
            "epss": 0.9,
            "kev": True,
            "cvss": 8.0,
            "exposure": "dmz",
            "criticality": "tier-1",
            "package": "safari",
            "version": "14",
        },
        # duplicate tuple (asset, cve) should be deduped:
        {
            "cve": "CVE-2023-0002",
            "asset": "web-01",
            "epss": 0.2,
            "kev": False,
            "cvss": 7.5,
            "exposure": "internet",
            "criticality": "tier-1",
            "package": "nginx",
            "version": "1.18.0",
        },
    ]


@pytest.fixture
def assets_sample(tmp_path: Path):
    data = {
        "db-01": {"os": "linux", "owner": "data", "tier": "tier-0", "window": "+8h"},
        "web-01": {
            "os": "Windows",
            "owner": "app",
            "tier": "tier-1",
            "window": "2030-01-01T10:00:00Z",
        },
        "app-01": {
            "platform": "ubuntu",
            "owner": "app",
            "tier": "tier-2",
        },  # no window -> default offset
        "mac-01": {"os": "macOS", "owner": "corp", "tier": "tier-1", "window": "+45m"},
    }
    p = tmp_path / "assets.json"
    p.write_text(json.dumps(data, indent=2))
    return p
