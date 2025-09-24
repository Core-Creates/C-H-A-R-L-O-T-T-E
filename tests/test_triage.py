# tests/test_triage.py
import json
from pathlib import Path
import shutil
import importlib
import importlib.util

# Try to import cli.cli as a package module; otherwise fall back to loading by path
try:
    cli = importlib.import_module("cli.cli")
except Exception:
    # Fallback: load the module directly from cli/cli.py (repo-root relative)
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "cli" / "cli.py"
    spec = importlib.util.spec_from_file_location("cli_fallback", str(module_path))
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_map_snyk_to_triage_basic():
    snyk_json = json.loads(
        (FIXTURES_DIR / "snyk_sample.json").read_text(encoding="utf-8")
    )
    items = cli.map_snyk_to_triage(snyk_json)
    assert isinstance(items, list)
    assert len(items) == 1
    item = items[0]
    assert item.component.name == "example-lib"
    assert item.id in ("CVE-2024-0001", "SNYK-123", "UNKNOWN")
    assert item.severity in ("high", "medium", "low", "critical", "none")


def test_parse_sbom_components_basic():
    sbom = json.loads(
        (FIXTURES_DIR / "sbom_cyclonedx.json").read_text(encoding="utf-8")
    )
    comp_map = cli.parse_sbom_components(sbom)
    assert "example-lib" in comp_map
    comp = comp_map["example-lib"]
    assert comp.version == "1.0.0"
    assert comp.purl == "pkg:pypi/example-lib@1.0.0"


def test_triage_end_to_end_creates_bundle(tmp_path):
    # copy fixtures into tmp so triage reads from files
    tmp_fixtures = tmp_path / "fixtures"
    tmp_fixtures.mkdir()
    shutil.copy(FIXTURES_DIR / "snyk_sample.json", tmp_fixtures / "snyk_sample.json")
    shutil.copy(
        FIXTURES_DIR / "sbom_cyclonedx.json", tmp_fixtures / "sbom_cyclonedx.json"
    )

    snyk_path = tmp_fixtures / "snyk_sample.json"
    sbom_path = tmp_fixtures / "sbom_cyclonedx.json"
    out_path = tmp_path / "triage_out.json"

    # call the triage Typer function directly
    # If the triage function expects Path objects, this should work; adjust if your signature differs.
    cli.triage(
        snyk=snyk_path,
        sbom=sbom_path,
        out=out_path,
        policy=None,
        repo="example/repo",
        commit="deadbeef",
    )

    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data.get("tool") == "charlotte"
    assert "items" in data
    assert len(data["items"]) == 1
    item = data["items"][0]

    # SBOM version should be present on the component (or at least version preserved)
    assert "component" in item
    comp = item["component"]
    assert comp["name"] == "example-lib"
    # version either from SBOM or snyk; ensure it's set
    assert comp.get("version") is not None

    # risk_score should be computed and within [0,1]
    assert item.get("risk_score") is not None
    assert 0.0 <= float(item["risk_score"]) <= 1.0
