# tests/test_patch_planner.py
import io
import json
import sys

import pytest


def test_build_plan_basics(patch_planner, triage_sample, assets_sample, tmp_path):
    assets = patch_planner.load_assets(assets_sample)
    findings = [patch_planner.Finding.from_dict(x) for x in triage_sample]

    plan = patch_planner.build_plan(
        findings=findings,
        assets=assets,
        min_epss=0.0,
        kev_only=False,
        ring_by_tier=None,
        hours_ahead=1,
        dedupe=True,
    )

    # Deduped (5 in input, 1 duplicate) -> 4 items
    assert len(plan) == 4

    # OS inference
    by_host = {p.host: p for p in plan}
    assert by_host["db-01"].os == "linux"
    assert by_host["web-01"].os == "windows"
    assert by_host["app-01"].os == "linux"  # inferred from platform 'ubuntu'
    assert by_host["mac-01"].os == "macos"

    # Window normalization: db-01 uses +8h, mac-01 uses +45m, web-01 fixed ISO, app-01 default offset
    assert "T" in by_host["db-01"].window and by_host["db-01"].window.endswith("+00:00")
    assert "T" in by_host["mac-01"].window and by_host["mac-01"].window.endswith(
        "+00:00"
    )
    assert by_host["web-01"].window.startswith("2030-01-01T10:00:00")
    assert "T" in by_host["app-01"].window

    # Ring assignment from default map
    assert by_host["db-01"].ring == 0  # tier-0
    assert by_host["web-01"].ring == 1  # tier-1
    assert by_host["app-01"].ring == 2  # tier-2
    assert by_host["mac-01"].ring == 1  # tier-1


def test_filters_and_sorting(patch_planner, triage_sample, assets_sample):
    assets = patch_planner.load_assets(assets_sample)
    findings = [patch_planner.Finding.from_dict(x) for x in triage_sample]

    # Only internet exposure, min EPSS 0.2, tiers tier-0/tier-1
    plan = patch_planner.build_plan(
        findings,
        assets,
        min_epss=0.2,
        kev_only=False,
        exposure_filter=["internet"],
        tiers_filter=["tier-0", "tier-1"],
    )
    # Should include db-01 (tier-0, kev) and web-01 (tier-1, non-kev). Excludes dmz/internal and epss<0.2
    hosts = [p.host for p in plan]
    assert set(hosts) == {"db-01", "web-01"}

    # Deterministic order: KEV + higher score first (db-01 outranks web-01)
    assert hosts[0] == "db-01"


def test_ring_override_map(patch_planner, triage_sample, assets_sample):
    assets = patch_planner.load_assets(assets_sample)
    findings = [patch_planner.Finding.from_dict(x) for x in triage_sample]
    ring_map = {"tier-0": 9, "tier-1": 5, "tier-2": 3, "tier-3": 1}

    plan = patch_planner.build_plan(findings, assets, ring_by_tier=ring_map)
    by_host = {p.host: p for p in plan}
    assert by_host["db-01"].ring == 9
    assert by_host["web-01"].ring == 5
    assert by_host["app-01"].ring == 3


def test_plan_to_dict_shape(patch_planner, triage_sample, assets_sample):
    assets = patch_planner.load_assets(assets_sample)
    findings = [patch_planner.Finding.from_dict(x) for x in triage_sample]
    plan = patch_planner.build_plan(findings, assets)
    doc = patch_planner.plan_to_dict(plan)

    assert "generated_at" in doc and "version" in doc and "items" in doc
    assert isinstance(doc["items"], list) and len(doc["items"]) == 4
    # Check a couple of fields exist on first item
    it0 = doc["items"][0]
    for field in ["host", "cve", "ring", "window", "rollback"]:
        assert field in it0


def test_csv_export(patch_planner, triage_sample, assets_sample, tmp_path):
    assets = patch_planner.load_assets(assets_sample)
    findings = [patch_planner.Finding.from_dict(x) for x in triage_sample]
    plan = patch_planner.build_plan(findings, assets)

    csv_path = tmp_path / "plan.csv"
    patch_planner._write_csv(plan, csv_path)

    text = csv_path.read_text(encoding="utf-8")
    # Header and at least one line
    assert (
        "host,os,cve,ring,window,kev,epss,cvss,exposure,criticality,package,current_version,fix_version,rollback"
        in text
    )
    assert "db-01" in text


def test_stdin_triage_path(patch_planner, triage_sample, monkeypatch):
    # Feed triage via STDIN using the '-' sentinel
    buf = io.StringIO(json.dumps({"items": triage_sample}))
    monkeypatch.setattr(sys, "stdin", buf)
    data = patch_planner._read_triage_arg("-")
    assert isinstance(data, list) and len(data) == 5  # includes duplicate before dedupe


def test_inline_ring_map_json(patch_planner):
    rm = patch_planner._read_json_or_inline('{"tier-0":0,"tier-1":1}')
    assert rm["tier-0"] == 0 and rm["tier-1"] == 1
    with pytest.raises(json.JSONDecodeError):
        patch_planner._read_json_or_inline('{"tier-0":0,"tier-1":}')  # malformed JSON
    with pytest.raises(FileNotFoundError):
        patch_planner._read_json_or_inline("/no/such/file.json")
