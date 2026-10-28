"""Unit tests for ProvGraph-DFIR command line interface."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from test_evtx_loader import SAMPLE_EVTX_XML

from provgraph.cli import main


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "ingest" in result.output
    assert "slice" in result.output
    assert "contract" in result.output
    assert "export" in result.output
    assert "ui" in result.output
    assert "benchmark" in result.output


def test_cli_ingest_and_slice_workflow(tmp_path: Path) -> None:
    runner = CliRunner()
    xml_file = tmp_path / "sample.xml"
    xml_file.write_text(SAMPLE_EVTX_XML, encoding="utf-8")
    db_file = tmp_path / "test.db"

    # 1. Ingest
    ingest_res = runner.invoke(
        main,
        ["ingest", str(xml_file), "--db", str(db_file), "--format", "evtx_xml"],
    )
    assert ingest_res.exit_code == 0
    assert db_file.exists()

    poi_key = "DESKTOP-FORENSIC:Microsoft-Windows-Sysmon/Operational:1001"
    output_json = tmp_path / "slice.json"

    # 2. Slice via SQLite CTE
    slice_res = runner.invoke(
        main,
        [
            "slice",
            "--db",
            str(db_file),
            "--poi",
            poi_key,
            "--method",
            "cte",
            "--output-json",
            str(output_json),
        ],
    )
    assert slice_res.exit_code == 0
    assert output_json.exists()
    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert poi_key in data["nodes"]

    # 3. Contract
    contract_res = runner.invoke(
        main,
        [
            "contract",
            "--db",
            str(db_file),
            "--poi",
            poi_key,
        ],
    )
    assert contract_res.exit_code == 0
    assert "Lossless Contraction Metrics" in contract_res.output

    # 4. Export HTML
    html_file = tmp_path / "graph.html"
    export_res = runner.invoke(
        main,
        [
            "export",
            "--db",
            str(db_file),
            "--poi",
            poi_key,
            "--output-html",
            str(html_file),
        ],
    )
    assert export_res.exit_code == 0
    assert html_file.exists()
    assert "<!DOCTYPE html>" in html_file.read_text(encoding="utf-8")


def test_cli_config_command() -> None:
    """Verifies that 'provgraph config' outputs active parameters and scenarios."""
    runner = CliRunner()
    result = runner.invoke(main, ["config"])
    assert result.exit_code == 0
    assert "Pipeline Parameters" in result.output
    assert "Cataloged Scenarios" in result.output
    assert "empire_vbs" in result.output
    assert "ransomware" in result.output


def test_cli_ingest_binary_evtx(tmp_path: Path) -> None:
    """Verifies that 'provgraph ingest' can process native binary .evtx files."""
    from test_evtx_loader import create_synthetic_binary_evtx

    ev_xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        "<Provider Name=\"Microsoft-Windows-Sysmon\"/>"
        "<EventID>1</EventID>"
        "<EventRecordID>9999</EventRecordID>"
        '<TimeCreated SystemTime="2026-10-27T01:00:00.000Z"/>'
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>CLI-BIN-PC</Computer>"
        "</System>"
        "<EventData>"
        "<Data Name=\"ProcessGuid\">{CLI-BIN-PROC}</Data>"
        "<Data Name=\"ProcessId\">8888</Data>"
        "<Data Name=\"Image\">C:\\Windows\\System32\\cmd.exe</Data>"
        "</EventData>"
        "</Event>"
    )
    raw_evtx = create_synthetic_binary_evtx([(9999, 1730000000.0, ev_xml)])
    evtx_file = tmp_path / "sysmon.evtx"
    evtx_file.write_bytes(raw_evtx)
    db_file = tmp_path / "cli_evtx.db"

    runner = CliRunner()
    result = runner.invoke(main, ["ingest", str(evtx_file), "--db", str(db_file)])
    assert result.exit_code == 0
    assert "Ingested 1 events" in result.output
    assert db_file.exists()
