"""Integration tests for MordorLoader and end-to-end provenance pipeline."""

from __future__ import annotations

from pathlib import Path

from provgraph.graph.dag_builder import DAGBuilder
from provgraph.ingestion.mordor_loader import MordorLoader
from provgraph.ledger.database import EvidenceLedger
from provgraph.slicing.deterministic import compute_deterministic_slice


def test_mordor_loader_and_pipeline_integration(tmp_path: Path) -> None:
    fixture_path = (
        Path(__file__).parent.parent / "data" / "test_fixtures" / "sample_sysmon.json"
    )
    assert fixture_path.exists()

    db_path = tmp_path / "integration.db"
    with EvidenceLedger(db_path) as ledger:
        loader = MordorLoader(ledger)
        events_count, procs_count = loader.load_file(fixture_path)

        assert events_count == 6
        assert procs_count == 3  # cmd.exe, powershell.exe, stage.exe
        assert ledger.count_events() == 6
        assert ledger.count_processes() == 3

        # Retrieve all events in chronological strict order
        cursor = ledger.connection.execute(
            "SELECT event_key FROM event_ledger ORDER BY timestamp_epoch ASC"
        )
        keys = [row[0] for row in cursor.fetchall()]
        events = ledger.get_events_by_keys(keys)
        assert len(events) == 6

        # Build Provenance DAG
        builder = DAGBuilder()
        dag = builder.build_graph(events)
        assert dag.number_of_nodes() == 6

        # Target PoI: Network Connect event (record_id 1005)
        poi_key = "VICTIM-PC.CORP.LOCAL:Microsoft-Windows-Sysmon/Operational:1005"
        assert poi_key in dag

        # Compute backward and forward slice around PoI
        slice_g = compute_deterministic_slice(
            dag, poi_key=poi_key, max_depth=10, max_delta_sec=3600.0
        )

        # Ensure the entire attack chain is captured in the slice:
        # cmd.exe -> powershell.exe -> stage.exe -> c2 network
        cmd_key = "VICTIM-PC.CORP.LOCAL:Microsoft-Windows-Sysmon/Operational:1001"
        ps_key = "VICTIM-PC.CORP.LOCAL:Microsoft-Windows-Sysmon/Operational:1002"
        stage_key = "VICTIM-PC.CORP.LOCAL:Microsoft-Windows-Sysmon/Operational:1004"

        assert cmd_key in slice_g
        assert ps_key in slice_g
        assert stage_key in slice_g
        assert poi_key in slice_g
