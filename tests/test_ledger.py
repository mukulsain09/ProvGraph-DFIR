"""Unit tests for SQLite Evidence Ledger and composite key resolution."""

from __future__ import annotations

import json
from pathlib import Path

from provgraph.graph.models import EventNode, MacroEdge, ProcessRecord
from provgraph.ledger.database import EvidenceLedger


def test_ledger_initialization(tmp_path: Path) -> None:
    db_file = tmp_path / "test_ledger.db"
    with EvidenceLedger(db_file) as ledger:
        assert ledger.count_events() == 0
        assert ledger.count_processes() == 0
        assert ledger.count_macro_edges() == 0


def test_process_insertion_and_retrieval() -> None:
    with EvidenceLedger(":memory:") as ledger:
        proc = ProcessRecord(
            process_guid="{AAAA-1111}",
            process_id=4020,
            image_path="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd.exe /c whoami",
            host_name="victim-pc",
            created_at_utc="2026-10-25T05:00:00Z",
        )
        ledger.insert_process(proc)
        assert ledger.count_processes() == 1


def test_event_insertion_and_composite_key() -> None:
    with EvidenceLedger(":memory:") as ledger:
        event = EventNode(
            event_key="victim-pc:Microsoft-Windows-Sysmon/Operational:101",
            host_name="victim-pc",
            channel="Microsoft-Windows-Sysmon/Operational",
            record_id=101,
            timestamp_epoch=1729830000.0,
            timestamp_utc="2026-10-25T05:00:00Z",
            event_type="ProcessCreate",
            event_id=1,
            process_guid="{AAAA-1111}",
            target_object="C:\\Windows\\System32\\cmd.exe",
            raw_payload='{"EventID": 1}',
        )
        ledger.insert_event(event)
        assert ledger.count_events() == 1

        fetched = ledger.get_event("victim-pc:Microsoft-Windows-Sysmon/Operational:101")
        assert fetched is not None
        assert fetched.event_key == event.event_key
        assert fetched.record_id == 101

        # Duplicate key insert should be ignored
        ledger.insert_event(event)
        assert ledger.count_events() == 1


def test_macro_edge_ledger_storage() -> None:
    with EvidenceLedger(":memory:") as ledger:
        macro = MacroEdge(
            macro_edge_id="macro_001",
            source_event_key="node_u",
            target_event_key="node_w",
            relation_type="WRITES_FILE",
            event_count=5,
            start_time_epoch=100.0,
            end_time_epoch=105.0,
            ordered_event_keys=["v1", "v2", "v3", "v4", "v5"],
            serialized_subgraph_json=json.dumps({"nodes": ["v1", "v2"]}),
        )
        ledger.insert_macro_edge(macro)
        assert ledger.count_macro_edges() == 1

        retrieved = ledger.get_macro_edge("macro_001")
        assert retrieved is not None
        assert retrieved.macro_edge_id == "macro_001"
        assert retrieved.ordered_event_keys == ["v1", "v2", "v3", "v4", "v5"]
        assert retrieved.event_count == 5


def test_cross_thread_access() -> None:
    """Verifies that EvidenceLedger can be safely accessed across different threads."""
    import concurrent.futures

    with EvidenceLedger(":memory:") as ledger:
        # Create an object in the main thread
        macro = MacroEdge(
            macro_edge_id="macro_thread_test",
            source_event_key="node_a",
            target_event_key="node_b",
            relation_type="SPAWNS",
            event_count=2,
            start_time_epoch=100.0,
            end_time_epoch=102.0,
            ordered_event_keys=["node_a", "node_b"],
        )
        ledger.insert_macro_edge(macro)

        def worker_access() -> int:
            # Access and insert from a separate worker thread
            macro2 = MacroEdge(
                macro_edge_id="macro_from_worker",
                source_event_key="node_b",
                target_event_key="node_c",
                relation_type="SPAWNS",
                event_count=1,
                start_time_epoch=103.0,
                end_time_epoch=104.0,
                ordered_event_keys=["node_c"],
            )
            ledger.insert_macro_edge(macro2)
            return ledger.count_macro_edges()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(worker_access)
            count = future.result()

        assert count == 2
        assert ledger.get_macro_edge("macro_from_worker") is not None
