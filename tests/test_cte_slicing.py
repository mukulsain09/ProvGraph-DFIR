"""Unit and integration tests for SQLite Recursive CTE causal slicing."""

from __future__ import annotations

import networkx as nx

from provgraph.graph.dag_builder import DAGBuilder
from provgraph.graph.models import EventNode
from provgraph.ledger.database import EvidenceLedger
from provgraph.slicing.cte_slicing import compute_sqlite_cte_slice
from provgraph.slicing.deterministic import compute_deterministic_slice


def _setup_ledger_with_attack_chain() -> tuple[EvidenceLedger, EventNode, nx.DiGraph]:
    ledger = EvidenceLedger(":memory:")
    builder = DAGBuilder()

    e_root = EventNode(
        event_key="h:c:1",
        host_name="h",
        channel="c",
        record_id=1,
        timestamp_epoch=100.0,
        timestamp_utc="2026-10-25T05:01:40Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{P1}",
        target_object="C:\\cmd.exe",
    )
    e_mid1 = EventNode(
        event_key="h:c:2",
        host_name="h",
        channel="c",
        record_id=2,
        timestamp_epoch=120.0,
        timestamp_utc="2026-10-25T05:02:00Z",
        event_type="FileCreate",
        event_id=11,
        process_guid="{P1}",
        target_object="C:\\script.ps1",
    )
    e_poi = EventNode(
        event_key="h:c:3",
        host_name="h",
        channel="c",
        record_id=3,
        timestamp_epoch=150.0,
        timestamp_utc="2026-10-25T05:02:30Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{P2}",
        parent_process_guid="{P1}",
        target_object="C:\\script.ps1",
    )
    e_downstream = EventNode(
        event_key="h:c:4",
        host_name="h",
        channel="c",
        record_id=4,
        timestamp_epoch=170.0,
        timestamp_utc="2026-10-25T05:02:50Z",
        event_type="NetworkConnect",
        event_id=3,
        process_guid="{P2}",
        target_object="192.0.2.1:8080",
    )
    e_far_future = EventNode(
        event_key="h:c:5",
        host_name="h",
        channel="c",
        record_id=5,
        timestamp_epoch=5000.0,
        timestamp_utc="2026-10-25T06:23:20Z",
        event_type="NetworkConnect",
        event_id=3,
        process_guid="{P2}",
        target_object="192.0.2.2:8080",
    )

    events = [e_root, e_mid1, e_poi, e_downstream, e_far_future]
    ledger.insert_events_batch(events)

    graph = builder.build_graph(events)
    builder.persist_to_ledger(ledger)

    return ledger, e_poi, graph


def test_sqlite_cte_slice_equivalence() -> None:
    ledger, poi, full_graph = _setup_ledger_with_attack_chain()

    # In-memory slice
    nx_slice = compute_deterministic_slice(
        full_graph, poi_key=poi.event_key, max_depth=10, max_delta_sec=300.0
    )

    # SQLite Recursive CTE slice
    cte_slice = compute_sqlite_cte_slice(
        ledger=ledger, poi_key=poi.event_key, max_depth=10, max_delta_sec=300.0
    )

    # Invariance check: node sets must match exactly
    assert set(cte_slice.nodes()) == set(nx_slice.nodes())
    # Edge sets must match exactly
    assert set(cte_slice.edges()) == set(nx_slice.edges())

    # Window enforcement check: far future event (5000s) excluded
    assert "h:c:5" not in cte_slice
    # Backward root cause preserved
    assert "h:c:1" in cte_slice
    # Forward consequence preserved
    assert "h:c:4" in cte_slice


def test_sqlite_cte_backward_and_forward_modes() -> None:
    ledger, poi, _ = _setup_ledger_with_attack_chain()

    # Backward only
    b_keys = ledger.compute_cte_slice(
        poi_key=poi.event_key, max_depth=10, max_delta_sec=300.0, direction="backward"
    )
    assert poi.event_key in b_keys
    assert "h:c:1" in b_keys
    assert "h:c:4" not in b_keys

    # Forward only
    f_keys = ledger.compute_cte_slice(
        poi_key=poi.event_key, max_depth=10, max_delta_sec=300.0, direction="forward"
    )
    assert poi.event_key in f_keys
    assert "h:c:4" in f_keys
    assert "h:c:1" not in f_keys
