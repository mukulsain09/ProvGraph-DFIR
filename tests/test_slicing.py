"""Unit tests for deterministic bidirectional causal slicing and PoI window enforcement."""

from __future__ import annotations

import networkx as nx

from provgraph.graph.dag_builder import DAGBuilder
from provgraph.graph.models import EventNode
from provgraph.slicing.deterministic import (
    compute_deterministic_slice,
    compute_slice_hash,
)


def _build_test_provenance_graph() -> tuple[nx.DiGraph, EventNode]:
    """Constructs a realistic 6-event attack sequence."""
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
    e_downstream1 = EventNode(
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
        timestamp_epoch=5000.0,  # Far beyond max delta
        timestamp_utc="2026-10-25T06:23:20Z",
        event_type="NetworkConnect",
        event_id=3,
        process_guid="{P2}",
        target_object="192.0.2.2:8080",
    )

    graph = builder.build_graph([e_root, e_mid1, e_poi, e_downstream1, e_far_future])
    return graph, e_poi


def test_bidirectional_slicing_and_window_filter() -> None:
    graph, poi = _build_test_provenance_graph()

    # Slice with 300 second window around PoI (150s)
    # Range is [0s, 450s] for backward/forward
    # e_root (100s), e_mid1 (120s), e_poi (150s), e_downstream1 (170s) are IN
    # e_far_future (5000s) is OUT (exceeds delta from PoI)
    slice_graph = compute_deterministic_slice(
        graph, poi_key=poi.event_key, max_depth=10, max_delta_sec=300.0
    )

    assert poi.event_key in slice_graph
    assert "h:c:1" in slice_graph  # Backward root cause
    assert "h:c:2" in slice_graph  # Backward intermediate file
    assert "h:c:4" in slice_graph  # Forward downstream C2
    assert "h:c:5" not in slice_graph  # Excluded by PoI-relative time window

    # Preserves path connectivity
    assert nx.has_path(slice_graph, "h:c:1", poi.event_key)
    assert nx.has_path(slice_graph, poi.event_key, "h:c:4")


def test_strict_slice_determinism_across_repeated_runs() -> None:
    """Verifies identical canonical hash across 10 independent executions."""
    graph, poi = _build_test_provenance_graph()

    base_hash = compute_slice_hash(
        compute_deterministic_slice(graph, poi.event_key, max_depth=5, max_delta_sec=200.0)
    )

    for _ in range(10):
        run_slice = compute_deterministic_slice(
            graph, poi.event_key, max_depth=5, max_delta_sec=200.0
        )
        run_hash = compute_slice_hash(run_slice)
        assert run_hash == base_hash
