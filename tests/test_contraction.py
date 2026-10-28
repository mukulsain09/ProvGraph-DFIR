"""Unit tests verifying Theorem 2 (Reachability Preservation Invariant) under contraction."""

from __future__ import annotations

import networkx as nx

from provgraph.contraction.lossless import contract_graph
from provgraph.evaluation.benchmark import compute_graph_metrics
from provgraph.ledger.database import EvidenceLedger


def _create_linear_burst_slice() -> tuple[nx.DiGraph, str]:
    """Creates a slice with a linear burst of 10 consecutive file write events."""
    g = nx.DiGraph()

    # Source process
    u = "h:c:100"
    g.add_node(u, event_key=u, process_guid="{BURST_P}", timestamp_epoch=100.0)

    # PoI at the end
    poi = "h:c:999"
    g.add_node(poi, event_key=poi, process_guid="{BURST_P}", timestamp_epoch=200.0)

    prev = u
    # 5 intermediate file write actions by the same process
    for i in range(1, 6):
        node_key = f"h:c:{100 + i}"
        g.add_node(
            node_key,
            event_key=node_key,
            process_guid="{BURST_P}",
            timestamp_epoch=100.0 + i,
        )
        g.add_edge(prev, node_key, relation_type="WRITES_FILE", is_macro=False)
        prev = node_key

    g.add_edge(prev, poi, relation_type="WRITES_FILE", is_macro=False)
    return g, poi


def test_theorem_2_reachability_preservation_and_reduction() -> None:
    """Verifies that 100% reachability is preserved while intermediate nodes are collapsed."""
    orig_slice, poi = _create_linear_burst_slice()

    with EvidenceLedger(":memory:") as ledger:
        contracted, macros = contract_graph(orig_slice, poi_key=poi, ledger=ledger)

        # Invariant 1: PoI must remain in contracted graph
        assert poi in contracted

        # Invariant 2: Root cause u must remain in contracted graph
        assert "h:c:100" in contracted

        # Invariant 3: Intermediate 5 nodes must be collapsed
        assert contracted.number_of_nodes() == 2
        assert contracted.number_of_edges() == 1
        assert len(macros) == 1

        # Invariant 4: Macro-edge connects u directly to poi
        assert contracted.has_edge("h:c:100", poi)
        edge_data = contracted.get_edge_data("h:c:100", poi)
        assert edge_data["is_macro"] is True
        assert edge_data["event_count"] == 5

        # Invariant 5: Theorem 2 Reachability Invariant (100% agreement)
        metrics = compute_graph_metrics(orig_slice, contracted)
        assert metrics.reachability_preserved is True
        assert metrics.reachability_agreement_rate == 1.0
        assert metrics.graph_size_reduction >= 0.70  # (7 nodes down to 2 nodes = >70%)


def test_poi_is_strictly_protected_from_contraction() -> None:
    """Verifies that a node designated as PoI is never contracted even if degree==1."""
    g = nx.DiGraph()
    g.add_node("u", process_guid="{P}", timestamp_epoch=10.0)
    g.add_node("poi", process_guid="{P}", timestamp_epoch=20.0)
    g.add_node("w", process_guid="{P}", timestamp_epoch=30.0)

    g.add_edge("u", "poi", relation_type="SPAWNS", is_macro=False)
    g.add_edge("poi", "w", relation_type="SPAWNS", is_macro=False)

    contracted, macros = contract_graph(g, poi_key="poi")

    # PoI must NOT be contracted away
    assert "poi" in contracted
    assert contracted.number_of_nodes() == 3
    assert len(macros) == 0


def test_fanout_burst_contraction_and_reduction() -> None:
    """Verifies that homogeneous degree-1 leaf bursts collapse and achieve >=70% GSR."""
    g = nx.DiGraph()
    proc = "h:c:1000"
    g.add_node(proc, event_key=proc, process_guid="{P}", timestamp_epoch=100.0)

    # 20 repetitive file create leaf actions
    for i in range(1, 21):
        leaf = f"h:c:{1000 + i}"
        g.add_node(
            leaf,
            event_key=leaf,
            process_guid="{P}",
            timestamp_epoch=100.0 + i,
            event_type="FileCreate",
            target_object=f"C:\\file_{i}.txt",
        )
        g.add_edge(proc, leaf, relation_type="WRITES_FILE", is_macro=False)

    assert g.number_of_nodes() == 21
    assert g.number_of_edges() == 20

    contracted, macros = contract_graph(g, poi_key=proc, enable_fanout=True, min_fanout_size=3)

    # Collapsed to 1 process node + 1 macro cluster node
    assert contracted.number_of_nodes() == 2
    assert contracted.number_of_edges() == 1
    assert len(macros) == 1
    assert macros[0].event_count == 20

    metrics = compute_graph_metrics(g, contracted)
    assert metrics.reachability_preserved is True
    assert metrics.reachability_agreement_rate == 1.0
    assert metrics.graph_size_reduction >= 0.70
