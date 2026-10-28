"""Unit tests verifying Definition 6 (Exact Path Expansion and Reversibility)."""

from __future__ import annotations

import networkx as nx

from provgraph.contraction.expansion import expand_macro_edge
from provgraph.contraction.lossless import contract_graph
from provgraph.ledger.database import EvidenceLedger


def test_reversible_expansion_fidelity() -> None:
    """Verifies that Expand(macro_edge) perfectly restores original vertices and edges."""
    g = nx.DiGraph()
    u = "node_source"
    v1 = "node_mid1"
    v2 = "node_mid2"
    w = "node_sink"

    g.add_node(u, event_key=u, process_guid="{P}", timestamp_epoch=1.0, event_id=1)
    g.add_node(v1, event_key=v1, process_guid="{P}", timestamp_epoch=2.0, event_id=11)
    g.add_node(v2, event_key=v2, process_guid="{P}", timestamp_epoch=3.0, event_id=11)
    g.add_node(w, event_key=w, process_guid="{P}", timestamp_epoch=4.0, event_id=3)

    g.add_edge(u, v1, relation_type="WRITES_FILE", is_macro=False)
    g.add_edge(v1, v2, relation_type="WRITES_FILE", is_macro=False)
    g.add_edge(v2, w, relation_type="WRITES_FILE", is_macro=False)

    with EvidenceLedger(":memory:") as ledger:
        contracted, macros = contract_graph(g, poi_key=w, ledger=ledger)

        assert contracted.number_of_nodes() == 2
        assert len(macros) >= 1
        macro_id = macros[-1].macro_edge_id

        # Perform reversible expansion
        restored = expand_macro_edge(contracted, macro_id, ledger=ledger)

        # Assert exact structural equivalence
        assert restored.number_of_nodes() == g.number_of_nodes()
        assert set(restored.nodes()) == set(g.nodes())
        assert restored.number_of_edges() == g.number_of_edges()

        # Assert all edges match original
        for src, dst in g.edges():
            assert restored.has_edge(src, dst)
            assert (
                restored.get_edge_data(src, dst)["relation_type"]
                == g.get_edge_data(src, dst)["relation_type"]
            )


def test_fanout_macro_reversible_expansion() -> None:
    """Verifies that Expand() on a fan-out macro cluster perfectly restores all leaves."""
    g = nx.DiGraph()
    u = "proc_wannacrypt"
    g.add_node(u, event_key=u, process_guid="{P}", timestamp_epoch=1.0, event_id=1)

    for i in range(10):
        key = f"leaf_file_{i}"
        g.add_node(key, event_key=key, process_guid="{P}", timestamp_epoch=2.0 + i, event_id=11)
        g.add_edge(u, key, relation_type="WRITES_FILE", is_macro=False)

    contracted, macros = contract_graph(g, poi_key=u, enable_fanout=True)
    assert contracted.number_of_nodes() == 2
    assert len(macros) == 1

    restored = expand_macro_edge(contracted, macros[0].macro_edge_id)
    assert restored.number_of_nodes() == g.number_of_nodes()
    assert set(restored.nodes()) == set(g.nodes())
    assert restored.number_of_edges() == g.number_of_edges()
    assert set(restored.edges()) == set(g.edges())
