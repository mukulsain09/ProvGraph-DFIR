"""SQLite Recursive CTE causal slicing engine.

Performs query-pushdown causal graph slicing directly inside SQLite,
avoiding loading massive full-dataset event graphs into Python memory.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import networkx as nx

if TYPE_CHECKING:
    from provgraph.ledger.database import EvidenceLedger

logger = logging.getLogger(__name__)


def compute_sqlite_cte_slice(
    ledger: EvidenceLedger,
    poi_key: str,
    max_depth: int = 15,
    max_delta_sec: float = 3600.0,
    direction: str = "both",
) -> nx.DiGraph:
    """Computes a deterministic causal slice directly within the SQLite ledger.

    Uses recursive Common Table Expressions (WITH RECURSIVE) for indexed traversal.
    Only the vertices and induced edges in the resulting slice are retrieved and instantiated
    as a networkx.DiGraph.

    Args:
        ledger: EvidenceLedger containing ingested events and causal edges.
        poi_key: Point of Interest event key.
        max_depth: Maximum edge traversal depth K.
        max_delta_sec: Strict temporal horizon |t(v) - t(poi)| <= Delta T.
        direction: 'backward', 'forward', or 'both'.

    Returns:
        A networkx.DiGraph containing only the slice vertices and induced causal edges.
    """
    sliced_keys = ledger.compute_cte_slice(
        poi_key=poi_key,
        max_depth=max_depth,
        max_delta_sec=max_delta_sec,
        direction=direction,
    )
    slice_graph = nx.DiGraph()
    if not sliced_keys:
        return slice_graph

    # Fetch only sliced event nodes
    events = ledger.get_events_by_keys(sliced_keys)
    for ev in events:
        slice_graph.add_node(ev.event_key, **ev.to_dict(), node_obj=ev)

    # Fetch induced causal edges
    edge_rows = ledger.get_causal_edges_induced(sliced_keys)
    for r in edge_rows:
        slice_graph.add_edge(
            r["source_event_key"],
            r["target_event_key"],
            relation_type=r["relation_type"],
            time_delta=r["time_delta"],
            confidence=r["confidence"],
            description=r["description"],
            is_macro=False,
        )

    logger.debug(
        "SQLite CTE slice extracted: %d nodes, %d edges for PoI %s",
        slice_graph.number_of_nodes(),
        slice_graph.number_of_edges(),
        poi_key,
    )
    return slice_graph
