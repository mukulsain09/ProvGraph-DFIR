"""Exact reversible expansion API for contracted macro-edges."""

from __future__ import annotations

import json
import logging
from typing import Any

import networkx as nx

from provgraph.ledger.database import EvidenceLedger

logger = logging.getLogger(__name__)


def expand_macro_edge(
    graph: nx.DiGraph,
    macro_edge_id: str,
    ledger: EvidenceLedger | None = None,
) -> nx.DiGraph:
    """Reversibly expands a macro-edge back into its original subpath.

    Implements Definition 6 (Exact Path Expansion API) and guarantees 100% reconstruction fidelity.

    Args:
        graph: The contracted DiGraph.
        macro_edge_id: Unique identifier of the macro-edge to expand.
        ledger: Optional SQLite ledger to retrieve macro metadata if missing from memory.

    Returns:
        The updated DiGraph with the macro-edge replaced by the original nodes and edges.
    """
    g = graph.copy()

    # Find the edge containing macro_edge_id
    target_edge: tuple[str, str, dict[str, Any]] | None = None
    for u, v, data in g.edges(data=True):
        if data.get("macro_edge_id") == macro_edge_id:
            target_edge = (u, v, data)
            break

    if target_edge is None:
        raise KeyError(f"MacroEdge with ID '{macro_edge_id}' not found in active graph.")

    u, w, edge_data = target_edge
    serialized_geom = edge_data.get("serialized_subgraph_json")

    if not serialized_geom and ledger is not None:
        macro_rec = ledger.get_macro_edge(macro_edge_id)
        if macro_rec:
            serialized_geom = macro_rec.serialized_subgraph_json

    if not serialized_geom:
        raise ValueError(
            f"Missing serialized subpath topology for macro-edge '{macro_edge_id}'."
        )

    subpath_data = json.loads(serialized_geom)
    nodes_to_restore: dict[str, dict[str, Any]] = subpath_data.get("nodes", {})
    edges_to_restore: list[list[Any]] = subpath_data.get("edges", [])

    is_fanout = (
        bool(subpath_data.get("is_fanout"))
        or bool(edge_data.get("is_fanout_macro"))
        or (w in g and bool(g.nodes[w].get("is_macro_cluster")))
    )

    # Remove the macro edge
    g.remove_edge(u, w)

    # If it was a fan-out cluster, remove the cluster vertex
    if is_fanout and w in g:
        g.remove_node(w)

    # Restore intermediate vertices
    for node_key, attrs in nodes_to_restore.items():
        g.add_node(node_key, **attrs)

    # Restore edges
    for edge in edges_to_restore:
        src, dst, attrs = edge[0], edge[1], edge[2]
        g.add_edge(src, dst, **attrs)

    logger.debug(
        "Expanded macro-edge '%s' between '%s' and '%s', restoring %d vertices.",
        macro_edge_id,
        u,
        w,
        len(nodes_to_restore),
    )
    return g
