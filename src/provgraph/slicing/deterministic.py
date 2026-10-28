"""Deterministic bidirectional causal slicing engine."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


def compute_deterministic_slice(
    graph: nx.DiGraph,
    poi_key: str,
    max_depth: int = 15,
    max_delta_sec: float = 3600.0,
    direction: str = "both",
) -> nx.DiGraph:
    """Computes a deterministic, bidirectional causal slice bounded relative to the PoI.

    Enforces Theorem 1 strict order determinism and eliminates hop-by-hop window drift.

    Args:
        graph: The full event-time DAG.
        poi_key: The composite key of the Point of Interest.
        max_depth: Maximum traversal hops backward and forward.
        max_delta_sec: Maximum time delta in seconds from the PoI.
        direction: Traversal direction: 'both', 'backward', or 'forward'.

    Returns:
        The induced subgraph containing both causal directions.
    """
    if poi_key not in graph:
        raise KeyError(f"Point of Interest '{poi_key}' does not exist in graph.")

    poi_node = graph.nodes[poi_key]
    poi_time = float(poi_node["timestamp_epoch"])

    slice_nodes: set[str] = {poi_key}

    # 1. Backward Traversal (Root Cause Discovery)
    if direction in ("both", "backward"):
        # Queue stores: (node_key, depth)
        b_queue: list[tuple[str, int]] = [(poi_key, 0)]
        b_visited: set[str] = {poi_key}

        while b_queue:
            # Deterministic sort: descending by timestamp, host, channel, record_id
            b_queue.sort(
                key=lambda item: (
                    graph.nodes[item[0]]["timestamp_epoch"],
                    graph.nodes[item[0]]["host_name"],
                    graph.nodes[item[0]]["channel"],
                    graph.nodes[item[0]]["record_id"],
                ),
                reverse=True,
            )
            curr_key, depth = b_queue.pop(0)

            if depth >= max_depth:
                continue

            for pred_key in graph.predecessors(curr_key):
                pred_node = graph.nodes[pred_key]
                pred_time = float(pred_node["timestamp_epoch"])

                # Enforce strict PoI-relative lookback window
                time_delta = poi_time - pred_time
                if 0.0 <= time_delta <= max_delta_sec:
                    slice_nodes.add(pred_key)
                    if pred_key not in b_visited:
                        b_visited.add(pred_key)
                        b_queue.append((pred_key, depth + 1))

    # 2. Forward Traversal (Downstream Impact Discovery)
    if direction in ("both", "forward"):
        f_queue: list[tuple[str, int]] = [(poi_key, 0)]
        f_visited: set[str] = {poi_key}

        while f_queue:
            # Deterministic sort: ascending by timestamp, host, channel, record_id
            f_queue.sort(
                key=lambda item: (
                    graph.nodes[item[0]]["timestamp_epoch"],
                    graph.nodes[item[0]]["host_name"],
                    graph.nodes[item[0]]["channel"],
                    graph.nodes[item[0]]["record_id"],
                ),
                reverse=False,
            )
            curr_key, depth = f_queue.pop(0)

            if depth >= max_depth:
                continue

            for succ_key in graph.successors(curr_key):
                succ_node = graph.nodes[succ_key]
                succ_time = float(succ_node["timestamp_epoch"])

                # Enforce strict PoI-relative lookahead window
                time_delta = succ_time - poi_time
                if 0.0 <= time_delta <= max_delta_sec:
                    slice_nodes.add(succ_key)
                    if succ_key not in f_visited:
                        f_visited.add(succ_key)
                        f_queue.append((succ_key, depth + 1))

    slice_subgraph = graph.subgraph(slice_nodes).copy()
    logger.debug(
        "Extracted slice around PoI '%s': %d nodes, %d edges.",
        poi_key,
        slice_subgraph.number_of_nodes(),
        slice_subgraph.number_of_edges(),
    )
    return slice_subgraph


def compute_slice_hash(slice_graph: nx.DiGraph) -> str:
    """Computes a canonical SHA-256 hash of a slice graph to verify determinism."""
    canonical_nodes = sorted(slice_graph.nodes())
    canonical_edges = sorted(
        (u, v, slice_graph.edges[u, v].get("relation_type", "")) for u, v in slice_graph.edges()
    )

    representation: dict[str, Any] = {
        "nodes": canonical_nodes,
        "edges": canonical_edges,
    }
    encoded = json.dumps(representation, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
