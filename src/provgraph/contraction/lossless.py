"""Lossless hierarchical contraction engine preserving reachability and evidence."""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from typing import Any

import networkx as nx

from provgraph.graph.models import MacroEdge
from provgraph.ledger.database import EvidenceLedger

logger = logging.getLogger(__name__)


def contract_graph(
    slice_graph: nx.DiGraph,
    poi_key: str,
    ledger: EvidenceLedger | None = None,
    enable_fanout: bool = True,
    min_fanout_size: int = 3,
) -> tuple[nx.DiGraph, list[MacroEdge]]:
    """Applies lossless hierarchical contraction to collapse intermediate linear chains and bursts.

    Implements Definitions 4 & 5 and guarantees Theorem 2 reachability invariance.

    Args:
        slice_graph: The uncontracted causal slice DiGraph.
        poi_key: Point of Interest key (strictly protected from contraction).
        ledger: Optional SQLite ledger to persist macro-edges for forensic audit.
        enable_fanout: Whether to collapse homogeneous degree-1 leaf action bursts.
        min_fanout_size: Minimum number of repetitive leaf actions required to form a macro-cluster.

    Returns:
        Tuple of (contracted_DiGraph, list_of_created_MacroEdges).
    """
    g = slice_graph.copy()

    # 1. Iteratively find contractible linear chains until convergence
    modified = True
    while modified:
        modified = False
        candidates = _find_contraction_candidates(g, poi_key)
        if not candidates:
            break

        for v in candidates:
            if v not in g:
                continue

            # Re-verify eligibility after prior contractions in this pass
            if not _is_eligible(g, v, poi_key):
                continue

            u = next(g.predecessors(v))
            w = next(g.successors(v))

            in_edge_data = g.get_edge_data(u, v)
            out_edge_data = g.get_edge_data(v, w)

            in_rel = in_edge_data.get("relation_type")
            out_rel = out_edge_data.get("relation_type")
            if in_rel != out_rel:
                continue

            # Construct ordered event sequence
            # Handle if incoming edge (u, v) or outgoing edge (v, w) were already macros
            ordered_keys: list[str] = []
            merged_nodes: dict[str, dict[str, Any]] = {}
            merged_edges: list[tuple[str, str, dict[str, Any]]] = []

            if in_edge_data.get("is_macro"):
                ordered_keys.extend(in_edge_data.get("ordered_event_keys", []))
                prev_meta = json.loads(in_edge_data.get("serialized_subgraph_json", "{}"))
                merged_nodes.update(prev_meta.get("nodes", {}))
                merged_edges.extend(prev_meta.get("edges", []))
            else:
                merged_edges.append((u, v, in_edge_data))

            ordered_keys.append(v)
            v_dict = {attr: val for attr, val in g.nodes[v].items() if attr != "node_obj"}
            merged_nodes[v] = v_dict

            if out_edge_data.get("is_macro"):
                ordered_keys.extend(out_edge_data.get("ordered_event_keys", []))
                next_meta = json.loads(out_edge_data.get("serialized_subgraph_json", "{}"))
                merged_nodes.update(next_meta.get("nodes", {}))
                merged_edges.extend(next_meta.get("edges", []))
            else:
                merged_edges.append((v, w, out_edge_data))

            serialized_geom = json.dumps(
                {
                    "nodes": merged_nodes,
                    "edges": merged_edges,
                    "is_fanout": False,
                }
            )

            v_node = g.nodes[v]
            start_time = float(
                in_edge_data.get("start_time_epoch", v_node.get("timestamp_epoch", 0.0))
            )
            end_time = float(
                out_edge_data.get("end_time_epoch", v_node.get("timestamp_epoch", 0.0))
            )

            macro_id = f"macro_{uuid.uuid4().hex[:12]}"
            macro = MacroEdge(
                macro_edge_id=macro_id,
                source_event_key=u,
                target_event_key=w,
                relation_type=in_rel,
                event_count=len(ordered_keys),
                start_time_epoch=min(start_time, end_time),
                end_time_epoch=max(start_time, end_time),
                ordered_event_keys=ordered_keys,
                serialized_subgraph_json=serialized_geom,
            )

            # Contract graph: remove v, add macro edge u -> w
            g.remove_node(v)
            g.add_edge(u, w, **macro.to_dict())

            modified = True
            break  # Restart candidate scan to maintain topological integrity

    # 2. Homogeneous Fan-Out Burst Contraction (Degree-1 repetitive leaves)
    if enable_fanout:
        contract_fanout_bursts(g, poi_key=poi_key, min_burst_size=min_fanout_size)

    # Extract final active macro-edges present in the contracted graph
    active_macros: list[MacroEdge] = []
    for src, dst, data in g.edges(data=True):
        if data.get("is_macro"):
            m = MacroEdge(
                macro_edge_id=data["macro_edge_id"],
                source_event_key=src,
                target_event_key=dst,
                relation_type=data["relation_type"],
                event_count=data["event_count"],
                start_time_epoch=data["start_time_epoch"],
                end_time_epoch=data["end_time_epoch"],
                ordered_event_keys=data["ordered_event_keys"],
                serialized_subgraph_json=data["serialized_subgraph_json"],
            )
            active_macros.append(m)
            if ledger is not None:
                ledger.insert_macro_edge(m)

    logger.info(
        "Contracted graph from %d to %d nodes (%d active macro-edges).",
        slice_graph.number_of_nodes(),
        g.number_of_nodes(),
        len(active_macros),
    )
    return g, active_macros


def _is_eligible(g: nx.DiGraph, v: str, poi_key: str) -> bool:
    """Checks Definition 4 eligibility constraints."""
    if v == poi_key:
        return False
    if g.in_degree(v) != 1 or g.out_degree(v) != 1:
        return False

    u = next(g.predecessors(v))
    w = next(g.successors(v))
    if u == v or w == v or u == w:
        return False

    # Check relation homogeneity
    in_rel = g.get_edge_data(u, v).get("relation_type")
    out_rel = g.get_edge_data(v, w).get("relation_type")
    if not in_rel or not out_rel or in_rel != out_rel:
        return False

    # Check process context homogeneity
    v_proc = g.nodes[v].get("process_guid")
    u_proc = g.nodes[u].get("process_guid")
    w_proc = g.nodes[w].get("process_guid")
    if v_proc and u_proc and w_proc:
        if not (u_proc == v_proc == w_proc):
            return False

    return True


def _find_contraction_candidates(g: nx.DiGraph, poi_key: str) -> list[str]:
    """Finds all nodes currently meeting in_degree=1 and out_degree=1."""
    candidates: list[str] = []
    for node in g.nodes():
        if _is_eligible(g, node, poi_key):
            candidates.append(node)
    return candidates


def contract_fanout_bursts(
    g: nx.DiGraph,
    poi_key: str,
    min_burst_size: int = 3,
) -> None:
    """Collapses repetitive degree-1 leaf actions from the same parent into Macro-Clusters."""
    nodes_snapshot = list(g.nodes())
    for u in nodes_snapshot:
        if u not in g:
            continue

        # Find leaf successors: in_degree==1, out_degree==0, not the PoI
        leaf_succs = [
            v
            for v in g.successors(u)
            if g.in_degree(v) == 1 and g.out_degree(v) == 0 and v != poi_key
        ]
        if len(leaf_succs) < min_burst_size:
            continue

        # Group leaves by relation_type
        by_rel: dict[str, list[str]] = defaultdict(list)
        for v in leaf_succs:
            edge_data = g.get_edge_data(u, v) or {}
            rel = str(edge_data.get("relation_type", "UNKNOWN"))
            by_rel[rel].append(v)

        for rel, leaves in by_rel.items():
            if len(leaves) < min_burst_size:
                continue

            # Deterministic sort by strict total order
            leaves.sort(
                key=lambda k: (
                    float(g.nodes[k].get("timestamp_epoch", 0.0)),
                    str(g.nodes[k].get("host_name", "")),
                    str(g.nodes[k].get("channel", "")),
                    int(g.nodes[k].get("record_id", 0)),
                )
            )

            start_time = min(float(g.nodes[v].get("timestamp_epoch", 0.0)) for v in leaves)
            end_time = max(float(g.nodes[v].get("timestamp_epoch", 0.0)) for v in leaves)

            macro_id = f"macro_fanout_{uuid.uuid4().hex[:12]}"
            cluster_key = f"{u}:burst:{rel}:{macro_id[-6:]}"

            merged_nodes = {
                v: {k: val for k, val in g.nodes[v].items() if k != "node_obj"}
                for v in leaves
            }
            merged_edges = [(u, v, g.get_edge_data(u, v)) for v in leaves]
            serialized_geom = json.dumps(
                {
                    "nodes": merged_nodes,
                    "edges": merged_edges,
                    "is_fanout": True,
                    "cluster_key": cluster_key,
                }
            )

            first_leaf = g.nodes[leaves[0]]
            u_host = g.nodes[u].get("host_name", first_leaf.get("host_name", ""))
            u_channel = g.nodes[u].get("channel", first_leaf.get("channel", ""))
            event_type = first_leaf.get("event_type", f"Burst_{rel}")
            target_summary = f"[{len(leaves)} actions collapsed]"

            # Remove original leaf nodes
            for v in leaves:
                g.remove_node(v)

            # Add Macro-Cluster node
            g.add_node(
                cluster_key,
                event_key=cluster_key,
                host_name=u_host,
                channel=u_channel,
                record_id=0,
                timestamp_epoch=start_time,
                timestamp_utc=first_leaf.get("timestamp_utc", ""),
                event_type=f"MacroBurst_{event_type}",
                event_id=0,
                target_object=target_summary,
                is_macro=True,
                is_macro_cluster=True,
                macro_edge_id=macro_id,
                event_count=len(leaves),
            )

            # Add MacroEdge from u to cluster_key
            g.add_edge(
                u,
                cluster_key,
                macro_edge_id=macro_id,
                is_macro=True,
                is_fanout_macro=True,
                relation_type=rel,
                event_count=len(leaves),
                start_time_epoch=start_time,
                end_time_epoch=end_time,
                ordered_event_keys=leaves,
                serialized_subgraph_json=serialized_geom,
                time_delta=max(0.0, round(end_time - start_time, 6)),
                confidence=1.0,
                description=f"Collapsed {len(leaves)} homogeneous leaf actions",
            )
