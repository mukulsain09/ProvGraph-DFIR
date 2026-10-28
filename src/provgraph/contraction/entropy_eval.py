"""Shannon relation entropy calculator and ablation evaluation module."""

from __future__ import annotations

import logging
import math
from collections import Counter
from typing import Any

import networkx as nx

from provgraph.contraction.lossless import contract_graph
from provgraph.graph.models import MacroEdge
from provgraph.ledger.database import EvidenceLedger

logger = logging.getLogger(__name__)


def calculate_node_relation_entropy(graph: nx.DiGraph, node: str) -> float:
    """Calculates categorical Shannon relation entropy H(v) over incident edge types.

    H(v) = -sum(p(r) * log2(p(r))) where p(r) is frequency of relation type r.

    Args:
        graph: DiGraph containing the node.
        node: Target node key.

    Returns:
        Shannon entropy in bits (>= 0.0). Single-type bursts yield 0.0.
    """
    if node not in graph:
        return 0.0

    relations: list[str] = []
    # Collect relations from incoming and outgoing edges
    for _, _, data in graph.in_edges(node, data=True):
        rel = data.get("relation_type")
        if rel:
            relations.append(rel)

    for _, _, data in graph.out_edges(node, data=True):
        rel = data.get("relation_type")
        if rel:
            relations.append(rel)

    total_edges = len(relations)
    if total_edges <= 1:
        return 0.0

    counts = Counter(relations)
    entropy = 0.0
    for count in counts.values():
        p = count / total_edges
        if p > 0.0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_graph_entropy_distribution(graph: nx.DiGraph) -> dict[str, float]:
    """Calculates H(v) for all vertices in the graph."""
    return {n: calculate_node_relation_entropy(graph, n) for n in graph.nodes()}


def evaluate_entropy_saliency_correlation(
    graph: nx.DiGraph, ground_truth_attack_nodes: set[str]
) -> dict[str, Any]:
    """Tests the Entropy Inversion Hypothesis (RQ2).

    Compares categorical entropy of attack burst nodes versus benign OS nodes.

    Args:
        graph: The provenance graph.
        ground_truth_attack_nodes: Set of node keys known to belong to the attack path.

    Returns:
        Dictionary containing mean attack entropy, mean benign entropy, and inversion status.
    """
    if not graph.number_of_nodes():
        return {
            "mean_attack_entropy": 0.0,
            "mean_benign_entropy": 0.0,
            "entropy_inversion_detected": False,
        }

    attack_entropies: list[float] = []
    benign_entropies: list[float] = []

    for n in graph.nodes():
        h = calculate_node_relation_entropy(graph, n)
        if n in ground_truth_attack_nodes:
            attack_entropies.append(h)
        else:
            benign_entropies.append(h)

    mean_attack = (sum(attack_entropies) / len(attack_entropies)) if attack_entropies else 0.0
    mean_benign = (sum(benign_entropies) / len(benign_entropies)) if benign_entropies else 0.0

    # Inversion occurs when attack nodes have LOWER entropy than benign background nodes
    inversion_detected = mean_attack < mean_benign

    return {
        "mean_attack_entropy": round(mean_attack, 4),
        "mean_benign_entropy": round(mean_benign, 4),
        "attack_node_count": len(attack_entropies),
        "benign_node_count": len(benign_entropies),
        "entropy_inversion_detected": inversion_detected,
    }


def entropy_guided_contraction(
    slice_graph: nx.DiGraph,
    poi_key: str,
    entropy_threshold: float = 1.0,
    ledger: EvidenceLedger | None = None,
) -> tuple[nx.DiGraph, list[MacroEdge]]:
    """Ablation Baseline B_4: Contraction prioritizing low-entropy nodes.

    Restricts contraction eligibility to candidates whose categorical Shannon relation
    entropy is below entropy_threshold.

    Args:
        slice_graph: Uncontracted slice graph.
        poi_key: Point of Interest key.
        entropy_threshold: Max Shannon entropy (bits) for a node to be eligible.
        ledger: Optional SQLite ledger.

    Returns:
        Tuple of (contracted_DiGraph, list_of_created_MacroEdges).
    """
    # Filter candidates by entropy constraint before passing to structural contraction
    eligible_subgraph = slice_graph.copy()
    for n in list(eligible_subgraph.nodes()):
        if n != poi_key:
            h = calculate_node_relation_entropy(slice_graph, n)
            # If node entropy exceeds threshold, mark as protected from contraction
            if h > entropy_threshold:
                eligible_subgraph.nodes[n]["is_protected"] = True

    return contract_graph(eligible_subgraph, poi_key=poi_key, ledger=ledger)
