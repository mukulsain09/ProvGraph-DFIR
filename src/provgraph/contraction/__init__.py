"""Lossless hierarchical contraction, expansion, and entropy evaluation package."""

from provgraph.contraction.entropy_eval import (
    calculate_graph_entropy_distribution,
    calculate_node_relation_entropy,
    entropy_guided_contraction,
    evaluate_entropy_saliency_correlation,
)
from provgraph.contraction.expansion import expand_macro_edge
from provgraph.contraction.lossless import contract_graph

__all__ = [
    "calculate_graph_entropy_distribution",
    "calculate_node_relation_entropy",
    "contract_graph",
    "entropy_guided_contraction",
    "evaluate_entropy_saliency_correlation",
    "expand_macro_edge",
]
