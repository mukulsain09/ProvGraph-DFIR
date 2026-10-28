"""Unit tests for Shannon relation entropy calculation and the Entropy Inversion Hypothesis."""

from __future__ import annotations

import networkx as nx

from provgraph.contraction.entropy_eval import (
    calculate_node_relation_entropy,
    entropy_guided_contraction,
    evaluate_entropy_saliency_correlation,
)


def test_shannon_entropy_calculation() -> None:
    g = nx.DiGraph()

    # Node with single relation (uniform attack burst: 10 file writes)
    g.add_node("burst_node")
    for i in range(10):
        src = f"src_{i}"
        g.add_node(src)
        g.add_edge(src, "burst_node", relation_type="WRITES_FILE")

    h_burst = calculate_node_relation_entropy(g, "burst_node")
    # 100% WRITES_FILE -> p=1.0 -> H = -1.0 * log2(1.0) = 0.0
    assert h_burst == 0.0

    # Node with 2 equally balanced relations (50/50)
    g.add_node("balanced_2")
    g.add_edge("s1", "balanced_2", relation_type="WRITES_FILE")
    g.add_edge("s2", "balanced_2", relation_type="OPENS_SOCKET")
    h_balanced_2 = calculate_node_relation_entropy(g, "balanced_2")
    # p1=0.5, p2=0.5 -> H = -(0.5*(-1) + 0.5*(-1)) = 1.0 bit
    assert h_balanced_2 == 1.0

    # Node with 4 equally balanced relations (25% each)
    g.add_node("balanced_4")
    g.add_edge("s1", "balanced_4", relation_type="WRITES_FILE")
    g.add_edge("s2", "balanced_4", relation_type="OPENS_SOCKET")
    g.add_edge("s3", "balanced_4", relation_type="LOADS_IMAGE")
    g.add_edge("s4", "balanced_4", relation_type="MODIFIES_REG")
    h_balanced_4 = calculate_node_relation_entropy(g, "balanced_4")
    # p=0.25 -> log2(0.25) = -2 -> H = 2.0 bits
    assert h_balanced_4 == 2.0


def test_entropy_inversion_hypothesis_verification() -> None:
    """Verifies that high-volume attack bursts yield lower entropy than benign OS churn."""
    g = nx.DiGraph()

    # Attack burst: ransomware modifying 20 files
    attack_nodes: set[str] = set()
    for i in range(20):
        attacker_event = f"ransomware_write_{i}"
        g.add_node(attacker_event)
        attack_nodes.add(attacker_event)
        g.add_edge("malware_proc", attacker_event, relation_type="WRITES_FILE")

    # Benign OS churn: svchost touching multiple resource types
    benign_nodes: set[str] = set()
    os_event = "svchost_churn"
    g.add_node(os_event)
    benign_nodes.add(os_event)
    g.add_edge("svchost_proc", os_event, relation_type="WRITES_FILE")
    g.add_edge(os_event, "socket_out", relation_type="OPENS_SOCKET")
    g.add_edge(os_event, "reg_key", relation_type="MODIFIES_REG")
    g.add_edge(os_event, "dll_load", relation_type="LOADS_IMAGE")

    eval_result = evaluate_entropy_saliency_correlation(g, ground_truth_attack_nodes=attack_nodes)

    # Attack nodes have lower entropy than benign system noise
    assert eval_result["entropy_inversion_detected"] is True
    assert eval_result["mean_attack_entropy"] < eval_result["mean_benign_entropy"]


def test_entropy_guided_contraction() -> None:
    g = nx.DiGraph()
    u = "source"
    v = "mid"
    w = "sink"

    g.add_node(u, process_guid="{P}", timestamp_epoch=1.0)
    g.add_node(v, process_guid="{P}", timestamp_epoch=2.0)
    g.add_node(w, process_guid="{P}", timestamp_epoch=3.0)

    g.add_edge(u, v, relation_type="WRITES_FILE", is_macro=False)
    g.add_edge(v, w, relation_type="WRITES_FILE", is_macro=False)

    contracted, macros = entropy_guided_contraction(g, poi_key=w, entropy_threshold=0.5)
    assert contracted.number_of_nodes() == 2
    assert len(macros) == 1
