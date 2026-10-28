"""Unit tests for MITRE ATT&CK Ground-Truth Step Recall verifier."""

from __future__ import annotations

import networkx as nx

from provgraph.contraction.lossless import contract_graph
from provgraph.evaluation.ground_truth import (
    GroundTruthStep,
    evaluate_attack_recall,
)


def test_ground_truth_step_matching() -> None:
    """Verifies that GroundTruthStep matching logic handles IDs, substrings, and predicates."""
    step = GroundTruthStep(
        step_id="S1",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        description="PowerShell process creation",
        expected_event_id=1,
        expected_target_substring="powershell.exe",
    )

    matching_attrs = {
        "event_id": 1,
        "target_object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "raw_payload": "powershell execution",
    }
    non_matching_event_id = {
        "event_id": 11,
        "target_object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    non_matching_target = {
        "event_id": 1,
        "target_object": "C:\\Windows\\System32\\cmd.exe",
    }

    assert step.matches(matching_attrs) is True
    assert step.matches(non_matching_event_id) is False
    assert step.matches(non_matching_target) is False


def test_evaluate_attack_recall_full_pipeline_preservation() -> None:
    """Verifies that 100% of telemetry-captured steps are preserved even through contraction."""
    raw_dag = nx.DiGraph()

    # Step 1: Cmd
    raw_dag.add_node(
        "e1",
        event_key="e1",
        event_id=1,
        process_guid="{P1}",
        target_object="C:\\cmd.exe",
        timestamp_epoch=1.0,
    )
    # Step 2: PowerShell
    raw_dag.add_node(
        "e2",
        event_key="e2",
        event_id=1,
        process_guid="{P2}",
        target_object="C:\\powershell.exe",
        timestamp_epoch=2.0,
    )
    # Step 3: File burst (leaves that will be contracted into a macro)
    for i in range(1, 5):
        k = f"f{i}"
        raw_dag.add_node(
            k,
            event_key=k,
            event_id=11,
            process_guid="{P2}",
            target_object=f"C:\\encrypted_{i}.wnry",
            timestamp_epoch=2.0 + i,
        )
        raw_dag.add_edge("e2", k, relation_type="WRITES_FILE", is_macro=False)

    raw_dag.add_edge("e1", "e2", relation_type="SPAWNS", is_macro=False)

    # Contract graph (leaves f1..f4 become a macro cluster)
    contracted, macros = contract_graph(raw_dag, poi_key="e2", enable_fanout=True)
    assert len(macros) == 1

    steps = [
        GroundTruthStep(
            step_id="S1",
            technique_id="T1059.003",
            technique_name="Cmd",
            tactic="Execution",
            description="Command line launch",
            expected_event_id=1,
            expected_target_substring="cmd.exe",
        ),
        GroundTruthStep(
            step_id="S2",
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="PowerShell execution",
            expected_event_id=1,
            expected_target_substring="powershell.exe",
        ),
        GroundTruthStep(
            step_id="S3",
            technique_id="T1486",
            technique_name="Data Encrypted",
            tactic="Impact",
            description="Ransomware encryption burst",
            expected_event_id=11,
            expected_target_substring=".wnry",
        ),
    ]

    result = evaluate_attack_recall(
        raw_dag=raw_dag,
        contracted_graph=contracted,
        scenario_name="Test Ransomware",
        ground_truth_steps=steps,
    )

    # All 3 steps are captured in telemetry
    assert result.total_ground_truth_steps == 3
    assert result.telemetry_captured_steps == 3
    assert result.telemetry_recall == 1.0

    # Even though S3 was collapsed inside a MacroCluster, it is 100% recovered
    assert result.pipeline_recovered_steps == 3
    assert result.pipeline_recall == 1.0
    assert len(result.telemetry_gaps) == 0


def test_evaluate_attack_recall_with_unlogged_telemetry_gap() -> None:
    """Verifies that sensor omissions correctly report R_telemetry < 1.0 and R_pipeline == 1.0."""
    raw_dag = nx.DiGraph()

    # Telemetry captures Step 1 and Step 2 only
    raw_dag.add_node(
        "e1",
        event_key="e1",
        event_id=1,
        process_guid="{P1}",
        target_object="C:\\cmd.exe",
        timestamp_epoch=1.0,
    )
    raw_dag.add_node(
        "e2",
        event_key="e2",
        event_id=1,
        process_guid="{P2}",
        target_object="C:\\powershell.exe",
        timestamp_epoch=2.0,
    )
    raw_dag.add_edge("e1", "e2", relation_type="SPAWNS", is_macro=False)

    contracted = raw_dag.copy()

    steps = [
        GroundTruthStep(
            step_id="S1",
            technique_id="T1059.003",
            technique_name="Cmd",
            tactic="Execution",
            description="Command line launch",
            expected_event_id=1,
            expected_target_substring="cmd.exe",
        ),
        GroundTruthStep(
            step_id="S2",
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="PowerShell execution",
            expected_event_id=1,
            expected_target_substring="powershell.exe",
        ),
        GroundTruthStep(
            step_id="S3",
            technique_id="T1003.001",
            technique_name="LSASS Access",
            tactic="Credential Access",
            description="Unlogged LSASS access step",
            expected_event_id=10,
            expected_target_substring="lsass.exe",
        ),
    ]

    result = evaluate_attack_recall(
        raw_dag=raw_dag,
        contracted_graph=contracted,
        scenario_name="Test Telemetry Gap",
        ground_truth_steps=steps,
    )

    # Telemetry captured 2 of 3 steps
    assert result.total_ground_truth_steps == 3
    assert result.telemetry_captured_steps == 2
    assert result.telemetry_recall == round(2 / 3, 4)

    # Pipeline preserved 100% of what telemetry captured
    assert result.pipeline_recovered_steps == 2
    assert result.pipeline_recall == 1.0
    assert len(result.telemetry_gaps) == 1
    assert "T1003.001" in result.telemetry_gaps[0]
