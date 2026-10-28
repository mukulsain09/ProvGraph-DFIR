"""MITRE ATT&CK Ground-Truth Step Recall verifier for ProvGraph-DFIR."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GroundTruthStep:
    """Discrete adversary technique step expected in an attack scenario."""

    step_id: str
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    expected_event_id: int | None = None
    expected_target_substring: str | None = None
    predicate: Callable[[dict[str, Any]], bool] | None = None

    def matches(self, attrs: dict[str, Any]) -> bool:
        """Evaluates whether an event node or record satisfies this ground-truth step."""
        if self.predicate is not None:
            try:
                return bool(self.predicate(attrs))
            except Exception:
                return False

        if self.expected_event_id is not None:
            if attrs.get("event_id") != self.expected_event_id:
                return False

        if self.expected_target_substring is not None:
            target = str(attrs.get("target_object") or "").lower()
            payload = str(attrs.get("raw_payload") or "").lower()
            if not payload and "node_obj" in attrs and hasattr(attrs["node_obj"], "raw_payload"):
                payload = str(attrs["node_obj"].raw_payload or "").lower()
            substr = self.expected_target_substring.lower()
            if substr not in target and substr not in payload:
                return False

        return True


@dataclass
class AttackRecallEvaluation:
    """Quantitative results of ground-truth ATT&CK step recall verification."""

    scenario_name: str
    total_ground_truth_steps: int
    telemetry_captured_steps: int
    pipeline_recovered_steps: int
    telemetry_recall: float  # R_telemetry = captured / total
    pipeline_recall: float  # R_pipeline = recovered / captured
    steps_detail: list[dict[str, Any]] = field(default_factory=list)
    telemetry_gaps: list[str] = field(default_factory=list)


def evaluate_attack_recall(
    raw_dag: nx.DiGraph,
    contracted_graph: nx.DiGraph,
    scenario_name: str,
    ground_truth_steps: Sequence[GroundTruthStep],
) -> AttackRecallEvaluation:
    """Evaluates Telemetry Attack Path Recall (R_telemetry) and Pipeline Recall (R_pipeline).

    Implements Section 8.3 of ProvGraph-DFIR protocol to explicitly decouple
    sensor-level ETW omissions from algorithmic causality and contraction accuracy.

    Args:
        raw_dag: The full ingested time-expanded provenance graph.
        contracted_graph: The contracted causal slice (with active MacroEdges).
        scenario_name: Identifying name of the scenario.
        ground_truth_steps: Expected MITRE ATT&CK technique milestones.

    Returns:
        AttackRecallEvaluation with formal recall percentages and step breakdown.
    """
    total_steps = len(ground_truth_steps)
    if total_steps == 0:
        return AttackRecallEvaluation(
            scenario_name=scenario_name,
            total_ground_truth_steps=0,
            telemetry_captured_steps=0,
            pipeline_recovered_steps=0,
            telemetry_recall=1.0,
            pipeline_recall=1.0,
        )

    # Pre-index macro-edge constituent events in the contracted graph
    macro_constituent_nodes: dict[str, set[str]] = {}
    macro_subgraph_nodes: dict[str, dict[str, Any]] = {}

    for _, _, edge_data in contracted_graph.edges(data=True):
        if edge_data.get("is_macro"):
            m_id = str(edge_data.get("macro_edge_id", ""))
            ordered_keys = edge_data.get("ordered_event_keys", [])
            macro_constituent_nodes[m_id] = set(ordered_keys)

            subgraph_str = edge_data.get("serialized_subgraph_json", "{}")
            try:
                subgraph_data = json.loads(subgraph_str)
                macro_subgraph_nodes[m_id] = subgraph_data.get("nodes", {})
            except Exception:
                macro_subgraph_nodes[m_id] = {}

    captured_count = 0
    recovered_count = 0
    steps_detail: list[dict[str, Any]] = []
    telemetry_gaps: list[str] = []

    for step in ground_truth_steps:
        # 1. Search in Raw Ingested Telemetry
        matching_raw_key: str | None = None
        for node_key, attrs in raw_dag.nodes(data=True):
            if step.matches(attrs):
                matching_raw_key = node_key
                break

        in_telemetry = matching_raw_key is not None
        if in_telemetry:
            captured_count += 1
        else:
            telemetry_gaps.append(
                f"{step.technique_id} ({step.technique_name}): {step.description}"
            )

        # 2. Search in Contracted Graph (visible nodes or inside active macro-edges)
        in_pipeline = False
        matching_contracted_key: str | None = None

        if in_telemetry:
            # Check visible contracted nodes
            for node_key, attrs in contracted_graph.nodes(data=True):
                if step.matches(attrs):
                    in_pipeline = True
                    matching_contracted_key = node_key
                    break

            # If not in visible nodes, check macro constituents
            if not in_pipeline:
                for m_id, node_dict in macro_subgraph_nodes.items():
                    for sub_key, sub_attrs in node_dict.items():
                        if step.matches(sub_attrs):
                            in_pipeline = True
                            matching_contracted_key = f"inside_macro:{m_id}:{sub_key}"
                            break
                    if in_pipeline:
                        break

        if in_pipeline:
            recovered_count += 1

        steps_detail.append(
            {
                "step_id": step.step_id,
                "technique_id": step.technique_id,
                "technique_name": step.technique_name,
                "tactic": step.tactic,
                "description": step.description,
                "captured_in_telemetry": in_telemetry,
                "recovered_in_pipeline": in_pipeline,
                "matched_node": matching_contracted_key or matching_raw_key,
            }
        )

    r_telemetry = captured_count / total_steps
    r_pipeline = (recovered_count / captured_count) if captured_count > 0 else 1.0

    return AttackRecallEvaluation(
        scenario_name=scenario_name,
        total_ground_truth_steps=total_steps,
        telemetry_captured_steps=captured_count,
        pipeline_recovered_steps=recovered_count,
        telemetry_recall=round(r_telemetry, 4),
        pipeline_recall=round(r_pipeline, 4),
        steps_detail=steps_detail,
        telemetry_gaps=telemetry_gaps,
    )


# ---------------------------------------------------------------------------
# Pre-Configured Ground-Truth Scenarios for Thesis Benchmarking
# ---------------------------------------------------------------------------

GROUND_TRUTH_CATALOG: dict[str, list[GroundTruthStep]] = {
    "Empire VBS Launcher": [
        GroundTruthStep(
            step_id="S1",
            technique_id="T1059.005",
            technique_name="Visual Basic",
            tactic="Execution",
            description="VBS launcher script executed by wscript.exe",
            expected_event_id=1,
            expected_target_substring="wscript.exe",
        ),
        GroundTruthStep(
            step_id="S2",
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="PowerShell spawned with base64 encoded stager",
            expected_event_id=1,
            expected_target_substring="powershell.exe",
        ),
        GroundTruthStep(
            step_id="S3",
            technique_id="T1082",
            technique_name="System Information Discovery",
            tactic="Discovery",
            description="Reconnaissance command whoami.exe executed",
            expected_event_id=1,
            expected_target_substring="whoami.exe",
        ),
    ],
    "BITSAdmin Download Cradle": [
        GroundTruthStep(
            step_id="S1",
            technique_id="T1197",
            technique_name="BITS Jobs",
            tactic="Defense Evasion",
            description="BITSAdmin executed to stage download job",
            expected_event_id=1,
            expected_target_substring="bitsadmin.exe",
        ),
        GroundTruthStep(
            step_id="S2",
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            tactic="Command and Control",
            description="Remote payload or staging buffer written to disk by BITS transfer",
            expected_event_id=11,
            predicate=lambda a: a.get("event_id") == 11
            and any(
                term in str(a.get("target_object") or "").lower()
                for term in ("bit", "ps1", "psh", "flag")
            ),
        ),
    ],
    "Empire Mimikatz LSASS Dump": [
        GroundTruthStep(
            step_id="S1",
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="Interactive PowerShell Empire stager session",
            predicate=lambda a: "powershell" in str(a.get("target_object") or "").lower()
            or "powershell" in str(a.get("raw_payload") or "").lower(),
        ),
        GroundTruthStep(
            step_id="S2",
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="Credential Access",
            description="ProcessAccess memory handle acquisition targeting lsass.exe",
            expected_event_id=10,
            expected_target_substring="lsass",
        ),
        GroundTruthStep(
            step_id="S3",
            technique_id="T1033",
            technique_name="System Owner/User Discovery",
            tactic="Discovery",
            description="whoami execution spawned by stager",
            expected_event_id=1,
            expected_target_substring="whoami.exe",
        ),
    ],
    "Metasploit Lateral & Credential Dumping": [
        GroundTruthStep(
            step_id="S1",
            technique_id="T1059.003",
            technique_name="Windows Command Shell",
            tactic="Execution",
            description="Initial command shell execution",
            expected_target_substring="cmd.exe",
        ),
        GroundTruthStep(
            step_id="S2",
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="Credential Access",
            description="Payload scraping credentials from lsass.exe",
            expected_event_id=10,
            expected_target_substring="lsass",
        ),
        GroundTruthStep(
            step_id="S3",
            technique_id="T1070.001",
            technique_name="Clear Windows Event Logs",
            tactic="Defense Evasion",
            description="Log clearing utility wevtutil.exe executed",
            expected_event_id=1,
            expected_target_substring="wevtutil",
        ),
    ],
    "Scenario B: High-Volume Ransomware Burst": [
        GroundTruthStep(
            step_id="S1",
            technique_id="T1059.003",
            technique_name="Windows Command Shell",
            tactic="Execution",
            description="Ransomware launch wrapper cmd.exe",
            expected_event_id=1,
            expected_target_substring="cmd.exe",
        ),
        GroundTruthStep(
            step_id="S2",
            technique_id="T1204.002",
            technique_name="Malicious File",
            tactic="Execution",
            description="WannaCrypt ransomware binary execution",
            expected_event_id=1,
            expected_target_substring="wannacrypt.exe",
        ),
        GroundTruthStep(
            step_id="S3",
            technique_id="T1547.001",
            technique_name="Registry Run Keys",
            tactic="Persistence",
            description="Registry persistence / canary value modification",
            expected_event_id=12,
            expected_target_substring="WannaCryptor",
        ),
        GroundTruthStep(
            step_id="S4",
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="Impact",
            description="High-volume file mass encryption burst",
            expected_event_id=11,
            expected_target_substring=".wnry",
        ),
        GroundTruthStep(
            step_id="S5",
            technique_id="T1491.001",
            technique_name="Internal Defacement",
            tactic="Impact",
            description="Ransom note dropped to victim desktop",
            expected_event_id=11,
            expected_target_substring="Please_Read_Me",
        ),
    ],
}
