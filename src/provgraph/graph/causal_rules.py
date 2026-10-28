"""Causal edge inference rules for Windows Sysmon telemetry."""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import NamedTuple

from provgraph.graph.models import EventNode

logger = logging.getLogger(__name__)


class RelationType(StrEnum):
    """Supported causal relation types."""

    SPAWNS = "SPAWNS"
    OPENS_SOCKET = "OPENS_SOCKET"
    LOADS_IMAGE = "LOADS_IMAGE"
    CREATES_THREAD = "CREATES_THREAD"
    WRITES_FILE = "WRITES_FILE"
    MODIFIES_REG = "MODIFIES_REG"
    DROPS_EXEC = "DROPS_EXEC"
    DROPS_DLL = "DROPS_DLL"
    INJECTED_EXEC = "INJECTED_EXEC"
    PROCESS_ACCESS = "PROCESS_ACCESS"
    SEQUENTIAL_EXEC = "SEQUENTIAL_EXEC"


class CausalInferenceResult(NamedTuple):
    """Result of causal edge evaluation."""

    relation: RelationType
    confidence: float
    description: str


def infer_causal_relation(u: EventNode, v: EventNode) -> CausalInferenceResult | None:
    """Evaluates whether an edge u -> v is causally justified under strict total ordering.

    Args:
        u: The candidate source (antecedent) event.
        v: The candidate target (consequent) event.

    Returns:
        CausalInferenceResult if a valid causal relation exists; None otherwise.
    """
    # Condition 1: Strict Total Order Monotonicity (Theorem 1 DAG guarantee)
    if not (u < v):
        return None

    # Rule 1: Process Creation Hierarchy (Parent Process -> Child Process Event 1)
    if v.event_id == 1 and u.process_guid and v.parent_process_guid:
        if u.process_guid == v.parent_process_guid:
            return CausalInferenceResult(
                RelationType.SPAWNS, 1.0, "Parent process spawned child process"
            )

    # Rule 2: Intra-process Action execution (Process Create / Anchor Event -> Action Event)
    if u.process_guid and u.process_guid == v.process_guid:
        if v.event_id == 3:
            return CausalInferenceResult(
                RelationType.OPENS_SOCKET, 1.0, "Process initiated network socket"
            )
        if v.event_id == 7:
            return CausalInferenceResult(
                RelationType.LOADS_IMAGE, 1.0, "Process loaded image/library"
            )
        if v.event_id == 8:
            return CausalInferenceResult(
                RelationType.CREATES_THREAD, 1.0, "Process initiated remote thread injection"
            )
        if v.event_id == 10:
            return CausalInferenceResult(
                RelationType.PROCESS_ACCESS,
                1.0,
                "Process accessed memory or handle of target process",
            )
        if v.event_id == 11:
            return CausalInferenceResult(
                RelationType.WRITES_FILE, 1.0, "Process created or modified file"
            )
        if v.event_id in (12, 13):
            return CausalInferenceResult(
                RelationType.MODIFIES_REG, 1.0, "Process modified registry key/value"
            )

    # Rule 3: File dropped by process then executed (Event 11 -> Event 1)
    if u.event_id == 11 and v.event_id == 1:
        if (
            u.target_object
            and v.target_object
            and u.target_object.strip().lower() == v.target_object.strip().lower()
        ):
            return CausalInferenceResult(
                RelationType.DROPS_EXEC, 0.95, "File dropped by process executed as new image"
            )

    # Rule 4: File dropped by process then loaded as library (Event 11 -> Event 7)
    if u.event_id == 11 and v.event_id == 7:
        if (
            u.target_object
            and v.target_object
            and u.target_object.strip().lower() == v.target_object.strip().lower()
        ):
            return CausalInferenceResult(
                RelationType.DROPS_DLL, 0.95, "File dropped by process loaded as library"
            )

    # Rule 5: Cross-Process Injection (Event 8 -> Activity in Target Process)
    if u.event_id == 8 and u.target_object and v.process_guid:
        # For Event 8, target_object stores TargetProcessGuid
        if u.target_object == v.process_guid:
            return CausalInferenceResult(
                RelationType.INJECTED_EXEC, 0.90, "Activity executed by injected target process"
            )

    return None
