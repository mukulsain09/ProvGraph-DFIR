"""Constructs strict-order, event-centric Directed Acyclic Graphs (DAGs)."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from typing import TYPE_CHECKING

import networkx as nx

from provgraph.graph.causal_rules import infer_causal_relation
from provgraph.graph.models import EventNode

if TYPE_CHECKING:
    from provgraph.ledger.database import EvidenceLedger

logger = logging.getLogger(__name__)


class DAGBuilder:
    """Constructs mathematically verified Directed Acyclic Graphs from Windows events."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def build_graph(self, events: Sequence[EventNode]) -> nx.DiGraph:
        """Builds a time-expanded DAG from a collection of EventNodes.

        Uses indexed lookups (process hierarchy, file drops, thread injection)
        to construct edges in O(N log N) time without O(N^2) cartesian comparisons.

        Args:
            events: Sequence of event nodes to include.

        Returns:
            A networkx.DiGraph instance guaranteed to be acyclic.
        """
        self.graph.clear()
        if not events:
            return self.graph

        # Add all vertices
        for event in events:
            self.graph.add_node(event.event_key, **event.to_dict(), node_obj=event)

        # Indexing for efficient O(1) causal lookup
        proc_creates: dict[str, EventNode] = {}
        proc_events: dict[str, list[EventNode]] = defaultdict(list)
        file_creates: dict[str, list[EventNode]] = defaultdict(list)
        thread_injections: list[EventNode] = []

        for event in events:
            if event.process_guid:
                proc_events[event.process_guid].append(event)

            if event.event_id == 1 and event.process_guid:
                # Retain primary process creation event
                if (
                    event.process_guid not in proc_creates
                    or event < proc_creates[event.process_guid]
                ):
                    proc_creates[event.process_guid] = event

            elif event.event_id == 11 and event.target_object:
                norm_path = event.target_object.strip().lower()
                file_creates[norm_path].append(event)

            elif event.event_id == 8 and event.target_object:
                thread_injections.append(event)

        # For processes that were already running before logging began, anchor to earliest event
        for proc_guid, evt_list in proc_events.items():
            if proc_guid not in proc_creates and evt_list:
                proc_creates[proc_guid] = min(evt_list)

        # 1. Infer Process Hierarchy Edges (Parent Event 1 -> Child Event 1)
        for child_create in proc_creates.values():
            if child_create.parent_process_guid:
                parent_create = proc_creates.get(child_create.parent_process_guid)
                if parent_create:
                    self._try_add_edge(parent_create, child_create)

        # 2. Infer Intra-Process Action Edges (Process Event 1 -> Action Events)
        for proc_guid, act_list in proc_events.items():
            parent_proc = proc_creates.get(proc_guid)
            if parent_proc:
                for act in act_list:
                    if act.event_key != parent_proc.event_key:
                        self._try_add_edge(parent_proc, act)

        # 3. Infer File-to-Process / File-to-DLL Edges
        for event in events:
            if event.event_id in (1, 7) and event.target_object:
                norm_path = event.target_object.strip().lower()
                matching_drops = file_creates.get(norm_path, [])
                for drop in matching_drops:
                    if drop < event:
                        self._try_add_edge(drop, event)

        # 4. Infer Cross-Process Injection Edges
        for inj in thread_injections:
            target_guid = inj.target_object
            if target_guid and target_guid in proc_events:
                for target_act in proc_events[target_guid]:
                    if inj < target_act:
                        self._try_add_edge(inj, target_act)

        # Verify Theorem 1 (Strict DAG property)
        if not nx.is_directed_acyclic_graph(self.graph):
            cycle = nx.find_cycle(self.graph, orientation="original")
            raise RuntimeError(f"DAG invariant violated! Cycle detected: {cycle}")

        logger.info(
            "Constructed DAG with %d vertices and %d causal edges.",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )
        return self.graph

    def _try_add_edge(self, u: EventNode, v: EventNode) -> bool:
        """Evaluates causal relation and safely adds edge u -> v."""
        result = infer_causal_relation(u, v)
        if result is None:
            return False

        # Add directed edge with causal attributes
        self.graph.add_edge(
            u.event_key,
            v.event_key,
            relation_type=result.relation.value,
            confidence=result.confidence,
            description=result.description,
            time_delta=max(0.0, round(v.timestamp_epoch - u.timestamp_epoch, 6)),
            is_macro=False,
        )
        return True

    def extract_causal_edges(self) -> list[tuple[str, str, str, float, float, str]]:
        """Extracts all inferred edges for database persistence.

        Returns:
            Tuples of (source_key, target_key, relation_type, time_delta, confidence, description).
        """
        records: list[tuple[str, str, str, float, float, str]] = []
        for u, v, data in self.graph.edges(data=True):
            records.append(
                (
                    str(u),
                    str(v),
                    str(data.get("relation_type", "UNKNOWN")),
                    float(data.get("time_delta", 0.0)),
                    float(data.get("confidence", 1.0)),
                    str(data.get("description", "")),
                )
            )
        return records

    def persist_to_ledger(self, ledger: EvidenceLedger) -> int:
        """Inserts all inferred causal edges into the evidence ledger.

        Args:
            ledger: EvidenceLedger database instance.

        Returns:
            Number of causal edges persisted.
        """
        edges = self.extract_causal_edges()
        ledger.insert_causal_edges_batch(edges)
        return len(edges)
