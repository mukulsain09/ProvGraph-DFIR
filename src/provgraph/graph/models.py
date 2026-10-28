"""Data models for ProvGraph-DFIR event-centric provenance graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EventNode:
    """Immutable representation of an event vertex with strict total order."""

    event_key: str
    host_name: str
    channel: str
    record_id: int
    timestamp_epoch: float
    timestamp_utc: str
    event_type: str
    event_id: int
    process_guid: str | None = None
    parent_process_guid: str | None = None
    target_object: str | None = None
    hashes: str | None = None
    raw_payload: str = ""

    def __lt__(self, other: EventNode) -> bool:
        """Enforces Definition 2 (Strict Total Order) to guarantee DAG acyclicity."""
        if not isinstance(other, EventNode):
            return NotImplemented
        if self.timestamp_epoch != other.timestamp_epoch:
            return self.timestamp_epoch < other.timestamp_epoch
        if self.host_name != other.host_name:
            return self.host_name < other.host_name
        if self.channel != other.channel:
            return self.channel < other.channel
        return self.record_id < other.record_id

    def to_dict(self) -> dict[str, Any]:
        """Serializes node attributes for NetworkX graph attribution."""
        return {
            "event_key": self.event_key,
            "host_name": self.host_name,
            "channel": self.channel,
            "record_id": self.record_id,
            "timestamp_epoch": self.timestamp_epoch,
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type,
            "event_id": self.event_id,
            "process_guid": self.process_guid,
            "parent_process_guid": self.parent_process_guid,
            "target_object": self.target_object,
            "hashes": self.hashes,
        }


@dataclass
class MacroEdge:
    """Structured macro-edge representing a collapsed linear chain of events."""

    macro_edge_id: str
    source_event_key: str
    target_event_key: str
    relation_type: str
    event_count: int
    start_time_epoch: float
    end_time_epoch: float
    ordered_event_keys: list[str] = field(default_factory=list)
    serialized_subgraph_json: str = "{}"

    def to_dict(self) -> dict[str, Any]:
        """Serializes macro-edge attributes for NetworkX edge attribution."""
        return {
            "macro_edge_id": self.macro_edge_id,
            "is_macro": True,
            "relation_type": self.relation_type,
            "event_count": self.event_count,
            "start_time_epoch": self.start_time_epoch,
            "end_time_epoch": self.end_time_epoch,
            "ordered_event_keys": self.ordered_event_keys,
            "serialized_subgraph_json": self.serialized_subgraph_json,
        }


@dataclass(frozen=True)
class ProcessRecord:
    """Normalized process metadata tracked by ProcessGuid."""

    process_guid: str
    process_id: int
    image_path: str
    host_name: str
    created_at_utc: str
    command_line: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    user_sid: str | None = None
    terminated_at_utc: str | None = None
