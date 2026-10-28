"""Point of Interest (PoI) selection utilities."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


def find_poi_by_key(graph: nx.DiGraph, event_key: str) -> str:
    """Finds PoI by exact event key."""
    if event_key in graph:
        return event_key
    raise KeyError(f"Event key '{event_key}' not found in graph.")


def find_poi_by_predicate(
    graph: nx.DiGraph, predicate: Callable[[dict[str, Any]], bool]
) -> str | None:
    """Finds the first node matching a custom filter predicate.

    Nodes are evaluated in deterministic strict order.
    """
    sorted_nodes = sorted(
        graph.nodes(data=True),
        key=lambda item: (
            item[1].get("timestamp_epoch", 0.0),
            item[1].get("host_name", ""),
            item[1].get("channel", ""),
            item[1].get("record_id", 0),
        ),
    )
    for node_key, attrs in sorted_nodes:
        if predicate(attrs):
            return str(node_key)
    return None


def find_poi_by_event_id(graph: nx.DiGraph, event_id: int) -> str | None:
    """Finds the first event with a specific Windows Event ID."""
    res = find_poi_by_predicate(graph, lambda attrs: attrs.get("event_id") == event_id)
    return str(res) if res is not None else None
