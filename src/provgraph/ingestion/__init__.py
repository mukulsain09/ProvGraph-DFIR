"""Ingestion engine for Windows DFIR logs."""

from provgraph.ingestion.mordor_loader import EVENT_TYPE_MAP, MordorLoader

__all__ = ["EVENT_TYPE_MAP", "MordorLoader"]
