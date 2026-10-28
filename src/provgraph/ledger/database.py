"""SQLite database interface for the immutable evidence ledger."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from provgraph.graph.models import EventNode, MacroEdge, ProcessRecord
from provgraph.ledger.schema import INIT_LEDGER_SQL

logger = logging.getLogger(__name__)


class EvidenceLedger:
    """Thread-safe SQLite manager for forensic events, processes, and macro-edges."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None
        self.init_db()

    @property
    def connection(self) -> sqlite3.Connection:
        """Returns the active SQLite connection, opening it if necessary."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            # Enable WAL mode for high concurrent read performance if on-disk
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA synchronous=NORMAL;")
        return self._conn

    def init_db(self) -> None:
        """Initializes tables and indexes."""
        with self.connection:
            self.connection.executescript(INIT_LEDGER_SQL)
        logger.debug("Database initialized at %s", self.db_path)

    def close(self) -> None:
        """Closes the underlying SQLite connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> EvidenceLedger:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def insert_process(self, proc: ProcessRecord) -> None:
        """Inserts or replaces a process record."""
        sql = """
        INSERT INTO processes (
            process_guid, process_id, image_path, command_line,
            parent_process_guid, parent_process_id, user_sid,
            host_name, created_at_utc, terminated_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(process_guid) DO UPDATE SET
            terminated_at_utc = excluded.terminated_at_utc
        """
        with self.connection:
            self.connection.execute(
                sql,
                (
                    proc.process_guid,
                    proc.process_id,
                    proc.image_path,
                    proc.command_line,
                    proc.parent_process_guid,
                    proc.parent_process_id,
                    proc.user_sid,
                    proc.host_name,
                    proc.created_at_utc,
                    proc.terminated_at_utc,
                ),
            )

    def insert_processes_batch(self, procs: Sequence[ProcessRecord]) -> None:
        """Batch inserts process records."""
        if not procs:
            return
        sql = """
        INSERT INTO processes (
            process_guid, process_id, image_path, command_line,
            parent_process_guid, parent_process_id, user_sid,
            host_name, created_at_utc, terminated_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(process_guid) DO UPDATE SET
            terminated_at_utc = excluded.terminated_at_utc
        """
        rows = [
            (
                p.process_guid,
                p.process_id,
                p.image_path,
                p.command_line,
                p.parent_process_guid,
                p.parent_process_id,
                p.user_sid,
                p.host_name,
                p.created_at_utc,
                p.terminated_at_utc,
            )
            for p in procs
        ]
        with self.connection:
            self.connection.executemany(sql, rows)

    def insert_event(self, event: EventNode) -> None:
        """Inserts a single event record."""
        sql = """
        INSERT OR IGNORE INTO event_ledger (
            event_key, host_name, channel, record_id,
            timestamp_utc, timestamp_epoch, event_type, event_id,
            process_guid, parent_process_guid, target_object,
            hashes, raw_payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.connection:
            self.connection.execute(
                sql,
                (
                    event.event_key,
                    event.host_name,
                    event.channel,
                    event.record_id,
                    event.timestamp_utc,
                    event.timestamp_epoch,
                    event.event_type,
                    event.event_id,
                    event.process_guid,
                    event.parent_process_guid,
                    event.target_object,
                    event.hashes,
                    event.raw_payload,
                ),
            )

    def insert_events_batch(self, events: Sequence[EventNode]) -> None:
        """Batch inserts event records."""
        if not events:
            return
        sql = """
        INSERT OR IGNORE INTO event_ledger (
            event_key, host_name, channel, record_id,
            timestamp_utc, timestamp_epoch, event_type, event_id,
            process_guid, parent_process_guid, target_object,
            hashes, raw_payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (
                e.event_key,
                e.host_name,
                e.channel,
                e.record_id,
                e.timestamp_utc,
                e.timestamp_epoch,
                e.event_type,
                e.event_id,
                e.process_guid,
                e.parent_process_guid,
                e.target_object,
                e.hashes,
                e.raw_payload,
            )
            for e in events
        ]
        with self.connection:
            self.connection.executemany(sql, rows)

    def insert_macro_edge(self, macro: MacroEdge) -> None:
        """Inserts a macro-edge with ordered event keys and serialized geometry."""
        sql = """
        INSERT OR REPLACE INTO macro_edges (
            macro_edge_id, source_event_key, target_event_key,
            relation_type, event_count, start_time_epoch, end_time_epoch,
            ordered_event_keys, serialized_subgraph_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.connection:
            self.connection.execute(
                sql,
                (
                    macro.macro_edge_id,
                    macro.source_event_key,
                    macro.target_event_key,
                    macro.relation_type,
                    macro.event_count,
                    macro.start_time_epoch,
                    macro.end_time_epoch,
                    json.dumps(macro.ordered_event_keys),
                    macro.serialized_subgraph_json,
                ),
            )

    def get_event(self, event_key: str) -> EventNode | None:
        """Fetches a single event by composite key."""
        cursor = self.connection.execute(
            "SELECT * FROM event_ledger WHERE event_key = ?", (event_key,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

    def get_events_by_keys(self, keys: Sequence[str]) -> list[EventNode]:
        """Fetches multiple events matching a list of composite keys using chunked queries."""
        if not keys:
            return []
        results: list[EventNode] = []
        chunk_size = 500
        for i in range(0, len(keys), chunk_size):
            chunk = keys[i : i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            sql = f"SELECT * FROM event_ledger WHERE event_key IN ({placeholders})"
            cursor = self.connection.execute(sql, tuple(chunk))
            results.extend(self._row_to_event(row) for row in cursor.fetchall())
        return results

    def get_all_events(self) -> list[EventNode]:
        """Retrieves all ingested events ordered strictly by timestamp_epoch."""
        sql = """
        SELECT * FROM event_ledger
        ORDER BY timestamp_epoch ASC, host_name ASC, channel ASC, record_id ASC
        """
        cursor = self.connection.execute(sql)
        return [self._row_to_event(row) for row in cursor.fetchall()]

    def get_macro_edge(self, macro_edge_id: str) -> MacroEdge | None:
        """Retrieves a macro-edge and deserializes its ordered event keys."""
        cursor = self.connection.execute(
            "SELECT * FROM macro_edges WHERE macro_edge_id = ?", (macro_edge_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return MacroEdge(
            macro_edge_id=row["macro_edge_id"],
            source_event_key=row["source_event_key"],
            target_event_key=row["target_event_key"],
            relation_type=row["relation_type"],
            event_count=row["event_count"],
            start_time_epoch=row["start_time_epoch"],
            end_time_epoch=row["end_time_epoch"],
            ordered_event_keys=json.loads(row["ordered_event_keys"]),
            serialized_subgraph_json=row["serialized_subgraph_json"],
        )

    def count_events(self) -> int:
        """Returns the total number of ingested events."""
        cursor = self.connection.execute("SELECT COUNT(*) FROM event_ledger")
        return int(cursor.fetchone()[0])

    def count_processes(self) -> int:
        """Returns the total number of tracked processes."""
        cursor = self.connection.execute("SELECT COUNT(*) FROM processes")
        return int(cursor.fetchone()[0])

    def count_macro_edges(self) -> int:
        """Returns the total number of contracted macro-edges."""
        cursor = self.connection.execute("SELECT COUNT(*) FROM macro_edges")
        return int(cursor.fetchone()[0])

    def insert_causal_edges_batch(
        self, edges: Sequence[tuple[str, str, str, float, float, str]]
    ) -> None:
        """Batch inserts inferred causal edges into SQLite.

        Args:
            edges: Tuples of (source_key, target_key, relation_type, time_delta,
                   confidence, description).
        """
        if not edges:
            return
        sql = """
        INSERT INTO causal_edges (
            source_event_key, target_event_key, relation_type,
            time_delta, confidence, description
        ) VALUES (?, ?, ?, ?, ?, ?)
        """
        with self.connection:
            self.connection.executemany(sql, edges)

    def count_causal_edges(self) -> int:
        """Returns the total number of inferred causal edges in the ledger."""
        cursor = self.connection.execute("SELECT COUNT(*) FROM causal_edges")
        return int(cursor.fetchone()[0])

    def get_causal_edges_induced(self, event_keys: Sequence[str]) -> list[sqlite3.Row]:
        """Retrieves all causal edges whose endpoints both reside within event_keys."""
        if not event_keys:
            return []
        if len(event_keys) > 400:
            with self.connection:
                self.connection.execute(
                    "CREATE TEMP TABLE IF NOT EXISTS _temp_slice_keys (key TEXT PRIMARY KEY)"
                )
                self.connection.execute("DELETE FROM _temp_slice_keys")
                self.connection.executemany(
                    "INSERT OR IGNORE INTO _temp_slice_keys VALUES (?)",
                    [(k,) for k in event_keys],
                )
                cursor = self.connection.execute("""
                    SELECT source_event_key, target_event_key, relation_type,
                           time_delta, confidence, description
                    FROM causal_edges
                    WHERE source_event_key IN (SELECT key FROM _temp_slice_keys)
                      AND target_event_key IN (SELECT key FROM _temp_slice_keys)
                """)
                return list(cursor.fetchall())

        placeholders = ",".join("?" for _ in event_keys)
        sql = f"""
        SELECT source_event_key, target_event_key, relation_type,
               time_delta, confidence, description
        FROM causal_edges
        WHERE source_event_key IN ({placeholders})
          AND target_event_key IN ({placeholders})
        """
        params = tuple(event_keys) + tuple(event_keys)
        cursor = self.connection.execute(sql, params)
        return list(cursor.fetchall())

    def compute_cte_slice(
        self,
        poi_key: str,
        max_depth: int = 15,
        max_delta_sec: float = 3600.0,
        direction: str = "both",
    ) -> list[str]:
        """Executes causal slicing directly inside SQLite via recursive CTE query pushdown.

        Performs bounded graph traversal (backward root cause, forward impact, or both)
        without requiring prior instantiation of the entire telemetry graph in memory.

        Args:
            poi_key: Composite event key of the Point-of-Interest.
            max_depth: Maximum edge traversal depth K.
            max_delta_sec: Maximum temporal distance relative to PoI timestamp |t(v) - t(s)|.
            direction: Slicing direction: 'backward', 'forward', or 'both'.

        Returns:
            Deterministic sequence of event keys ordered by strict total order.
        """
        poi_event = self.get_event(poi_key)
        if poi_event is None:
            return []

        poi_time = poi_event.timestamp_epoch

        if direction == "backward":
            sql = """
            WITH RECURSIVE backward_slice(node_key, depth) AS (
                SELECT event_key, 0
                FROM event_ledger
                WHERE event_key = ?
                UNION
                SELECT e.source_event_key, b.depth + 1
                FROM causal_edges e
                JOIN backward_slice b ON e.target_event_key = b.node_key
                JOIN event_ledger el ON el.event_key = e.source_event_key
                WHERE b.depth < ?
                  AND abs(? - el.timestamp_epoch) <= ?
            )
            SELECT DISTINCT el.event_key
            FROM event_ledger el
            JOIN backward_slice bs ON el.event_key = bs.node_key
            ORDER BY el.timestamp_epoch ASC, el.host_name ASC, el.channel ASC, el.record_id ASC
            """
            params: tuple[Any, ...] = (poi_key, max_depth, poi_time, max_delta_sec)

        elif direction == "forward":
            sql = """
            WITH RECURSIVE forward_slice(node_key, depth) AS (
                SELECT event_key, 0
                FROM event_ledger
                WHERE event_key = ?
                UNION
                SELECT e.target_event_key, f.depth + 1
                FROM causal_edges e
                JOIN forward_slice f ON e.source_event_key = f.node_key
                JOIN event_ledger el ON el.event_key = e.target_event_key
                WHERE f.depth < ?
                  AND abs(el.timestamp_epoch - ?) <= ?
            )
            SELECT DISTINCT el.event_key
            FROM event_ledger el
            JOIN forward_slice fs ON el.event_key = fs.node_key
            ORDER BY el.timestamp_epoch ASC, el.host_name ASC, el.channel ASC, el.record_id ASC
            """
            params = (poi_key, max_depth, poi_time, max_delta_sec)

        else:  # 'both'
            sql = """
            WITH RECURSIVE
            backward_slice(node_key, depth) AS (
                SELECT event_key, 0
                FROM event_ledger
                WHERE event_key = ?
                UNION
                SELECT e.source_event_key, b.depth + 1
                FROM causal_edges e
                JOIN backward_slice b ON e.target_event_key = b.node_key
                JOIN event_ledger el ON el.event_key = e.source_event_key
                WHERE b.depth < ?
                  AND abs(? - el.timestamp_epoch) <= ?
            ),
            forward_slice(node_key, depth) AS (
                SELECT event_key, 0
                FROM event_ledger
                WHERE event_key = ?
                UNION
                SELECT e.target_event_key, f.depth + 1
                FROM causal_edges e
                JOIN forward_slice f ON e.source_event_key = f.node_key
                JOIN event_ledger el ON el.event_key = e.target_event_key
                WHERE f.depth < ?
                  AND abs(el.timestamp_epoch - ?) <= ?
            )
            SELECT DISTINCT el.event_key
            FROM event_ledger el
            WHERE el.event_key IN (
                SELECT node_key FROM backward_slice
                UNION
                SELECT node_key FROM forward_slice
            )
            ORDER BY el.timestamp_epoch ASC, el.host_name ASC, el.channel ASC, el.record_id ASC
            """
            params = (
                poi_key,
                max_depth,
                poi_time,
                max_delta_sec,
                poi_key,
                max_depth,
                poi_time,
                max_delta_sec,
            )

        cursor = self.connection.execute(sql, params)
        return [r["event_key"] for r in cursor.fetchall()]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> EventNode:
        return EventNode(
            event_key=row["event_key"],
            host_name=row["host_name"],
            channel=row["channel"],
            record_id=row["record_id"],
            timestamp_utc=row["timestamp_utc"],
            timestamp_epoch=row["timestamp_epoch"],
            event_type=row["event_type"],
            event_id=row["event_id"],
            process_guid=row["process_guid"],
            parent_process_guid=row["parent_process_guid"],
            target_object=row["target_object"],
            hashes=row["hashes"],
            raw_payload=row["raw_payload"],
        )
