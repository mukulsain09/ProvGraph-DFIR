"""SQLite schema definitions for ProvGraph-DFIR evidence and macro-edge ledgers."""

INIT_LEDGER_SQL = """
CREATE TABLE IF NOT EXISTS processes (
    process_guid TEXT PRIMARY KEY,
    process_id INTEGER NOT NULL,
    image_path TEXT NOT NULL,
    command_line TEXT,
    parent_process_guid TEXT,
    parent_process_id INTEGER,
    user_sid TEXT,
    host_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    terminated_at_utc TEXT
);

CREATE TABLE IF NOT EXISTS event_ledger (
    event_key TEXT PRIMARY KEY,
    host_name TEXT NOT NULL,
    channel TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    timestamp_utc TEXT NOT NULL,
    timestamp_epoch REAL NOT NULL,
    event_type TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    process_guid TEXT,
    parent_process_guid TEXT,
    target_object TEXT,
    hashes TEXT,
    raw_payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS macro_edges (
    macro_edge_id TEXT PRIMARY KEY,
    source_event_key TEXT NOT NULL,
    target_event_key TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    start_time_epoch REAL NOT NULL,
    end_time_epoch REAL NOT NULL,
    ordered_event_keys TEXT NOT NULL,
    serialized_subgraph_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS causal_edges (
    edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_event_key TEXT NOT NULL,
    target_event_key TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    time_delta REAL NOT NULL,
    confidence REAL DEFAULT 1.0,
    description TEXT,
    FOREIGN KEY(source_event_key) REFERENCES event_ledger(event_key),
    FOREIGN KEY(target_event_key) REFERENCES event_ledger(event_key)
);

CREATE INDEX IF NOT EXISTS idx_events_proc ON event_ledger(process_guid);
CREATE INDEX IF NOT EXISTS idx_events_time ON event_ledger(timestamp_epoch);
CREATE INDEX IF NOT EXISTS idx_events_target ON event_ledger(target_object);
CREATE INDEX IF NOT EXISTS idx_events_composite ON event_ledger(host_name, channel, record_id);
CREATE INDEX IF NOT EXISTS idx_macro_endpoints ON macro_edges(source_event_key, target_event_key);
CREATE INDEX IF NOT EXISTS idx_edges_source ON causal_edges(source_event_key);
CREATE INDEX IF NOT EXISTS idx_edges_target ON causal_edges(target_event_key);
CREATE INDEX IF NOT EXISTS idx_edges_src_tgt ON causal_edges(source_event_key, target_event_key);
"""
