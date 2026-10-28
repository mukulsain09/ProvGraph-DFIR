"""Ingestion module for Mordor and Sysmon JSON telemetry."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from provgraph.graph.models import EventNode, ProcessRecord
from provgraph.ledger.database import EvidenceLedger

logger = logging.getLogger(__name__)

EVENT_TYPE_MAP: dict[int, str] = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    7: "ImageLoaded",
    8: "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryObject",
    13: "RegistryValueSet",
    22: "DnsQuery",
}


class MordorLoader:
    """Parses and normalizes Mordor / Sysmon JSON logs into the SQLite Evidence Ledger."""

    def __init__(self, ledger: EvidenceLedger) -> None:
        self.ledger = ledger

    def load_file(self, file_path: Path | str, batch_size: int = 1000) -> tuple[int, int]:
        """Loads a JSON or JSONL file into the evidence ledger.

        Args:
            file_path: Path to the telemetry file.
            batch_size: Number of records to insert per database transaction.

        Returns:
            Tuple of (total_events_ingested, total_processes_indexed).
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Telemetry file not found: {path}")

        events_batch: list[EventNode] = []
        procs_batch: list[ProcessRecord] = []
        total_events = 0
        total_procs = 0

        with path.open("r", encoding="utf-8", errors="replace") as f:
            first_char = f.read(1)
            f.seek(0)
            if first_char == "[":
                records = json.load(f)
                iterator: Iterator[dict[str, Any]] = iter(records)
            else:
                iterator = (json.loads(line) for line in f if line.strip())

            for line_idx, raw in enumerate(iterator, start=1):
                event, proc = self.parse_record(raw, fallback_record_id=line_idx)
                if event:
                    events_batch.append(event)
                    total_events += 1
                if proc:
                    procs_batch.append(proc)
                    total_procs += 1

                if len(events_batch) >= batch_size:
                    self.ledger.insert_events_batch(events_batch)
                    events_batch.clear()

                if len(procs_batch) >= batch_size:
                    self.ledger.insert_processes_batch(procs_batch)
                    procs_batch.clear()

        # Flush remaining
        if events_batch:
            self.ledger.insert_events_batch(events_batch)
        if procs_batch:
            self.ledger.insert_processes_batch(procs_batch)

        logger.info(
            "Ingestion complete: %d events and %d processes indexed from %s",
            total_events,
            total_procs,
            path.name,
        )
        return total_events, total_procs

    def parse_record(
        self, record: dict[str, Any], fallback_record_id: int = 0
    ) -> tuple[EventNode | None, ProcessRecord | None]:
        """Normalizes a raw Mordor JSON record into an EventNode and optional ProcessRecord."""
        event_data: dict[str, Any] = record.get("EventData", {})
        if not event_data and "data" in record and isinstance(record["data"], dict):
            event_data = record["data"]

        def get_val(key: str) -> Any:
            v = event_data.get(key)
            if v is not None:
                return v
            return record.get(key)

        # 1. Resolve host and channel
        host_name = None
        host_field = record.get("host")
        if isinstance(host_field, dict):
            host_name = host_field.get("name")
        elif isinstance(host_field, str):
            host_name = host_field
        host_name = (
            host_name
            or record.get("Computer")
            or record.get("ComputerName")
            or record.get("Hostname")
            or record.get("Domain")
            or "unknown-host"
        )

        channel = None
        log_field = record.get("log")
        if isinstance(log_field, dict):
            channel = log_field.get("name")
        elif isinstance(log_field, str):
            channel = log_field
        channel = (
            channel
            or record.get("Channel")
            or record.get("SourceName")
            or "Microsoft-Windows-Sysmon/Operational"
        )

        # 2. Resolve Event ID and Record ID
        event_field = record.get("event")
        if isinstance(event_field, dict):
            event_id_raw = record.get("EventID") or event_field.get("code", 0)
            rec_id_raw = (
                record.get("RecordNumber")
                or record.get("record_number")
                or record.get("EventRecordID")
                or event_field.get("record_id", 0)
            )
        else:
            event_id_raw = record.get("EventID", 0)
            rec_id_raw = (
                record.get("RecordNumber")
                or record.get("record_number")
                or record.get("EventRecordID", 0)
            )

        try:
            event_id = int(event_id_raw)
        except (ValueError, TypeError):
            return None, None

        try:
            record_id = int(rec_id_raw)
            if record_id <= 0 and fallback_record_id > 0:
                record_id = fallback_record_id
        except (ValueError, TypeError):
            record_id = fallback_record_id

        # 3. Resolve timestamp
        time_created = record.get("TimeCreated")
        sys_time = time_created.get("SystemTime") if isinstance(time_created, dict) else None
        ts_utc = (
            get_val("@timestamp")
            or get_val("UtcTime")
            or get_val("EventTime")
            or sys_time
            or datetime.now(UTC).isoformat()
        )
        epoch = self._parse_iso_or_utc(ts_utc)

        # 4. Extract forensic entities
        proc_guid = (
            get_val("ProcessGuid")
            or get_val("SourceProcessGuid")
            or get_val("SourceProcessGUID")
        )
        parent_proc_guid = (
            get_val("ParentProcessGuid")
            or get_val("ParentProcessGUID")
            or (get_val("TargetProcessGuid") if event_id == 10 else None)
            or (get_val("TargetProcessGUID") if event_id == 10 else None)
        )
        event_type = EVENT_TYPE_MAP.get(event_id, f"SysmonEvent_{event_id}")

        # Resolve target object contextually
        target_obj: str | None = None
        if event_id == 1:
            target_obj = get_val("Image")
        elif event_id == 3:
            dest_ip = get_val("DestinationIp") or ""
            dest_port = get_val("DestinationPort") or ""
            target_obj = f"{dest_ip}:{dest_port}" if dest_ip else None
        elif event_id == 7:
            target_obj = get_val("ImageLoaded")
        elif event_id == 8:
            target_obj = get_val("TargetProcessGuid")
        elif event_id == 10:
            target_obj = (
                get_val("TargetImage")
                or get_val("TargetProcessGuid")
                or get_val("TargetProcessGUID")
            )
        elif event_id == 11:
            target_obj = get_val("TargetFilename")
        elif event_id in (12, 13):
            target_obj = get_val("TargetObject")

        if not target_obj:
            target_obj = (
                get_val("TargetFilename")
                or get_val("Image")
                or get_val("Application")
                or get_val("ObjectName")
            )

        event_key = f"{host_name}:{channel}:{record_id}"

        event_node = EventNode(
            event_key=event_key,
            host_name=host_name,
            channel=channel,
            record_id=record_id,
            timestamp_epoch=epoch,
            timestamp_utc=str(ts_utc),
            event_type=event_type,
            event_id=event_id,
            process_guid=str(proc_guid) if proc_guid else None,
            parent_process_guid=str(parent_proc_guid) if parent_proc_guid else None,
            target_object=str(target_obj) if target_obj else None,
            hashes=get_val("Hashes"),
            raw_payload=json.dumps(record),
        )

        # If ProcessCreate (Event 1), also produce ProcessRecord
        proc_record: ProcessRecord | None = None
        if event_id == 1 and proc_guid:
            pid_raw = get_val("ProcessId")
            parent_pid_raw = get_val("ParentProcessId")
            try:
                pid = int(pid_raw) if pid_raw else 0
            except (ValueError, TypeError):
                pid = 0
            try:
                ppid = int(parent_pid_raw) if parent_pid_raw else None
            except (ValueError, TypeError):
                ppid = None

            proc_record = ProcessRecord(
                process_guid=str(proc_guid),
                process_id=pid,
                image_path=str(get_val("Image") or "unknown"),
                command_line=get_val("CommandLine"),
                parent_process_guid=str(parent_proc_guid) if parent_proc_guid else None,
                parent_process_id=ppid,
                user_sid=get_val("User"),
                host_name=host_name,
                created_at_utc=str(ts_utc),
            )

        return event_node, proc_record

    @staticmethod
    def _parse_iso_or_utc(ts_str: str) -> float:
        """Parses UTC timestamp strings into epoch seconds."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        # Clean string
        cleaned = ts_str.strip()
        for fmt in formats:
            try:
                dt = datetime.strptime(cleaned, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt.timestamp()
            except ValueError:
                continue
        # Fallback to current timestamp
        return datetime.now(UTC).timestamp()
