"""Windows Event Log (EVTX / XML) ingestion parser for ProvGraph-DFIR.

Supports both direct binary EVTX container decoding (.evtx) and XML export parsing (.xml).
"""

from __future__ import annotations

import datetime
import logging
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING, Any

from provgraph.graph.models import EventNode, ProcessRecord

if TYPE_CHECKING:
    from provgraph.ledger.database import EvidenceLedger

logger = logging.getLogger(__name__)

# Constants for Windows Event Log Binary Format
EVTX_FILE_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"  # 0x00002a2a
FILETIME_EPOCH_DIFF = 11644473600.0  # Seconds between 1601-01-01 and 1970-01-01

EVENT_TYPE_MAP: dict[int, str] = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    7: "ImageLoaded",
    8: "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent",
    13: "RegistryEvent",
}


def detect_evtx_format(file_path: Path | str) -> str:
    """Detects whether a file is a binary EVTX container or an XML export.

    Args:
        file_path: Path to the Windows Event Log file.

    Returns:
        'binary' if file has the ElfFile\\0 magic header, otherwise 'xml'.
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Event log file not found: {p}")

    try:
        with open(p, "rb") as f:
            header = f.read(8)
            if header == EVTX_FILE_MAGIC:
                return "binary"
    except Exception as err:
        logger.debug("Failed to read header of %s: %s", p, err)

    return "xml"


class EVTXLoader:
    """Ingests Windows Sysmon event records from EVTX XML or EVTX binary containers."""

    def __init__(self, ledger: EvidenceLedger) -> None:
        self.ledger = ledger

    def load_file(self, file_path: Path | str) -> tuple[int, int]:
        """Automatically detects EVTX format and ingests events into the evidence ledger.

        Args:
            file_path: Path to .evtx binary file or .xml export.

        Returns:
            Tuple of (total_events_ingested, total_processes_ingested).
        """
        fmt = detect_evtx_format(file_path)
        if fmt == "binary":
            return self.load_binary_file(file_path)
        return self.load_xml_file(file_path)

    def load_xml_file(self, file_path: Path | str) -> tuple[int, int]:
        """Loads and ingests an XML export of Windows Event Logs.

        Args:
            file_path: Path to XML file.

        Returns:
            Tuple of (total_events_ingested, total_processes_ingested).
        """
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"EVTX XML file not found: {p}")

        content = p.read_text(encoding="utf-8", errors="replace")
        return self.load_xml_string(content)

    def load_xml_string(self, xml_content: str) -> tuple[int, int]:
        """Parses an XML string containing one or more <Event> elements.

        Args:
            xml_content: XML formatted event records.

        Returns:
            Tuple of (total_events_ingested, total_processes_ingested).
        """
        if not xml_content.strip().startswith("<Events>"):
            wrapped = f"<Events>{xml_content}</Events>"
        else:
            wrapped = xml_content

        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError as err:
            logger.error("Failed to parse EVTX XML: %s", err)
            return 0, 0

        event_nodes: list[EventNode] = []
        proc_records: list[ProcessRecord] = []

        for elem in root.findall(".//{*}Event") or root.findall(".//Event"):
            parsed = self._parse_event_element(elem)
            if parsed:
                node, proc = parsed
                event_nodes.append(node)
                if proc:
                    proc_records.append(proc)

        self.ledger.insert_events_batch(event_nodes)
        self.ledger.insert_processes_batch(proc_records)

        logger.info(
            "EVTX XML ingested: %d events, %d process entities.",
            len(event_nodes),
            len(proc_records),
        )
        return len(event_nodes), len(proc_records)

    def load_binary_file(self, file_path: Path | str) -> tuple[int, int]:
        """Parses a native Windows EVTX binary file into the immutable evidence ledger.

        Attempts to use python-evtx library if installed, otherwise uses pure-Python
        chunk/record extraction.

        Args:
            file_path: Path to binary .evtx file.

        Returns:
            Tuple of (total_events_ingested, total_processes_ingested).
        """
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"EVTX binary file not found: {p}")

        # Check if python-evtx library is installed in environment
        try:
            import Evtx.Evtx as python_evtx  # type: ignore[import-not-found,import-untyped]

            return self._load_via_python_evtx(p, python_evtx)
        except ImportError:
            pass

        return self._load_binary_chunks(p)

    def _load_via_python_evtx(self, p: Path, python_evtx: Any) -> tuple[int, int]:
        """Ingests EVTX binary records via python-evtx parser."""
        event_nodes: list[EventNode] = []
        proc_records: list[ProcessRecord] = []

        with python_evtx.Evtx(str(p)) as evtx:
            for record in evtx.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    target = root if root.tag.endswith("Event") else root.find(".//{*}Event")
                    if target is not None:
                        parsed = self._parse_event_element(target)
                        if parsed:
                            node, proc = parsed
                            event_nodes.append(node)
                            if proc:
                                proc_records.append(proc)
                except Exception as err:
                    logger.debug("Failed to decode EVTX record %s: %s", record.record_num(), err)

        self.ledger.insert_events_batch(event_nodes)
        self.ledger.insert_processes_batch(proc_records)

        logger.info(
            "EVTX binary ingested (python-evtx): %d events, %d process entities.",
            len(event_nodes),
            len(proc_records),
        )
        return len(event_nodes), len(proc_records)

    def _load_binary_chunks(self, p: Path) -> tuple[int, int]:
        """Pure-Python chunk/record extraction for binary EVTX files without dependencies."""
        event_nodes: list[EventNode] = []
        proc_records: list[ProcessRecord] = []

        with open(p, "rb") as f:
            header_bytes = f.read(4096)
            if not header_bytes.startswith(EVTX_FILE_MAGIC):
                raise ValueError(f"File {p} does not contain valid EVTX magic header.")

            chunk_size = 65536
            while True:
                chunk_bytes = f.read(chunk_size)
                if len(chunk_bytes) < 512:
                    break
                if not chunk_bytes.startswith(EVTX_CHUNK_MAGIC):
                    continue

                self._parse_evtx_chunk(chunk_bytes, event_nodes, proc_records)

        self.ledger.insert_events_batch(event_nodes)
        self.ledger.insert_processes_batch(proc_records)

        logger.info(
            "EVTX binary ingested (native chunk reader): %d events, %d process entities.",
            len(event_nodes),
            len(proc_records),
        )
        return len(event_nodes), len(proc_records)

    def _parse_evtx_chunk(
        self,
        chunk: bytes,
        event_nodes: list[EventNode],
        proc_records: list[ProcessRecord],
    ) -> None:
        """Parses individual 64KB EVTX chunk records."""
        if len(chunk) < 512:
            return

        header_size = struct.unpack_from("<I", chunk, 40)[0]
        offset = header_size if header_size >= 128 else 512
        chunk_len = len(chunk)

        while offset + 24 <= chunk_len:
            magic = chunk[offset : offset + 4]
            if magic != EVTX_RECORD_MAGIC:
                # Seek next possible record signature
                next_pos = chunk.find(EVTX_RECORD_MAGIC, offset + 1)
                if next_pos == -1:
                    break
                offset = next_pos
                continue

            rec_size = struct.unpack_from("<I", chunk, offset + 4)[0]
            if rec_size < 28 or offset + rec_size > chunk_len:
                offset += 4
                continue

            rec_id = struct.unpack_from("<Q", chunk, offset + 8)[0]
            filetime = struct.unpack_from("<Q", chunk, offset + 16)[0]
            epoch_sec = max(0.0, (filetime / 10_000_000.0) - FILETIME_EPOCH_DIFF)

            payload_bytes = chunk[offset + 24 : offset + rec_size - 4]
            parsed = self._extract_event_from_binary_payload(
                payload_bytes, rec_id, epoch_sec
            )
            if parsed:
                node, proc = parsed
                event_nodes.append(node)
                if proc:
                    proc_records.append(proc)

            offset += rec_size

    def _extract_event_from_binary_payload(
        self, payload: bytes, record_id: int, epoch_sec: float
    ) -> tuple[EventNode, ProcessRecord | None] | None:
        """Extracts event elements from binary record payload (XML string or fallback)."""
        # 1. Attempt UTF-8 XML extraction
        start_idx = payload.find(b"<Event")
        if start_idx != -1:
            end_idx = payload.find(b"</Event>", start_idx)
            if end_idx != -1:
                xml_slice = payload[start_idx : end_idx + 8]
                try:
                    elem = ET.fromstring(xml_slice.decode("utf-8", errors="replace"))
                    return self._parse_event_element(elem)
                except Exception:
                    pass

        # 2. Attempt UTF-16LE XML extraction
        start_16 = payload.find(b"<\x00E\x00v\x00e\x00n\x00t\x00")
        if start_16 != -1:
            end_16 = payload.find(b"<\x00/\x00E\x00v\x00e\x00n\x00t\x00>\x00", start_16)
            if end_16 != -1:
                xml_slice_16 = payload[start_16 : end_16 + 16]
                try:
                    elem = ET.fromstring(xml_slice_16.decode("utf-16le", errors="replace"))
                    return self._parse_event_element(elem)
                except Exception:
                    pass

        # 3. Fallback: Create structured EventNode from binary record header
        dt_str = (
            datetime.datetime.fromtimestamp(epoch_sec, datetime.UTC).isoformat()
            if epoch_sec > 0
            else datetime.datetime.now(datetime.UTC).isoformat()
        )
        computer = "UNKNOWN_HOST"
        channel = "Microsoft-Windows-Sysmon/Operational"
        event_key = f"{computer}:{channel}:{record_id}"

        node = EventNode(
            event_key=event_key,
            host_name=computer,
            channel=channel,
            record_id=record_id,
            timestamp_utc=dt_str,
            timestamp_epoch=epoch_sec,
            event_type="BinaryRecord",
            event_id=0,
            process_guid=None,
            parent_process_guid=None,
            target_object=None,
            hashes="",
            raw_payload=f"[EVTX Binary Record #{record_id}]",
        )
        return node, None

    def _parse_event_element(
        self, elem: ET.Element
    ) -> tuple[EventNode, ProcessRecord | None] | None:
        """Extracts normalized EventNode and optional ProcessRecord from an XML Event element."""
        try:
            # 1. System header extraction
            system_elem = elem.find("{*}System")
            if system_elem is None:
                system_elem = elem.find("System")
            if system_elem is None:
                return None

            event_id_text = self._find_text(system_elem, "EventID") or "0"
            event_id = int(event_id_text)
            record_id_text = self._find_text(system_elem, "EventRecordID") or "0"
            record_id = int(record_id_text)
            channel = (
                self._find_text(system_elem, "Channel")
                or "Microsoft-Windows-Sysmon/Operational"
            )
            computer = self._find_text(system_elem, "Computer") or "UNKNOWN_HOST"

            time_elem = system_elem.find("{*}TimeCreated")
            if time_elem is None:
                time_elem = system_elem.find("TimeCreated")
            time_created = (
                time_elem.get("SystemTime")
                if time_elem is not None
                else datetime.datetime.now(datetime.UTC).isoformat()
            ) or ""

            timestamp_epoch = self._parse_timestamp(time_created)

            # 2. EventData extraction
            data_map: dict[str, str] = {}
            event_data = elem.find("{*}EventData")
            if event_data is None:
                event_data = elem.find("EventData")
            if event_data is not None:
                data_items = event_data.findall("{*}Data")
                if not data_items:
                    data_items = event_data.findall("Data")
                for data_item in data_items:
                    name = data_item.get("Name")
                    if name:
                        data_map[name] = data_item.text or ""

            process_guid = data_map.get("ProcessGuid") or data_map.get("SourceProcessGuid")
            process_id_str = data_map.get("ProcessId") or data_map.get("SourceProcessId")
            process_id = (
                int(process_id_str)
                if process_id_str and process_id_str.isdigit()
                else None
            )
            parent_process_guid = data_map.get("ParentProcessGuid") or (
                data_map.get("TargetProcessGuid") if event_id == 10 else None
            )
            parent_process_id_str = data_map.get("ParentProcessId")
            parent_process_id = (
                int(parent_process_id_str)
                if parent_process_id_str and parent_process_id_str.isdigit()
                else None
            )

            image = data_map.get("Image", "") or data_map.get("SourceImage", "")
            target_obj = (
                (data_map.get("TargetImage") if event_id == 10 else None)
                or data_map.get("TargetFilename")
                or data_map.get("TargetObject")
                or data_map.get("DestinationIp")
                or image
            )
            hashes = data_map.get("Hashes", "")
            cmd_line = data_map.get("CommandLine", "")
            user = data_map.get("User", "")

            event_key = f"{computer}:{channel}:{record_id}"
            event_type = EVENT_TYPE_MAP.get(event_id, f"EventID_{event_id}")

            event_node = EventNode(
                event_key=event_key,
                host_name=computer,
                channel=channel,
                record_id=record_id,
                timestamp_utc=time_created,
                timestamp_epoch=timestamp_epoch,
                event_type=event_type,
                event_id=event_id,
                process_guid=process_guid,
                parent_process_guid=parent_process_guid,
                target_object=target_obj,
                hashes=hashes,
                raw_payload=ET.tostring(elem, encoding="unicode"),
            )

            proc_record: ProcessRecord | None = None
            if event_id == 1 and process_guid and process_id is not None:
                proc_record = ProcessRecord(
                    process_guid=process_guid,
                    process_id=process_id,
                    image_path=image,
                    command_line=cmd_line,
                    parent_process_guid=parent_process_guid,
                    parent_process_id=parent_process_id,
                    user_sid=user,
                    host_name=computer,
                    created_at_utc=time_created,
                )

            return event_node, proc_record

        except Exception as err:
            logger.debug("Failed to parse event element: %s", err)
            return None

    @staticmethod
    def _find_text(parent: ET.Element, tag_name: str) -> str | None:
        """Finds element text ignoring XML namespaces."""
        child = parent.find(f"{{*}}{tag_name}")
        if child is None:
            child = parent.find(tag_name)
        return child.text if child is not None else None

    @staticmethod
    def _parse_timestamp(ts_str: str) -> float:
        """Parses ISO timestamp string to Unix epoch seconds."""
        try:
            norm = ts_str.rstrip("Z")
            if "." in norm:
                base, frac = norm.split(".", 1)
                frac = frac[:6].ljust(6, "0")
                norm = f"{base}.{frac}"
            dt = datetime.datetime.fromisoformat(norm).replace(tzinfo=datetime.UTC)
            return dt.timestamp()
        except Exception:
            return 0.0
