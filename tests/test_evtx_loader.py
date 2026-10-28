"""Unit tests for EVTX XML and binary EVTX ingestion engine."""

from __future__ import annotations

import struct
from pathlib import Path

from provgraph.ingestion.evtx_loader import (
    EVTX_CHUNK_MAGIC,
    EVTX_FILE_MAGIC,
    EVTX_RECORD_MAGIC,
    FILETIME_EPOCH_DIFF,
    EVTXLoader,
    detect_evtx_format,
)
from provgraph.ledger.database import EvidenceLedger

SAMPLE_EVTX_XML = """
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
      <EventID>1</EventID>
      <Version>5</Version>
      <EventRecordID>1001</EventRecordID>
      <TimeCreated SystemTime="2026-10-25T05:00:00.000000Z"/>
      <Execution ProcessID="2440" ThreadID="3000"/>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>DESKTOP-FORENSIC</Computer>
    </System>
    <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2026-10-25 05:00:00.000</Data>
      <Data Name="ProcessGuid">{AAAA-BBBB-CCCC-DDDD}</Data>
      <Data Name="ProcessId">4100</Data>
      <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c whoami</Data>
      <Data Name="ParentProcessGuid">{1111-2222-3333-4444}</Data>
      <Data Name="ParentProcessId">1024</Data>
      <Data Name="User">WORKGROUP\\Analyst</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
      <EventID>11</EventID>
      <Version>2</Version>
      <EventRecordID>1002</EventRecordID>
      <TimeCreated SystemTime="2026-10-25T05:00:05.000000Z"/>
      <Execution ProcessID="2440" ThreadID="3000"/>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>DESKTOP-FORENSIC</Computer>
    </System>
    <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2026-10-25 05:00:05.000</Data>
      <Data Name="ProcessGuid">{AAAA-BBBB-CCCC-DDDD}</Data>
      <Data Name="ProcessId">4100</Data>
      <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="TargetFilename">C:\\Users\\Analyst\\AppData\\Local\\Temp\\out.txt</Data>
    </EventData>
  </Event>
</Events>
"""


def create_synthetic_binary_evtx(xml_records: list[tuple[int, float, str]]) -> bytes:
    """Constructs a valid binary EVTX byte stream containing chunks and records."""
    file_header = bytearray(4096)
    file_header[0:8] = EVTX_FILE_MAGIC
    struct.pack_into("<Q", file_header, 8, 0)  # first chunk
    struct.pack_into("<Q", file_header, 16, 0)  # last chunk
    struct.pack_into("<Q", file_header, 24, len(xml_records) + 1)
    struct.pack_into("<I", file_header, 32, 4096)  # header size

    chunk = bytearray(65536)
    chunk[0:8] = EVTX_CHUNK_MAGIC
    struct.pack_into("<I", chunk, 40, 512)  # chunk header size

    offset = 512
    for rec_id, epoch_sec, xml_content in xml_records:
        xml_bytes = xml_content.encode("utf-8")
        rec_len = 24 + len(xml_bytes) + 4
        # Align to 4 bytes
        pad = (4 - (rec_len % 4)) % 4
        total_len = rec_len + pad

        rec = bytearray(total_len)
        rec[0:4] = EVTX_RECORD_MAGIC
        struct.pack_into("<I", rec, 4, total_len)
        struct.pack_into("<Q", rec, 8, rec_id)
        filetime = int((epoch_sec + FILETIME_EPOCH_DIFF) * 10_000_000)
        struct.pack_into("<Q", rec, 16, filetime)
        rec[24 : 24 + len(xml_bytes)] = xml_bytes
        struct.pack_into("<I", rec, total_len - 4, total_len)

        chunk[offset : offset + total_len] = rec
        offset += total_len

    return bytes(file_header) + bytes(chunk)


def test_evtx_loader_xml_parsing() -> None:
    with EvidenceLedger(":memory:") as ledger:
        loader = EVTXLoader(ledger)
        events_count, procs_count = loader.load_xml_string(SAMPLE_EVTX_XML)

        assert events_count == 2
        assert procs_count == 1

        # Check ledger entries
        ev1 = ledger.get_event("DESKTOP-FORENSIC:Microsoft-Windows-Sysmon/Operational:1001")
        assert ev1 is not None
        assert ev1.event_id == 1
        assert ev1.process_guid == "{AAAA-BBBB-CCCC-DDDD}"
        assert ev1.target_object == "C:\\Windows\\System32\\cmd.exe"

        ev2 = ledger.get_event("DESKTOP-FORENSIC:Microsoft-Windows-Sysmon/Operational:1002")
        assert ev2 is not None
        assert ev2.event_id == 11
        assert ev2.target_object == "C:\\Users\\Analyst\\AppData\\Local\\Temp\\out.txt"


def test_detect_evtx_format(tmp_path: Path) -> None:
    """Verifies format detection between binary EVTX containers and XML exports."""
    # 1. XML format
    xml_p = tmp_path / "test.xml"
    xml_p.write_text("<Events><Event></Event></Events>", encoding="utf-8")
    assert detect_evtx_format(xml_p) == "xml"

    # 2. Binary EVTX format
    bin_p = tmp_path / "test.evtx"
    raw_evtx = create_synthetic_binary_evtx([])
    bin_p.write_bytes(raw_evtx)
    assert detect_evtx_format(bin_p) == "binary"


def test_evtx_loader_binary_ingestion(tmp_path: Path) -> None:
    """Verifies that native binary EVTX chunks are decoded directly into the ledger."""
    ev1_xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        "<Provider Name=\"Microsoft-Windows-Sysmon\"/>"
        "<EventID>1</EventID>"
        "<EventRecordID>5001</EventRecordID>"
        '<TimeCreated SystemTime="2026-10-27T01:00:00.000Z"/>'
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>BIN-FORENSIC-01</Computer>"
        "</System>"
        "<EventData>"
        "<Data Name=\"ProcessGuid\">{BIN-PROC-01}</Data>"
        "<Data Name=\"ProcessId\">7777</Data>"
        "<Data Name=\"Image\">C:\\Windows\\System32\\cmd.exe</Data>"
        "<Data Name=\"CommandLine\">cmd.exe /c echo binary</Data>"
        "</EventData>"
        "</Event>"
    )

    ev2_xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        "<Provider Name=\"Microsoft-Windows-Sysmon\"/>"
        "<EventID>11</EventID>"
        "<EventRecordID>5002</EventRecordID>"
        '<TimeCreated SystemTime="2026-10-27T01:00:02.000Z"/>'
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>BIN-FORENSIC-01</Computer>"
        "</System>"
        "<EventData>"
        "<Data Name=\"ProcessGuid\">{BIN-PROC-01}</Data>"
        "<Data Name=\"TargetFilename\">C:\\extracted.bin</Data>"
        "</EventData>"
        "</Event>"
    )

    records = [
        (5001, 1730000000.0, ev1_xml),
        (5002, 1730000002.0, ev2_xml),
    ]

    evtx_data = create_synthetic_binary_evtx(records)
    bin_file = tmp_path / "sysmon_capture.evtx"
    bin_file.write_bytes(evtx_data)

    with EvidenceLedger(":memory:") as ledger:
        loader = EVTXLoader(ledger)
        num_events, num_procs = loader.load_file(bin_file)

        assert num_events == 2
        assert num_procs == 1

        node1 = ledger.get_event("BIN-FORENSIC-01:Microsoft-Windows-Sysmon/Operational:5001")
        assert node1 is not None
        assert node1.event_id == 1
        assert node1.process_guid == "{BIN-PROC-01}"
        assert node1.target_object == "C:\\Windows\\System32\\cmd.exe"

        node2 = ledger.get_event("BIN-FORENSIC-01:Microsoft-Windows-Sysmon/Operational:5002")
        assert node2 is not None
        assert node2.event_id == 11
        assert node2.target_object == "C:\\extracted.bin"
