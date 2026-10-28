"""Unit tests verifying Theorem 1 (Strict DAG Acyclicity) and causal inference rules."""

from __future__ import annotations

import networkx as nx

from provgraph.graph.dag_builder import DAGBuilder
from provgraph.graph.models import EventNode


def test_theorem_1_dag_acyclicity_with_identical_timestamps() -> None:
    """Verifies that events with IDENTICAL timestamps are strictly acyclic under Definition 2."""
    builder = DAGBuilder()

    # Three events occurring at the exact same epoch millisecond
    t_shared = 1729830000.123
    e1 = EventNode(
        event_key="hostA:Sysmon:101",
        host_name="hostA",
        channel="Sysmon",
        record_id=101,
        timestamp_epoch=t_shared,
        timestamp_utc="2026-10-25T05:00:00.123Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{PROC-1}",
        target_object="C:\\cmd.exe",
    )
    e2 = EventNode(
        event_key="hostA:Sysmon:102",
        host_name="hostA",
        channel="Sysmon",
        record_id=102,
        timestamp_epoch=t_shared,
        timestamp_utc="2026-10-25T05:00:00.123Z",
        event_type="FileCreate",
        event_id=11,
        process_guid="{PROC-1}",
        target_object="C:\\payload.exe",
    )
    e3 = EventNode(
        event_key="hostA:Sysmon:103",
        host_name="hostA",
        channel="Sysmon",
        record_id=103,
        timestamp_epoch=t_shared,
        timestamp_utc="2026-10-25T05:00:00.123Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{PROC-2}",
        parent_process_guid="{PROC-1}",
        target_object="C:\\payload.exe",
    )

    # e1 < e2 < e3 holds by strict total order
    assert e1 < e2 < e3

    graph = builder.build_graph([e1, e2, e3])

    # Must be strictly a DAG
    assert nx.is_directed_acyclic_graph(graph)
    assert graph.number_of_nodes() == 3
    assert graph.has_edge(e1.event_key, e2.event_key)
    assert graph.has_edge(e1.event_key, e3.event_key)
    assert graph.has_edge(e2.event_key, e3.event_key)


def test_process_spawn_and_file_dropper_chain() -> None:
    """Tests causal chain: Dropper Process -> Writes File -> Executed Process -> NetConnect."""
    builder = DAGBuilder()

    dropper = EventNode(
        event_key="host1:Sysmon:1",
        host_name="host1",
        channel="Sysmon",
        record_id=1,
        timestamp_epoch=10.0,
        timestamp_utc="2026-10-25T05:00:10Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{DROPPER-GUID}",
        target_object="C:\\word.exe",
    )
    file_drop = EventNode(
        event_key="host1:Sysmon:2",
        host_name="host1",
        channel="Sysmon",
        record_id=2,
        timestamp_epoch=12.0,
        timestamp_utc="2026-10-25T05:00:12Z",
        event_type="FileCreate",
        event_id=11,
        process_guid="{DROPPER-GUID}",
        target_object="C:\\Users\\Temp\\payload.exe",
    )
    payload_exec = EventNode(
        event_key="host1:Sysmon:3",
        host_name="host1",
        channel="Sysmon",
        record_id=3,
        timestamp_epoch=15.0,
        timestamp_utc="2026-10-25T05:00:15Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{PAYLOAD-GUID}",
        parent_process_guid="{DROPPER-GUID}",
        target_object="C:\\Users\\Temp\\payload.exe",
    )
    c2_connect = EventNode(
        event_key="host1:Sysmon:4",
        host_name="host1",
        channel="Sysmon",
        record_id=4,
        timestamp_epoch=18.0,
        timestamp_utc="2026-10-25T05:00:18Z",
        event_type="NetworkConnect",
        event_id=3,
        process_guid="{PAYLOAD-GUID}",
        target_object="198.51.100.4:443",
    )

    events = [dropper, file_drop, payload_exec, c2_connect]
    graph = builder.build_graph(events)

    assert nx.is_directed_acyclic_graph(graph)
    assert graph.number_of_nodes() == 4
    # Dropper wrote file
    assert graph.has_edge(dropper.event_key, file_drop.event_key)
    # File drop dropped executable
    assert graph.has_edge(file_drop.event_key, payload_exec.event_key)
    # Dropper spawned payload
    assert graph.has_edge(dropper.event_key, payload_exec.event_key)
    # Payload connected to C2
    assert graph.has_edge(payload_exec.event_key, c2_connect.event_key)
    # Root cause reaches C2
    assert nx.has_path(graph, dropper.event_key, c2_connect.event_key)


def test_process_access_causal_rule() -> None:
    """Verifies Gap 4: Sysmon Event 10 (ProcessAccess) connects source to target process."""
    builder = DAGBuilder()

    psh = EventNode(
        event_key="host1:Sysmon:10",
        host_name="host1",
        channel="Sysmon",
        record_id=10,
        timestamp_epoch=100.0,
        timestamp_utc="2026-10-25T05:01:40Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{PSH-GUID}",
        target_object="C:\\powershell.exe",
    )
    access_lsass = EventNode(
        event_key="host1:Sysmon:11",
        host_name="host1",
        channel="Sysmon",
        record_id=11,
        timestamp_epoch=102.0,
        timestamp_utc="2026-10-25T05:01:42Z",
        event_type="ProcessAccess",
        event_id=10,
        process_guid="{PSH-GUID}",
        parent_process_guid="{LSASS-GUID}",
        target_object="C:\\Windows\\System32\\lsass.exe",
    )
    graph = builder.build_graph([psh, access_lsass])

    assert nx.is_directed_acyclic_graph(graph)
    assert graph.number_of_nodes() == 2
    # PSH accessed LSASS
    assert graph.has_edge(psh.event_key, access_lsass.event_key)
    edge_data1 = graph.get_edge_data(psh.event_key, access_lsass.event_key)
    assert edge_data1["relation_type"] == "PROCESS_ACCESS"
    assert "target process" in edge_data1["description"].lower()


def test_preexisting_process_anchoring() -> None:
    """Verifies that pre-existing processes anchor and link to actions/children."""
    builder = DAGBuilder()

    # Pre-existing process has no Event 1 in log capture, only Event 12, Event 10
    parent_earliest = EventNode(
        event_key="host1:Sysmon:20",
        host_name="host1",
        channel="Sysmon",
        record_id=20,
        timestamp_epoch=50.0,
        timestamp_utc="2026-10-25T05:00:50Z",
        event_type="RegistryObject",
        event_id=12,
        process_guid="{PRE-EXISTING-PROC}",
        target_object="HKLM\\Software\\Test",
    )
    parent_access = EventNode(
        event_key="host1:Sysmon:21",
        host_name="host1",
        channel="Sysmon",
        record_id=21,
        timestamp_epoch=52.0,
        timestamp_utc="2026-10-25T05:00:52Z",
        event_type="ProcessAccess",
        event_id=10,
        process_guid="{PRE-EXISTING-PROC}",
        parent_process_guid="{LSASS-GUID}",
        target_object="C:\\Windows\\System32\\lsass.exe",
    )
    child_spawn = EventNode(
        event_key="host1:Sysmon:22",
        host_name="host1",
        channel="Sysmon",
        record_id=22,
        timestamp_epoch=55.0,
        timestamp_utc="2026-10-25T05:00:55Z",
        event_type="ProcessCreate",
        event_id=1,
        process_guid="{CHILD-PROC}",
        parent_process_guid="{PRE-EXISTING-PROC}",
        target_object="C:\\Windows\\System32\\whoami.exe",
    )

    graph = builder.build_graph([parent_earliest, parent_access, child_spawn])

    assert nx.is_directed_acyclic_graph(graph)
    assert graph.number_of_nodes() == 3
    # Anchor links to intra-process action
    assert graph.has_edge(parent_earliest.event_key, parent_access.event_key)
    # Anchor links to child process creation
    assert graph.has_edge(parent_earliest.event_key, child_spawn.event_key)
    edge_spawn = graph.get_edge_data(parent_earliest.event_key, child_spawn.event_key)
    assert edge_spawn["relation_type"] == "SPAWNS"
