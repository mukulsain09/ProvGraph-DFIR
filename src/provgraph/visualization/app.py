"""Interactive Streamlit & Cytoscape.js Provenance Explorer UI."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import networkx as nx
import streamlit as st
import streamlit.components.v1 as components

from provgraph.contraction.expansion import expand_macro_edge
from provgraph.contraction.lossless import contract_graph
from provgraph.evaluation.benchmark import compute_graph_metrics
from provgraph.graph.dag_builder import DAGBuilder
from provgraph.ingestion.evtx_loader import EVTXLoader
from provgraph.ingestion.mordor_loader import MordorLoader
from provgraph.ledger.database import EvidenceLedger
from provgraph.slicing.deterministic import compute_deterministic_slice
from provgraph.visualization.graph_export import (
    export_cytoscape_elements,
    generate_cytoscape_html,
)

# Page configuration
st.set_page_config(
    page_title="ProvGraph-DFIR Provenance Explorer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

DATA_DIR = Path(__file__).parent.parent.parent.parent / "data" / "raw_mordor"

SCENARIO_DISPLAY_MAP: dict[str, str] = {
    "empire_launcher_vbs_2020-09-04160940.json": (
        "🎯 [T1059.005] Empire VBS Launcher & LOLBin Cradle"
    ),
    "ransomware_burst.json": (
        "🛡️ [T1486] High-Volume Ransomware Mass Encryption Burst"
    ),
    "empire_mimikatz_logonpasswords_2020-08-07103224.json": (
        "🔑 [T1003.001] Empire Mimikatz LSASS ProcessAccess Dump"
    ),
    "apt_spearphishing_macro.json": (
        "📧 [T1566.001] Spearphishing Macro Dropper -> Infiltration"
    ),
    "lateral_movement_psexec.json": (
        "⚡ [T1021.002] PsExec Remote Service Lateral Movement"
    ),
    "defense_evasion_tampering.json": (
        "🛑 [T1490] Shadow Copy Deletion & Defense Impairment"
    ),
    "cmd_bitsadmin_download_psh_script_2020-10-2302365189.json": (
        "🌐 [T1197] BITSAdmin Living-off-the-Land Download Cradle"
    ),
    "metasploit_logonpasswords_lsass_memory_dump.json": (
        "💀 [T1003.001] Metasploit LSASS Memory Dump Campaign"
    ),
    "sysmon_audit_sample.xml": "📄 [XML Export] Windows Sysmon Native XML Log",
    "sample_sysmon.json": "🧪 [Test Fixture] Minimal 5-Event Process Chain",
}


def init_session_state() -> None:
    """Initializes Streamlit session state variables."""
    if "db_path" not in st.session_state:
        st.session_state.db_path = ":memory:"
    if "ledger" not in st.session_state:
        st.session_state.ledger = EvidenceLedger(":memory:")
    if "dag" not in st.session_state:
        st.session_state.dag = nx.DiGraph()
    if "slice_graph" not in st.session_state:
        st.session_state.slice_graph = nx.DiGraph()
    if "contracted_graph" not in st.session_state:
        st.session_state.contracted_graph = nx.DiGraph()
    if "macros" not in st.session_state:
        st.session_state.macros = []
    if "poi_key" not in st.session_state:
        st.session_state.poi_key = None
    if "loaded_dataset" not in st.session_state:
        st.session_state.loaded_dataset = None


def render_sidebar() -> tuple[Path | None, Any, bool, str | None, int, float, bool]:
    """Renders investigation sidebar controls."""
    st.sidebar.title("🔍 ProvGraph-DFIR")
    st.sidebar.caption("Deterministic Windows Forensic Provenance Engine")
    st.sidebar.markdown("---")

    # 1. Dataset Selection / Upload
    st.sidebar.subheader("📁 Telemetry Source")
    available_files: list[Path] = []
    if DATA_DIR.exists():
        for ext in ("*.json", "*.evtx", "*.xml"):
            available_files.extend(DATA_DIR.glob(ext))
    fixtures_dir = DATA_DIR.parent / "test_fixtures"
    if fixtures_dir.exists():
        for ext in ("*.json", "*.evtx", "*.xml"):
            available_files.extend(fixtures_dir.glob(ext))

    dataset_options: dict[str, Path] = {}
    for f in sorted(available_files, key=lambda x: x.name):
        label = SCENARIO_DISPLAY_MAP.get(f.name, f"📁 {f.name}")
        dataset_options[label] = f

    selected_name = st.sidebar.selectbox(
        "Preloaded Benchmark Datasets",
        options=list(dataset_options.keys()),
        index=0 if dataset_options else None,
    )
    selected_path = dataset_options.get(selected_name) if selected_name else None

    uploaded_file = st.sidebar.file_uploader(
        "Or Upload Custom Evidence Log",
        type=["json", "evtx", "xml"],
        help="Ingest custom Windows Sysmon EVTX, XML export, or Mordor JSON log.",
    )

    load_clicked = st.sidebar.button("📥 Ingest Telemetry & Build DAG", use_container_width=True)

    st.sidebar.markdown("---")
    st.sidebar.subheader("🎯 Point of Interest (PoI)")

    # PoI selection dropdown
    poi_options: list[str] = []
    if st.session_state.dag.number_of_nodes() > 0:
        saliency_keywords = (
            "whoami",
            "powershell",
            "vssadmin",
            "certutil",
            "wbadmin",
            "bcdedit",
            "psexec",
            "nltest",
            "net.exe",
            "rundll32",
            "wannacrypt",
            "lsass",
            "mimikatz",
            "bitsadmin",
            "winword",
            "wscript",
        )
        for n, d in st.session_state.dag.nodes(data=True):
            ev_type = d.get("event_type", "")
            tgt = Path(d.get("target_object") or "").name
            rec_id = d.get("record_id", 0)
            low_tgt = tgt.lower()
            cmd = (d.get("command_line") or "").lower()
            target_extensions = (".exe", ".dll", ".vbs", ".ps1", ".wnry", ".zip")
            is_saliency = (
                d.get("event_id") in (1, 3, 8, 10)
                or any(k in low_tgt or k in cmd for k in saliency_keywords)
                or (
                    d.get("event_id") == 11
                    and any(ext in low_tgt for ext in target_extensions)
                )
            )
            if is_saliency:
                poi_options.append(f"{rec_id} - {ev_type} ({tgt}) | {n}")

        # Fallback if no specific saliency keywords matched
        if not poi_options:
            for n, d in list(st.session_state.dag.nodes(data=True))[:25]:
                ev_type = d.get("event_type", "")
                tgt = Path(d.get("target_object") or "").name
                rec_id = d.get("record_id", 0)
                poi_options.append(f"{rec_id} - {ev_type} ({tgt}) | {n}")

    selected_poi_str = st.sidebar.selectbox(
        "Select Saliency PoI Target",
        options=poi_options,
        index=0 if poi_options else None,
    )
    selected_poi_key = selected_poi_str.split(" | ")[-1] if selected_poi_str else None

    # Custom key fallback input
    custom_key = st.sidebar.text_input(
        "Or Enter Custom Event Key",
        value=selected_poi_key or "",
        help="Format: host:channel:record_id",
    )
    active_poi_key = custom_key.strip() if custom_key.strip() else selected_poi_key

    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ Causal Slicing Parameters")
    max_depth = st.sidebar.slider(
        "Max Traversal Depth (Hops)", min_value=1, max_value=25, value=12
    )
    max_delta = st.sidebar.slider(
        "Time Window ΔT (Seconds)", min_value=60, max_value=7200, value=1800, step=60
    )

    st.sidebar.markdown("---")
    st.sidebar.subheader("🔬 Contraction & Abstraction")
    use_contraction = st.sidebar.toggle("Apply Lossless Contraction", value=True)

    return (
        selected_path,
        uploaded_file,
        load_clicked,
        active_poi_key,
        max_depth,
        float(max_delta),
        use_contraction,
    )


def main() -> None:
    init_session_state()
    (
        selected_path,
        uploaded_file,
        load_clicked,
        poi_key,
        max_depth,
        max_delta,
        use_contraction,
    ) = render_sidebar()

    st.title("ProvGraph-DFIR: Interactive Provenance Explorer")
    st.markdown(
        "*Beyond-MVP Demonstration Engine: Causal Slicing & Lossless Contraction*"
    )

    # Ingestion handling
    if load_clicked and (uploaded_file or selected_path):
        source_name = uploaded_file.name if uploaded_file else selected_path.name  # type: ignore[union-attr]
        with st.spinner(f"Ingesting {source_name} into Evidence Ledger..."):
            t0 = time.perf_counter()
            st.session_state.ledger = EvidenceLedger(":memory:")

            # Determine file path to load
            temp_path: Path | None = None
            if uploaded_file:
                import tempfile

                suffix = Path(uploaded_file.name).suffix
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded_file.getbuffer())
                    temp_path = Path(tmp.name)
                target_file = temp_path
            else:
                target_file = selected_path  # type: ignore[assignment]

            suffix = target_file.suffix.lower()
            if suffix in (".evtx", ".xml"):
                evtx_loader = EVTXLoader(st.session_state.ledger)
                ev_count, proc_count = evtx_loader.load_file(target_file)
            else:
                mordor_loader = MordorLoader(st.session_state.ledger)
                ev_count, proc_count = mordor_loader.load_file(target_file)

            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

            cursor = st.session_state.ledger.connection.execute(
                "SELECT event_key FROM event_ledger ORDER BY timestamp_epoch ASC"
            )
            keys = [r[0] for r in cursor.fetchall()]
            events = st.session_state.ledger.get_events_by_keys(keys)

            builder = DAGBuilder()
            st.session_state.dag = builder.build_graph(events)
            st.session_state.loaded_dataset = source_name
            t_total = time.perf_counter() - t0
            st.success(
                f"Ingested {ev_count:,} events ({proc_count:,} processes) and constructed "
                f"DAG with {st.session_state.dag.number_of_nodes():,} nodes and "
                f"{st.session_state.dag.number_of_edges():,} causal edges in {t_total:.2f}s."
            )

    dag = st.session_state.dag
    ledger = st.session_state.ledger

    if dag.number_of_nodes() == 0:
        st.info("👈 Select a Mordor attack dataset and click **Ingest Telemetry & Build DAG**.")
        return

    # Slicing & Contraction Execution
    if poi_key and poi_key in dag:
        slice_g = compute_deterministic_slice(
            dag, poi_key=poi_key, max_depth=max_depth, max_delta_sec=max_delta
        )
        st.session_state.slice_graph = slice_g

        if use_contraction:
            contracted_g, macros = contract_graph(slice_g, poi_key=poi_key, ledger=ledger)
            st.session_state.contracted_graph = contracted_g
            st.session_state.macros = macros
            active_display_graph = contracted_g
        else:
            active_display_graph = slice_g
            st.session_state.macros = []
    else:
        st.warning("Please select a valid Point of Interest (PoI) in the sidebar.")
        active_display_graph = dag

    # KPI Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Raw Events", f"{dag.number_of_nodes():,}")
    with col2:
        st.metric("DAG Causal Edges", f"{dag.number_of_edges():,}")
    with col3:
        st.metric("Causal Slice Nodes", f"{st.session_state.slice_graph.number_of_nodes():,}")
    with col4:
        st.metric("Visual Graph Nodes", f"{active_display_graph.number_of_nodes():,}")
    with col5:
        if st.session_state.slice_graph.number_of_nodes() > 0 and use_contraction:
            res = compute_graph_metrics(st.session_state.slice_graph, active_display_graph)
            st.metric("Size Reduction (GSR)", f"{res.graph_size_reduction * 100:.1f}%")
        else:
            st.metric("Reduction Mode", "Uncontracted" if not use_contraction else "N/A")

    # Interactive Cytoscape.js Canvas & Report Export Actions
    c_title, c_exp_html, c_exp_json = st.columns([2, 1, 1])
    with c_title:
        st.subheader("Interactive Forensic Provenance DAG")
    with c_exp_html:
        safe_poi = (poi_key or "slice").replace(":", "_").replace("/", "_").replace("\\", "_")
        elements = export_cytoscape_elements(active_display_graph, poi_key=poi_key)
        html_code = generate_cytoscape_html(elements, poi_key=poi_key, height=660)
        st.download_button(
            label="📥 Export HTML Report",
            data=html_code,
            file_name=f"provgraph_report_{safe_poi}.html",
            mime="text/html",
            use_container_width=True,
            help="Download self-contained interactive Cytoscape.js HTML dossier.",
        )
    with c_exp_json:
        json_report = json.dumps(elements, indent=2)
        st.download_button(
            label="📄 Export JSON Dossier",
            data=json_report,
            file_name=f"provgraph_dossier_{safe_poi}.json",
            mime="application/json",
            use_container_width=True,
            help="Export raw graph elements and forensic node metadata as JSON.",
        )

    components.html(html_code, height=680)

    # Macro-Edge Drilldown & Expansion Drawer
    if use_contraction and st.session_state.macros:
        st.subheader("🗂️ Macro-Edge Evidence Ledger & Reversible Expansion")
        macro_options = [
            f"{m.macro_edge_id} | {m.relation_type} [x{m.event_count}] "
            f"({m.source_event_key} -> {m.target_event_key})"
            for m in st.session_state.macros
        ]
        sel_macro_str = st.selectbox("Select Macro-Edge to Inspect", options=macro_options)

        if sel_macro_str:
            sel_macro_id = sel_macro_str.split(" | ")[0]
            macro_obj = next(
                (m for m in st.session_state.macros if m.macro_edge_id == sel_macro_id), None
            )

            if macro_obj:
                c1, c2 = st.columns([3, 1])
                with c1:
                    st.write(
                        f"**Macro-Edge ID:** `{macro_obj.macro_edge_id}` | "
                        f"**Relation:** `{macro_obj.relation_type}` | "
                        f"**Underlying Events:** `{macro_obj.event_count}`"
                    )
                with c2:
                    if st.button("🔄 Expand Selected Macro-Edge", key="expand_btn"):
                        expanded = expand_macro_edge(
                            st.session_state.contracted_graph,
                            macro_obj.macro_edge_id,
                            ledger=ledger,
                        )
                        st.session_state.contracted_graph = expanded
                        st.session_state.macros = [
                            m
                            for m in st.session_state.macros
                            if m.macro_edge_id != macro_obj.macro_edge_id
                        ]
                        st.success(f"Expanded {macro_obj.macro_edge_id}! Graph refreshed.")
                        st.rerun()

                # Display raw underlying records from SQLite
                underlying_events = ledger.get_events_by_keys(macro_obj.ordered_event_keys)
                events_data = [
                    {
                        "Record ID": e.record_id,
                        "UTC Time": e.timestamp_utc,
                        "Event Type": e.event_type,
                        "Target Object": e.target_object or "",
                        "Process GUID": e.process_guid or "",
                        "Hashes": e.hashes or "",
                    }
                    for e in underlying_events
                ]
                st.dataframe(events_data, use_container_width=True, height=220)


if __name__ == "__main__":
    main()
