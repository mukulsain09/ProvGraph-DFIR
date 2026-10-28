"""ProvGraph-DFIR unified command-line interface.

Provides commands for telemetry ingestion, deterministic causal slicing,
lossless hierarchical contraction, interactive UI launching, and automated benchmarking.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from provgraph.config import load_config, load_scenarios
from provgraph.contraction.entropy_eval import entropy_guided_contraction
from provgraph.contraction.lossless import contract_graph
from provgraph.evaluation.benchmark import compute_graph_metrics
from provgraph.graph.dag_builder import DAGBuilder
from provgraph.ingestion.evtx_loader import EVTXLoader
from provgraph.ingestion.mordor_loader import MordorLoader
from provgraph.ledger.database import EvidenceLedger
from provgraph.slicing.cte_slicing import compute_sqlite_cte_slice
from provgraph.slicing.deterministic import (
    compute_deterministic_slice,
    compute_slice_hash,
)
from provgraph.visualization.graph_export import export_interactive_html

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="ProvGraph-DFIR")
def main() -> None:
    """ProvGraph-DFIR: Deterministic Causal Slicing & Lossless Contraction Engine."""


@main.command()
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--db",
    "db_path",
    type=click.Path(path_type=Path),
    default=Path("provgraph.db"),
    help="Target SQLite evidence database path.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["auto", "mordor", "evtx_xml", "evtx_binary", "evtx"], case_sensitive=False),
    default="auto",
    help="Telemetry log format.",
)
@click.option(
    "--build-edges/--no-build-edges",
    default=True,
    help="Infer and persist causal edges into SQLite for CTE pushdown slicing.",
)
def ingest(file_path: Path, db_path: Path, fmt: str, build_edges: bool) -> None:
    """Ingest Windows security telemetry (Mordor JSON / EVTX binary / EVTX XML) into ledger."""
    console.print(
        Panel.fit(
            f"[bold cyan]ProvGraph Ingestion Engine[/bold cyan]\n"
            f"Input: [yellow]{file_path}[/yellow]\n"
            f"Ledger: [green]{db_path}[/green]",
            title="Ingestion",
        )
    )

    suffix = file_path.suffix.lower()
    is_evtx = fmt in ("evtx", "evtx_binary", "evtx_xml") or (
        fmt == "auto" and suffix in (".evtx", ".xml")
    )

    t0 = time.perf_counter()
    with EvidenceLedger(db_path) as ledger:
        if is_evtx:
            loader_evtx = EVTXLoader(ledger)
            num_events, num_procs = loader_evtx.load_file(file_path)
        else:
            loader_mordor = MordorLoader(ledger)
            num_events, num_procs = loader_mordor.load_file(file_path)

        t_load = time.perf_counter() - t0
        console.print(
            f"[bold green][+][/bold green] Ingested {num_events:,} events and "
            f"{num_procs:,} process records in {t_load:.2f}s."
        )

        num_edges = 0
        if build_edges and num_events > 0:
            console.print("[cyan]Inferring and indexing causal edges...[/cyan]")
            cursor = ledger.connection.execute(
                "SELECT event_key FROM event_ledger ORDER BY timestamp_epoch ASC"
            )
            keys = [r[0] for r in cursor.fetchall()]
            events = ledger.get_events_by_keys(keys)
            builder = DAGBuilder()
            builder.build_graph(events)
            num_edges = builder.persist_to_ledger(ledger)
            console.print(
                f"[bold green][+][/bold green] Indexed {num_edges:,} causal edges in SQLite ledger."
            )

    table = Table(title="Ingestion Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="green")
    table.add_row("Total Ingested Events", f"{num_events:,}")
    table.add_row("Tracked Processes", f"{num_procs:,}")
    table.add_row("Indexed Causal Edges", f"{num_edges:,}")
    table.add_row("Elapsed Time", f"{time.perf_counter() - t0:.2f}s")
    console.print(table)


@main.command()
@click.option(
    "--db",
    "db_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="SQLite database path.",
)
@click.option(
    "--poi",
    "poi_key",
    type=str,
    required=True,
    help="Point of Interest event key (host:channel:record_id).",
)
@click.option("--depth", type=int, default=15, help="Maximum edge traversal depth.")
@click.option(
    "--window",
    "window_sec",
    type=float,
    default=3600.0,
    help="Temporal window delta around PoI in seconds.",
)
@click.option(
    "--method",
    type=click.Choice(["cte", "nx"], case_sensitive=False),
    default="cte",
    help="Slicing execution engine: SQLite CTE (pushdown) or NetworkX in-memory.",
)
@click.option(
    "--direction",
    type=click.Choice(["both", "backward", "forward"], case_sensitive=False),
    default="both",
    help="Causal traversal direction.",
)
@click.option(
    "--output-json",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional path to export slice node keys and hashes.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to YAML configuration file.",
)
def slice_cmd(
    db_path: Path,
    poi_key: str,
    depth: int,
    window_sec: float,
    method: str,
    direction: str,
    output_json: Path | None,
    config_path: Path | None = None,
) -> None:
    """Extract deterministic causal slice bounded relative to PoI timestamp."""
    if config_path:
        cfg = load_config(config_path)
        if depth == 15:
            depth = cfg.slicing.max_depth
        if window_sec == 3600.0:
            window_sec = cfg.slicing.max_delta_sec
        if direction == "both":
            direction = cfg.slicing.direction

    console.print(f"[cyan]Computing slice for PoI:[/cyan] [bold yellow]{poi_key}[/bold yellow]")
    t0 = time.perf_counter()

    with EvidenceLedger(db_path) as ledger:
        if method == "cte":
            slice_g = compute_sqlite_cte_slice(
                ledger,
                poi_key=poi_key,
                max_depth=depth,
                max_delta_sec=window_sec,
                direction=direction,
            )
        else:
            cursor = ledger.connection.execute(
                "SELECT event_key FROM event_ledger ORDER BY timestamp_epoch ASC"
            )
            keys = [r[0] for r in cursor.fetchall()]
            events = ledger.get_events_by_keys(keys)
            builder = DAGBuilder()
            dag = builder.build_graph(events)
            slice_g = compute_deterministic_slice(
                dag,
                poi_key=poi_key,
                max_depth=depth,
                max_delta_sec=window_sec,
                direction=direction,
            )

        t_elapsed = time.perf_counter() - t0
        slice_hash = compute_slice_hash(slice_g)

    table = Table(title="Causal Slice Statistics", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    engine_desc = "SQLite Recursive CTE" if method == "cte" else "NetworkX In-Memory"
    table.add_row("Execution Engine", engine_desc)
    table.add_row("Traversal Direction", direction.capitalize())
    table.add_row("Slice Vertices", f"{slice_g.number_of_nodes():,}")
    table.add_row("Slice Edges", f"{slice_g.number_of_edges():,}")
    table.add_row("Deterministic SHA-256", slice_hash)
    table.add_row("Execution Latency", f"{t_elapsed:.4f}s")
    console.print(table)

    if output_json:
        data = {
            "poi_key": poi_key,
            "method": method,
            "slice_hash": slice_hash,
            "nodes": list(slice_g.nodes()),
            "edges": list(slice_g.edges()),
        }
        output_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[bold green][+][/bold green] Exported slice metadata to {output_json}")


@main.command()
@click.option(
    "--db",
    "db_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="SQLite database path.",
)
@click.option(
    "--poi",
    "poi_key",
    type=str,
    required=True,
    help="Point of Interest event key (host:channel:record_id).",
)
@click.option("--depth", type=int, default=15, help="Maximum edge traversal depth.")
@click.option(
    "--window",
    "window_sec",
    type=float,
    default=3600.0,
    help="Temporal window delta around PoI in seconds.",
)
@click.option(
    "--entropy/--no-entropy", default=False, help="Use Shannon relation entropy heuristic."
)
@click.option(
    "--output-json",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional path to export contracted graph metrics.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to YAML configuration file.",
)
def contract(
    db_path: Path,
    poi_key: str,
    depth: int,
    window_sec: float,
    entropy: bool,
    output_json: Path | None,
    config_path: Path | None = None,
) -> None:
    """Apply lossless hierarchical contraction to causal slice."""
    enable_fanout = True
    min_fanout = 3
    if config_path:
        cfg = load_config(config_path)
        if depth == 15:
            depth = cfg.slicing.max_depth
        if window_sec == 3600.0:
            window_sec = cfg.slicing.max_delta_sec
        enable_fanout = cfg.contraction.enable_fanout_contraction
        min_fanout = cfg.contraction.min_fanout_size

    with EvidenceLedger(db_path) as ledger:
        slice_g = compute_sqlite_cte_slice(
            ledger, poi_key=poi_key, max_depth=depth, max_delta_sec=window_sec
        )
        if slice_g.number_of_nodes() == 0:
            console.print("[red]No nodes found in causal slice for PoI.[/red]")
            return

        t0 = time.perf_counter()
        if entropy:
            contracted_g, macros = entropy_guided_contraction(
                slice_g, poi_key=poi_key, entropy_threshold=1.0, ledger=ledger
            )
        else:
            contracted_g, macros = contract_graph(
                slice_g,
                poi_key=poi_key,
                enable_fanout=enable_fanout,
                min_fanout_size=min_fanout,
                ledger=ledger,
            )
        t_elapsed = time.perf_counter() - t0

        metrics = compute_graph_metrics(slice_g, contracted_g)

    table = Table(title="Lossless Contraction Metrics", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    mode_desc = "Shannon Entropy Heuristic" if entropy else "Structural Equivalence"
    table.add_row("Contraction Mode", mode_desc)
    table.add_row("Original Slice Vertices", f"{slice_g.number_of_nodes():,}")
    table.add_row("Contracted Vertices", f"{contracted_g.number_of_nodes():,}")
    table.add_row("Created Macro-Edges", f"{len(macros):,}")
    table.add_row("Graph Size Reduction (GSR)", f"{metrics.graph_size_reduction * 100:.1f}%")
    table.add_row("Structural Complexity Ratio (SCR)", f"{metrics.structural_complexity_ratio:.3f}")
    table.add_row(
        "Reachability Invariant",
        "[bold green]100.0% PRESERVED[/bold green]"
        if metrics.reachability_preserved
        else "[bold red]VIOLATED[/bold red]",
    )
    table.add_row("Contraction Latency", f"{t_elapsed:.4f}s")
    console.print(table)

    if output_json:
        data = {
            "poi_key": poi_key,
            "entropy": entropy,
            "slice_nodes": slice_g.number_of_nodes(),
            "slice_edges": slice_g.number_of_edges(),
            "contracted_nodes": contracted_g.number_of_nodes(),
            "contracted_edges": contracted_g.number_of_edges(),
            "macro_edges": len(macros),
            "gsr": metrics.graph_size_reduction,
            "scr": metrics.structural_complexity_ratio,
            "reachability_preserved": metrics.reachability_preserved,
        }
        output_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[bold green][+][/bold green] Exported metrics to {output_json}")


@main.command()
@click.option(
    "--db",
    "db_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="SQLite database path.",
)
@click.option(
    "--poi",
    "poi_key",
    type=str,
    required=True,
    help="Point of Interest event key (host:channel:record_id).",
)
@click.option(
    "--output-html",
    type=click.Path(path_type=Path),
    default=Path("provenance_graph.html"),
    help="Target HTML visualization file.",
)
@click.option("--contract/--no-contract", default=True, help="Apply contraction prior to export.")
def export(db_path: Path, poi_key: str, output_html: Path, contract: bool) -> None:
    """Export self-contained Cytoscape.js interactive provenance graph to HTML."""
    with EvidenceLedger(db_path) as ledger:
        slice_g = compute_sqlite_cte_slice(ledger, poi_key=poi_key)
        if slice_g.number_of_nodes() == 0:
            console.print("[red]No nodes in slice for PoI.[/red]")
            return

        if contract:
            graph_to_export, _ = contract_graph(slice_g, poi_key=poi_key, ledger=ledger)
        else:
            graph_to_export = slice_g

        export_interactive_html(
            graph_to_export,
            output_path=output_html,
            title=f"ProvGraph-DFIR: PoI {poi_key}",
            poi_key=poi_key,
        )
        out_str = str(output_html.resolve())
        console.print(
            f"[bold green][+][/bold green] Exported to: [yellow]{out_str}[/yellow]"
        )


@main.command()
@click.option("--port", type=int, default=8501, help="Port to run Streamlit server.")
@click.option("--host", type=str, default="localhost", help="Host address for Streamlit.")
def ui(port: int, host: str) -> None:
    """Launch the interactive Streamlit + Cytoscape.js Provenance Explorer UI."""
    app_path = Path(__file__).parent / "visualization" / "app.py"
    console.print(
        Panel.fit(
            f"[bold cyan]Launching ProvGraph Interactive Explorer[/bold cyan]\n"
            f"URL: [bold green]http://{host}:{port}[/bold green]\n"
            f"Press Ctrl+C to terminate the UI.",
            title="ProvGraph UI",
        )
    )
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.port",
        str(port),
        "--server.address",
        host,
    ]
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        console.print("\n[yellow]UI server stopped by user.[/yellow]")


@main.command()
@click.option(
    "--data-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("data/raw_mordor"),
    help="Directory containing Mordor JSON datasets.",
)
@click.option(
    "--output-json",
    type=click.Path(path_type=Path),
    default=Path("experiments/ablation_results.json"),
    help="Target path for ablation matrix output.",
)
def benchmark(data_dir: Path, output_json: Path) -> None:
    """Run automated multi-scenario ablation matrix benchmark across all datasets."""
    from experiments.run_ablation_matrix import run_full_ablation

    console.print("[bold cyan]Running ProvGraph-DFIR Multi-Scenario Ablation Suite...[/bold cyan]")
    run_full_ablation()


@main.command(name="config")
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to YAML configuration file.",
)
def view_config(config_path: Path | None) -> None:
    """Display active pipeline configuration and cataloged benchmark scenarios."""
    cfg = load_config(config_path)
    scenarios_cat = load_scenarios()

    console.print(
        Panel.fit(
            "[bold cyan]ProvGraph-DFIR Configuration Engine[/bold cyan]",
            title="Config",
        )
    )

    t_cfg = Table(title="Pipeline Parameters", show_header=True)
    t_cfg.add_column("Category", style="cyan")
    t_cfg.add_column("Parameter", style="yellow")
    t_cfg.add_column("Value", style="green")

    t_cfg.add_row("Slicing", "max_depth", str(cfg.slicing.max_depth))
    t_cfg.add_row("Slicing", "max_delta_sec", f"{cfg.slicing.max_delta_sec}s")
    t_cfg.add_row("Slicing", "direction", cfg.slicing.direction)
    t_cfg.add_row(
        "Contraction", "entropy_threshold", str(cfg.contraction.entropy_threshold)
    )
    t_cfg.add_row(
        "Contraction",
        "enable_fanout_contraction",
        str(cfg.contraction.enable_fanout_contraction),
    )
    t_cfg.add_row(
        "Contraction", "min_fanout_size", str(cfg.contraction.min_fanout_size)
    )
    t_cfg.add_row("Storage", "default_db_path", cfg.storage.default_db_path)
    console.print(t_cfg)

    t_sc = Table(
        title=f"Cataloged Scenarios ({len(scenarios_cat.scenarios)})",
        show_header=True,
    )
    t_sc.add_column("ID", style="cyan")
    t_sc.add_column("Scenario Name", style="white")
    t_sc.add_column("Technique", style="yellow")
    t_sc.add_column("Dataset File", style="green")
    t_sc.add_column("Steps", justify="right", style="magenta")

    for s in scenarios_cat.scenarios:
        t_sc.add_row(s.id, s.name, s.technique, s.file, str(len(s.ground_truth_steps)))
    console.print(t_sc)


if __name__ == "__main__":
    main()
