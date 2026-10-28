# ProvGraph-DFIR

> **Deterministic Causal Slicing and Lossless Hierarchical Contraction for Windows Forensic Provenance Graphs**

ProvGraph-DFIR is a high-performance Digital Forensics and Incident Response (DFIR) framework designed to ingest high-volume Windows security telemetry (Sysmon and EVTX), construct mathematically sound, strictly acyclic causal execution Directed Acyclic Graphs (DAGs), isolate incident-relevant subgraphs via deterministic bidirectional slicing, and losslessly contract redundant execution chains for auditable forensic investigation.

---

## Key Capabilities & Technical Specifications

1. **Strict Total Order Event-Time DAG Construction**
   - Ingests raw Sysmon (JSON / EVTX) and constructs an execution DAG $\mathcal{G} = (\mathcal{V}, \mathcal{E})$.
   - Enforces strict monotonic ordering across contemporaneous events via a composite key $(t, \text{RecordID}, \text{EventID})$ to mathematically eliminate causal cycles ($t(u) \le t(v)$).
   - Maps granular Windows primitives (Process Creation, Network Connect, File Create/Write/Delete, Registry Modification, Remote Thread Injection).

2. **Deterministic Bidirectional Causal Slicing**
   - **Antecedent Root-Cause Slicing ($\mathcal{B}(s)$):** Traverses backward in time to identify initial execution vectors, download cradles, and ingress points.
   - **Downstream Consequence Slicing ($\mathcal{F}(s)$):** Traverses forward in time to determine lateral spread, credential dumping, persistence, and impact.
   - Strictly bounded by Point-of-Interest (PoI) relative time horizons ($\Delta t_{\text{back}}$, $\Delta t_{\text{fwd}}$) to prevent exponential graph explosion.

3. **Lossless Hierarchical Contraction**
   - Solves the investigative dependency explosion without loss of evidence.
   - Replaces heuristic lossy pruning with provable structural equivalence contraction, collapsing intermediate single-in/single-out execution chains into typed Macro-Edges.
   - **Preservation Invariant:** Preserves reachability between all retained endpoints.
   - **Forensic Chain-of-Custody:** Retains full raw telemetry event pointers and cryptographic hashes within an immutable SQLite ledger.

4. **Reversible Path Expansion**
   - Implements an exact, deterministic `Expand(e)` primitive.
   - Allows investigators to visually drill down into any contracted macro-edge and restore full granular subpaths on demand.

5. **Auditable SQLite Provenance Ledger**
   - High-throughput indexing and persistence of entities, events, and causal relations.
   - High-performance recursive Common Table Expressions (CTEs) for multi-hop path extraction and ancestor/descendant reachability queries.

6. **Interactive Visualization & Web UI**
   - Standalone Streamlit-based investigator portal coupled with Cytoscape.js graph rendering.
   - Timeline filters, MITRE technique tagging, interactive node inspection, and dynamic graph expansion.

---

## Architecture Overview

```
Windows Telemetry (Sysmon / EVTX / Mordor)
                   │
                   ▼
       [ Ingestion & Normalizer ]
                   │
                   ▼
     [ Strict Total Order DAG Builder ]
                   │
                   ▼
      [ Immutable SQLite Ledger ]
         │                   │
         ▼                   ▼
 [ Recursive CTE Slicing ] [ Lossless Contraction ]
         │                   │
         └─────────┬─────────┘
                   │
                   ▼
       [ Interactive UI & Visualizer ]
```

---

## Installation

### Prerequisites
- Python 3.11 or higher
- PowerShell or bash

```powershell
# Clone the repository
git clone https://github.com/mukulsain09/ProvGraph-DFIR.git
cd ProvGraph-DFIR

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install in editable mode with development & UI dependencies
pip install -e ".[dev,viz]"
```

---

## Quick Start & CLI Usage

ProvGraph provides a unified command-line interface:

### 1. Ingest Security Telemetry
```powershell
provgraph ingest --input data/test_fixtures/ransomware_burst.json --db data/incident.db
```

### 2. Extract Deterministic Causal Slice
```powershell
provgraph slice --db data/incident.db --poi-node "PROC:1024" --backward-mins 60 --forward-mins 30
```

### 3. Contract Noise Losslessly
```powershell
provgraph contract --db data/incident.db --output data/contracted_graph.json
```

### 4. Export Self-Contained Interactive Visualization
```powershell
provgraph export --db data/incident.db --output incident_provenance.html
```

### 5. Launch the Web Visualizer
```powershell
provgraph ui --port 8501
```

---

## Testing & Quality Gates

Run the verification pipeline to ensure code integrity:

```powershell
# Run unit and integration tests
pytest -q

# Code formatting and linting
ruff check .

# Static type verification
mypy src tests
```

---

## License

This project is licensed under the Apache 2.0 License.
