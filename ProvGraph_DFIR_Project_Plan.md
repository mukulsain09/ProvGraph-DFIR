# ProvGraph-DFIR: Project Specification and Implementation Blueprint
## Deterministic Causal Slicing and Lossless Hierarchical Contraction for Windows Forensic Provenance Graphs

**Academic Program:** Integrated B.Tech–M.Tech in Cybersecurity, National Forensic Sciences University (NFSU)  
**Project Category:** Digital Forensics and Incident Response (DFIR) Research & Systems Implementation  
**Project Status:** Revised Research and Implementation Proposal (Post-Audit Verified Blueprint)  
**Target Completion:** 16-Week Schedule (October 2026 – February 2027)  
**Critical Target:** **Mid-December 2026 "Beyond-MVP" Interactive Demonstration**  
**Evaluation Review Artifact:** [`LLM_Council_Review_Report.md`](./LLM_Council_Review_Report.md)

---

## 1. Executive Summary

**ProvGraph-DFIR** is an offline digital forensics investigation engine designed to reconstruct evidence-linked, causal execution graphs from Windows security telemetry (Sysmon and EVTX). Modern forensic examiners are routinely overwhelmed by hundreds of thousands of unstructured, flat event records during incident triage. While current forensic tools (e.g., Plaso, Timesketch, Hayabusa) perform chronological timeline indexing, they cannot compute causal data flow or trace living-off-the-land multi-hop attack paths. Conversely, academic provenance engines focus heavily on real-time Linux kernel interception (e.g., `auditd`, eBPF), largely neglecting post-mortem Windows endpoint triage.

ProvGraph-DFIR solves this by allowing an investigator to designate a suspicious **Point of Interest (PoI)**—such as an encoded PowerShell command, an unrecognized network socket, or an alert record—and automatically extract a **time-monotonic, deterministic causal slice** tracing antecedent root causes (backward) and downstream consequences (forward).

Crucially, addressing the findings of both the LLM Council review and the technical pre-implementation audit, ProvGraph-DFIR rejects lossy node pruning. In forensic practice and legal proceedings (e.g., Daubert standard, Section 65B of the Indian Evidence Act), permanent deletion of intermediate events invalidates evidentiary chain-of-custody. Instead, ProvGraph-DFIR introduces **Lossless Hierarchical Contraction**: collapsing repetitive, structurally equivalent intermediate execution sequences into typed **Macro-Edges** while maintaining an immutable SQLite ledger mapping every visual element directly to raw, verifiable Windows Event Record IDs and preserving full, bidirectional invertibility (exact path expansion).

---

## 2. Research Objectives and Formal Hypotheses

### Primary Research Objective
Design, implement, and experimentally validate an offline forensic provenance engine that constructs deterministic, event-centric causal DAGs from Windows telemetry, performs auditable backward/forward slicing from a Point of Interest, and applies lossless hierarchical contraction to maximize graph comprehension without evidence loss.

### Formal Research Questions
* **RQ1 (Contraction Efficiency):** By how much does lossless hierarchical contraction reduce visual graph complexity (node and edge counts) compared to unpruned causal slicing across documented Windows attack scenarios?
* **RQ2 (Information-Theoretic Utility & Inversion):** Does a categorical Shannon edge-diversity metric provide any measurable advantage in identifying collapsible routine behaviors over pure structural equivalence, or does it introduce algorithmic inversion by penalizing high-volume uniform attack bursts (e.g., ransomware, credential dumping)?
* **RQ3 (Algorithmic Contraction Invariant & Invertibility):** Does lossless hierarchical contraction mathematically and empirically guarantee 100% reachability preservation between all retained boundary vertices ($u \rightsquigarrow w \text{ in } \mathcal{G}_{\text{slice}} \iff u \rightsquigarrow w \text{ in } \mathcal{G}'$), and does it permit exact reconstruction of the contracted subpath and its evidence references?
* **RQ4 (Telemetry Completeness & Attack Path Recall):** Under asynchronous, sampled Windows Sysmon telemetry without kernel-level syscall interposition, what proportion of ground-truth MITRE ATT&CK technique sequences are captured in the ingested graph, and does the slicing/contraction pipeline preserve 100% of the recoverable telemetry attack paths?
* **RQ5 (Structural Investigation Simplification):** To what extent does contraction simplify graph topology (measured by Graph Structural Complexity Ratio, diameter, and average degree), and does macro-edge aggregation maintain 100% retrievability of forensic attributes without loss of context?

### Core Hypotheses
1. *Contraction Reachability & Invertibility Invariant:* Lossless hierarchical contraction mathematically guarantees that reachability between any pair of retained vertices is invariant ($u \rightsquigarrow w \iff u \rightsquigarrow_{\text{contracted}} w$) and permits exact subpath reconstruction ($\text{Expand}(e_{\text{macro}}) \equiv \mathcal{P}_{\text{original}}$) while reducing visual graph elements by $\ge 70\%$.
2. *Telemetry Recall Decoupling:* Sensor-level telemetry omissions (e.g., dropped logs, unlogged in-memory operations) bound overall attack path recall ($R_{\text{telemetry}} \le 1.0$), but the causal slicing and contraction pipeline introduces zero additional reachability loss ($R_{\text{pipeline}} = 1.0$).
3. *Entropy Inversion Hypothesis:* Categorical Shannon entropy over relation frequencies penalizes uniform attack bursts (e.g., ransomware file encryption, credential dumping) while favoring benign multi-action system noise (`svchost.exe`), making structural equivalence contraction strictly superior in both attack recall and execution latency.

---

## 3. Scope Boundaries and Prior-Art Positioning

### In Scope (Mandatory Thesis Deliverables)
* **Telemetry Focus:** Windows Sysmon (pre-recorded JSON exports from the Mordor project and compatible native EVTX exports). Supported Event IDs:
  * Event ID 1: Process Creation
  * Event ID 3: Network Connection Detected
  * Event ID 7: Image Loaded (DLLs)
  * Event ID 8: CreateRemoteThread (Injection)
  * Event ID 11: FileCreate / FileOverwrite
  * Event ID 12 / 13: Registry Object Added / Value Modified
* **Graph Formalism:** Event-Centric Directed Acyclic Graph (DAG) enforcing a strict total order ($u \prec v$) over all event vertices to guarantee acyclicity even among contemporaneous events.
* **Identity Resolution:** Robust resolution using Sysmon `ProcessGuid` to guarantee immunity to Windows PID recycling.
* **Deterministic Bidirectional Slicing:** Time-bounded backward ($\mathcal{B}(s)$) and forward ($\mathcal{F}(s)$) reachability with deterministic priority queue tie-breaking and PoI-relative time window constraints.
* **Lossless Contraction:** Structural equivalence macro-edge abstraction backed by an immutable SQLite evidence ledger and an explicit sub-path expansion API.
* **Evaluation Scenarios:** Controlled attack datasets from the [Mordor Project](https://github.com/OTRF/mordor) covering MITRE ATT&CK techniques (Empire, Cobalt Strike, Ransomware, Credential Dumping).
* **Delivery Milestone:** Fully functional interactive visualization tool demo ready by **Mid-December 2026**.

### Out of Scope (Explicitly Excluded to Prevent Failure)
* **DARPA OpTC Dataset:** Excluded entirely due to massive size (>1 TB compressed eCAR JSON) and ambiguous narrative-only ground truth.
* **Live Kernel Interception:** No real-time kernel drivers or live ETW streaming; strictly offline post-mortem triage.
* **Lossy Permanent Node Pruning:** No destructive deletion of graph vertices; all reduction is reversible aggregation into macro-edges.
* **Full Rust Engine Rewrite:** Core algorithms implemented in Python using indexed SQLite pre-filtering and NetworkX for bounded slices.
* **Automated Threat Actor Attribution:** No probabilistic intent guessing or machine learning malware classifiers.

### Prior-Art Positioning and Novelty Claim

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              PRIOR-ART COMPARISON MATRIX                               │
├───────────────┬──────────────┬───────────────┬─────────────────┬───────────────┬───────┤
│ System        │ Telemetry    │ Graph Model   │ Reduction Style │ Reversibility │ Open? │
├───────────────┼──────────────┼───────────────┼─────────────────┼───────────────┼───────┤
│ CPR (CCS '16) │ Linux Auditd │ Event DAG     │ State deletion  │ Irreversible  │ Part  │
│ NodeMerge '18 │ Linux Auditd │ Event DAG     │ Template merge  │ Partial       │ No    │
│ PrioTracker   │ Linux Auditd │ Dependency    │ Anomaly drop    │ Irreversible  │ No    │
│ ProvGRP '24   │ Linux/DARPA  │ Context Graph │ Path clustering │ Irreversible  │ No    │
│ TeRed '25     │ Linux Auditd │ Dependency    │ Unit-test prune │ Irreversible  │ No    │
│ CSCProv '26   │ Linux/DARPA  │ Semantic Graph│ Semantic merge  │ Partial       │ No    │
│ CONTEXTS '25  │ Linux/Win    │ POI Subgraph  │ Waypoint slice  │ Unspecified   │ No    │
├───────────────┼──────────────┼───────────────┼─────────────────┼───────────────┼───────┤
│ ProvGraph-    │ Windows      │ Strict Order  │ Lossless Macro- │ Fully         │ Open  │
│ DFIR (Ours)   │ Sysmon/EVTX  │ Event DAG     │ Edge Contraction│ Reversible    │ Target│
└───────────────┴──────────────┴───────────────┴─────────────────┴───────────────┴───────┘
```

#### Defensible Novelty Statement
ProvGraph-DFIR does not claim novelty on the general concept of causal slicing. Its defensible academic contribution lies in:
> *The formalization, proof, and empirical evaluation of **reversible, lossless hierarchical contraction** tailored specifically to the failure modes and semantics of **offline Windows Sysmon telemetry** (ProcessGUID tracking, strict total-order event-time DAGs, and living-off-the-land techniques), benchmarked against structural equivalence and Shannon relation entropy heuristics to establish exact reachability preservation and forensic auditability.*

---

## 4. Formal Mathematical and Algorithmic Specification

### 4.1. The Event-Centric Time-Expanded Graph Model

Entity-level Windows graphs (where nodes are long-lived processes or files) inherently contain directed cycles:
$$\text{Process } P \xrightarrow{\text{Write}} \text{File } F \xrightarrow{\text{Read}} \text{Process } P$$
Traversing a cyclic entity graph produces causal paradoxes (backward-in-time reachability). ProvGraph-DFIR eliminates these cycles by defining the graph strictly at the **event-instance level**.

#### Definition 1 (Event Vertex and Composite Identity)
An event vertex $v \in V$ is an immutable tuple:
$$v = \langle \text{event\_key}, t, \tau, \text{proc\_guid}, \text{target\_obj}, \text{host}, \text{channel}, \text{record\_id} \rangle$$
where:
* $\text{event\_key} = (\text{host} \,\|\, \text{channel} \,\|\, \text{record\_id})$ is the globally unique composite identifier.
* $t \in \mathbb{R}^+$ is the normalized UTC epoch timestamp (millisecond resolution).
* $\tau \in \mathcal{T}$ is the normalized event type (e.g., `ProcessCreate`, `FileCreate`, `NetConnect`).
* $\text{proc\_guid}$ is the Sysmon-generated process GUID (immune to PID reuse).
* $\text{target\_obj}$ is the contextual target (file path, remote IP:Port, registry key, or `NULL`).

#### Definition 2 (Strict Total Order $\prec$)
To break timestamp ties deterministically and prevent cycles between contemporaneous events, we define a strict total order $\prec$ over all event vertices:
$$u \prec v \iff \begin{cases} 
t(u) < t(v) \\
t(u) = t(v) \land \text{host}(u) < \text{host}(v) \\
t(u) = t(v) \land \text{host}(u) = \text{host}(v) \land \text{channel}(u) < \text{channel}(v) \\
t(u) = t(v) \land \text{host}(u) = \text{host}(v) \land \text{channel}(u) = \text{channel}(v) \land \text{record\_id}(u) < \text{record\_id}(v)
\end{cases}$$

#### Definition 3 (Causal Temporal Edge)
A directed edge $e = (u, v) \in E$ with relation type $r \in \mathcal{R}$ exists if and only if:
1. $u \prec v$ (**Strict Monotonic Ordering**).
2. A valid causal dependency links $u$ and $v$ according to the explicit Causal Edge Inference Rules (Section 4.2).

#### Theorem 1 (Strict DAG Acyclicity Guarantee)
*The event-centric provenance graph $\mathcal{G} = (V, E)$ constructed under Definition 3 is strictly a Directed Acyclic Graph (DAG).*

*Proof:*  
Suppose $\mathcal{G}$ contains a directed cycle $C = v_1 \to v_2 \to \dots \to v_k \to v_1$.  
By Condition 1 of Definition 3, every directed edge $(v_i, v_{i+1}) \in E$ requires $v_i \prec v_{i+1}$.  
By the transitivity of the strict total order $\prec$:
$$v_1 \prec v_2 \prec \dots \prec v_k \implies v_1 \prec v_k$$
For the closing edge $(v_k, v_1) \in E$ to exist, Condition 1 requires:
$$v_k \prec v_1$$
However, by the asymmetry property of strict total orders, $v_1 \prec v_k \implies v_k \not\prec v_1$.  
This is a contradiction. Therefore, no directed cycle can exist in $\mathcal{G}$. $\mathcal{G}$ is strictly a DAG. $\blacksquare$

---

### 4.2. Windows Telemetry Causal-Edge Inference Engine

Causal relationships cannot be assumed solely from timestamp proximity. The following inference rules define how directed edges $(u, v)$ are constructed:

| Source Event ($u$) | Target Event ($v$) | Inferred Relation ($r$) | Ingestion & Join Precondition | Forensic Semantic Meaning |
| :--- | :--- | :--- | :--- | :--- |
| **Event 1** (ProcessCreate) | **Event 1** (ProcessCreate) | `SPAWNS` | $u.\text{proc\_guid} == v.\text{parent\_proc\_guid} \land u \prec v$ | Direct process hierarchy execution (Parent $\to$ Child). |
| **Event 1** (ProcessCreate) | **Event 3** (NetConnect) | `OPENS_SOCKET` | $u.\text{proc\_guid} == v.\text{proc\_guid} \land u \prec v$ | Process establishes external network telemetry. |
| **Event 1** (ProcessCreate) | **Event 7** (ImageLoad) | `LOADS_IMAGE` | $u.\text{proc\_guid} == v.\text{proc\_guid} \land u \prec v$ | Process loads a DLL or executable module. |
| **Event 1** (ProcessCreate) | **Event 8** (RemoteThread) | `CREATES_THREAD` | $u.\text{proc\_guid} == v.\text{proc\_guid} \land u \prec v$ | Source process initiates cross-process injection. |
| **Event 1** (ProcessCreate) | **Event 11** (FileCreate) | `WRITES_FILE` | $u.\text{proc\_guid} == v.\text{proc\_guid} \land u \prec v$ | Process creates or overwrites a file on disk. |
| **Event 1** (ProcessCreate) | **Event 12/13** (RegAction) | `MODIFIES_REG` | $u.\text{proc\_guid} == v.\text{proc\_guid} \land u \prec v$ | Process adds or alters a registry key/value. |
| **Event 11** (FileCreate) | **Event 1** (ProcessCreate) | `DROPS_EXEC` | $u.\text{target\_obj} == v.\text{image\_path} \land u \prec v$ | Dropper or script creates an executable that is later spawned. |
| **Event 11** (FileCreate) | **Event 7** (ImageLoad) | `DROPS_DLL` | $u.\text{target\_obj} == v.\text{target\_obj} \land u \prec v$ | Dropped file is loaded dynamically as a library. |
| **Event 8** (RemoteThread) | **Event 1 / 3 / 11** | `INJECTED_EXEC` | $u.\text{target\_proc\_guid} == v.\text{proc\_guid} \land u \prec v$ | Activity executed by target process following memory injection. |

> [!NOTE]
> **Telemetry Boundary Limitation:** Sysmon does not log file-read operations (`FileRead`). Therefore, data-flow dependencies through intermediary files are inferred specifically when an execution event (`ProcessCreate` or `ImageLoad`) references a file previously written by another process (`DROPS_EXEC`, `DROPS_DLL`). If native Windows Security Event ID 4663 is present, explicit read-edges are incorporated.

---

### 4.3. Algorithm 1: Deterministic Bidirectional Causal Slicing

Given the event graph $\mathcal{G} = (V, E)$, a selected Point of Interest $s \in V$, a maximum depth limit $D_{\max}$, and a lookback/lookahead time window $\Delta T$:

$$\mathcal{B}(s) = \{u \in V \mid u \rightsquigarrow s \land (t(s) - t(u) \le \Delta T) \land \text{dist}(u, s) \le D_{\max}\}$$

$$\mathcal{F}(s) = \{w \in V \mid s \rightsquigarrow w \land (t(w) - t(s) \le \Delta T) \land \text{dist}(s, w) \le D_{\max}\}$$

$$\mathcal{S}(s) = \mathcal{G}[\mathcal{B}(s) \cup \mathcal{F}(s)]$$

```python
import networkx as nx
from typing import Tuple, Set

def compute_deterministic_slice(
    G: nx.DiGraph, 
    poi_key: str, 
    max_depth: int, 
    max_delta_sec: float
) -> nx.DiGraph:
    """
    Computes a deterministic, bidirectional causal slice (backward root-cause
    and forward impact) bounded strictly relative to the Point of Interest (PoI).
    """
    poi_node = G.nodes[poi_key]
    poi_time = poi_node['timestamp_epoch']
    
    slice_nodes: Set[str] = {poi_key}
    
    # 1. Backward Traversal (Root Cause Discovery)
    # Queue stores: (node_key, current_depth)
    b_queue = [(poi_key, 0)]
    b_visited = {poi_key}
    
    while b_queue:
        # Deterministic sort: descending by timestamp, host, channel, record_id
        b_queue.sort(
            key=lambda item: (
                G.nodes[item[0]]['timestamp_epoch'],
                G.nodes[item[0]]['host_name'],
                G.nodes[item[0]]['channel'],
                G.nodes[item[0]]['record_id']
            ),
            reverse=True
        )
        curr_key, depth = b_queue.pop(0)
        
        if depth >= max_depth:
            continue
            
        for pred_key in G.predecessors(curr_key):
            pred_node = G.nodes[pred_key]
            # Enforce PoI-relative time window & strict DAG ordering
            time_delta = poi_time - pred_node['timestamp_epoch']
            if 0 <= time_delta <= max_delta_sec:
                slice_nodes.add(pred_key)
                if pred_key not in b_visited:
                    b_visited.add(pred_key)
                    b_queue.append((pred_key, depth + 1))

    # 2. Forward Traversal (Downstream Impact Discovery)
    f_queue = [(poi_key, 0)]
    f_visited = {poi_key}
    
    while f_queue:
        # Deterministic sort: ascending by timestamp, host, channel, record_id
        f_queue.sort(
            key=lambda item: (
                G.nodes[item[0]]['timestamp_epoch'],
                G.nodes[item[0]]['host_name'],
                G.nodes[item[0]]['channel'],
                G.nodes[item[0]]['record_id']
            ),
            reverse=False
        )
        curr_key, depth = f_queue.pop(0)
        
        if depth >= max_depth:
            continue
            
        for succ_key in G.successors(curr_key):
            succ_node = G.nodes[succ_key]
            # Enforce PoI-relative time window & strict DAG ordering
            time_delta = succ_node['timestamp_epoch'] - poi_time
            if 0 <= time_delta <= max_delta_sec:
                slice_nodes.add(succ_key)
                if succ_key not in f_visited:
                    f_visited.add(succ_key)
                    f_queue.append((succ_key, depth + 1))
                    
    # Return induced subgraph containing both causal directions
    return G.subgraph(slice_nodes).copy()
```

---

### 4.4. Algorithm 2: Lossless Hierarchical Contraction and Exact Invertibility

Lossless contraction replaces linear, homogeneous intermediate execution sequences with **Macro-Edges**, preserving all endpoints, topological reachability, and audit records.

#### Definition 4 (Contraction Eligibility)
A node $v \in V$ is an **eligible contraction candidate** if and only if:
1. $v \neq s$ (PoI is protected).
2. $v$ is not an external or root-cause boundary ($\text{in-degree}(v) > 0$).
3. $v$ is not a terminal egress or external socket ($\text{out-degree}(v) > 0$).
4. $\text{in-degree}(v) = 1$ and $\text{out-degree}(v) = 1$. Let $u$ be its unique predecessor and $w$ be its unique successor.
5. The incoming edge $(u, v)$ and outgoing edge $(v, w)$ share identical process context ($\text{proc\_guid}$) and relation type ($r$).

#### Definition 5 (Macro-Edge Formation & Ordered Sequence)
When $v$ is contracted, edges $(u, v)$ and $(v, w)$ are replaced by a macro-edge:
$$e_{\text{macro}} = \langle u, w, r, \mathcal{S}_{\text{records}}, \mathcal{M} \rangle$$
where:
* $\mathcal{S}_{\text{records}} = \mathcal{S}_{(u, v)} \oplus \langle \text{event\_key}(v) \rangle \oplus \mathcal{S}_{(v, w)}$ is the **strictly ordered sequence** (concatenation $\oplus$) of underlying event keys.
* $\mathcal{M} = \langle t_{\text{start}}, t_{\text{end}}, k, \mathcal{V}_{\text{contracted}}, \mathcal{E}_{\text{contracted}} \rangle$ is the immutable contraction provenance metadata containing intermediate edge types, timestamps, and serialized subpath geometry.

#### Definition 6 (Exact Path Expansion API)
For any macro-edge $e_{\text{macro}} = (u, w)$, the expansion operator $\text{Expand}(e_{\text{macro}})$ is defined as:
$$\text{Expand}(e_{\text{macro}}) \implies \mathcal{P} = (u, v_1, v_2, \dots, v_k, w)$$
where the exact sequence of intermediate vertices $\mathcal{V}_{\text{contracted}}$ and directed edges $\mathcal{E}_{\text{contracted}}$ are restored into the graph with identical attributes.

#### Theorem 2 (Reachability Preservation Invariant)
*Let $\mathcal{G}_{\text{slice}} = (V, E)$ be the uncontracted slice, and let $\mathcal{G}' = (V', E')$ be the contracted graph obtained by contracting eligible vertex $v$. For all boundary vertices $a, b \in V \setminus \{v\}$:*
$$a \rightsquigarrow b \text{ in } \mathcal{G}_{\text{slice}} \iff a \rightsquigarrow b \text{ in } \mathcal{G}'$$

*Proof:*  
$(\implies)$ Let $P = (a = x_0, x_1, \dots, x_m = b)$ be a directed path from $a$ to $b$ in $\mathcal{G}_{\text{slice}}$.
* Case 1: $v \notin P$. Every edge in $P$ remains in $E'$, so $P$ is an intact path in $\mathcal{G}' \implies a \rightsquigarrow b \text{ in } \mathcal{G}'$.
* Case 2: $v \in P$. Because $\text{in-degree}(v) = 1$ and $\text{out-degree}(v) = 1$, the incoming edge to $v$ must be $(u, v)$ and the outgoing edge must be $(v, w)$. Thus, $P$ has the exact subpath $(\dots, u, v, w, \dots)$. In $\mathcal{G}'$, the subpath $u \to v \to w$ is replaced by the macro-edge $u \xrightarrow{\text{macro}} w$. Substituting this macro-edge yields a valid directed path $P' = (\dots, u, w, \dots)$ in $\mathcal{G}' \implies a \rightsquigarrow b \text{ in } \mathcal{G}'$.

$(\impliedby)$ Let $P'$ be a directed path from $a$ to $b$ in $\mathcal{G}'$.
* Case 1: $P'$ does not contain the macro-edge $(u, w)$. Then every edge in $P'$ is an original edge in $E$, so $a \rightsquigarrow b \text{ in } \mathcal{G}_{\text{slice}}$.
* Case 2: $P'$ traverses $u \xrightarrow{\text{macro}} w$. By Definition 5, this macro-edge was created from the valid subpath $u \to v \to w$ in $\mathcal{G}_{\text{slice}}$. Replacing $(u, w)$ with $(u, v, w)$ yields a valid directed path in $\mathcal{G}_{\text{slice}} \implies a \rightsquigarrow b \text{ in } \mathcal{G}_{\text{slice}}$.  
Therefore, reachability between all retained vertices is strictly invariant. $\blacksquare$

---

## 5. System Architecture and Database Schema

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         PROVGRAPH-DFIR SYSTEM PIPELINE                           │
├─────────────────────┬────────────────────┬────────────────────┬──────────────────┤
│ 1. Telemetry Ingest │ 2. Normalization & │ 3. Deterministic   │ 4. Contraction & │
│    & Filtering      │    Evidence Ledger │    Causal Slicing  │    Visualization │
├─────────────────────┼────────────────────┼────────────────────┼──────────────────┤
│ • Mordor Sysmon     │ • SQLite Ledger    │ • Strict-Order DAG │ • Macro-Edge     │
│ • Native EVTX       │ • ProcessGUID Map  │ • PoI Slicing      │   Contraction    │
│ • Supported Event   │ • Composite Keys   │   (Bidirectional)  │ • Reversible     │
│   IDs (1,3,7,8,11..)│ • Indexing         │ • Monotonic Order  │   Drilldown UI   │
└─────────────────────┴────────────────────┴────────────────────┴──────────────────┘
```

### 5.1. SQLite Evidence Ledger Schema

The SQLite database acts as the immutable single source of truth, decoupled from in-memory NetworkX graph objects.

```sql
-- Normalized Process Table resolving identity across PID recycling
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

-- Immutable Event Ledger linking every graph element to raw records
CREATE TABLE IF NOT EXISTS event_ledger (
    event_key TEXT PRIMARY KEY,            -- host:channel:record_id (Globally unique)
    host_name TEXT NOT NULL,
    channel TEXT NOT NULL,                 -- e.g., Microsoft-Windows-Sysmon/Operational
    record_id INTEGER NOT NULL,
    timestamp_utc TEXT NOT NULL,
    timestamp_epoch REAL NOT NULL,
    event_type TEXT NOT NULL,              -- ProcessCreate, FileCreate, NetConnect, etc.
    event_id INTEGER NOT NULL,             -- Windows Event ID (1, 3, 7, 8, 11, etc.)
    process_guid TEXT,                     -- Nullable to accommodate headless/system events
    parent_process_guid TEXT,
    target_object TEXT,                    -- Nullable (File path, IP:Port, Reg key)
    hashes TEXT,                           -- SHA256 / ImpHash
    raw_payload TEXT NOT NULL              -- Complete raw JSON/EVTX payload
);

-- Immutable Macro-Edge Ledger enabling O(1) drill-down and 100% reversible expansion
CREATE TABLE IF NOT EXISTS macro_edges (
    macro_edge_id TEXT PRIMARY KEY,
    source_event_key TEXT NOT NULL,
    target_event_key TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    start_time_epoch REAL NOT NULL,
    end_time_epoch REAL NOT NULL,
    ordered_event_keys TEXT NOT NULL,      -- JSON-serialized array of event keys
    serialized_subgraph_json TEXT NOT NULL,-- Exact edge/vertex structure for Expand()
    FOREIGN KEY(source_event_key) REFERENCES event_ledger(event_key),
    FOREIGN KEY(target_event_key) REFERENCES event_ledger(event_key)
);

CREATE INDEX IF NOT EXISTS idx_events_proc ON event_ledger(process_guid);
CREATE INDEX IF NOT EXISTS idx_events_time ON event_ledger(timestamp_epoch);
CREATE INDEX IF NOT EXISTS idx_events_target ON event_ledger(target_object);
CREATE INDEX IF NOT EXISTS idx_events_composite ON event_ledger(host_name, channel, record_id);
```

---

## 6. Target Deliverables: The Mid-December "Beyond-MVP" Milestone

To satisfy the academic requirement of presenting **more than a basic MVP by Mid-December 2026**, the system will deliver a functional, interactive investigation workspace with automated algorithmic verification.

### Mid-December Deliverable Checklist (Week 8)
1. **Automated Pipeline:** Single-command ingestion of any Mordor Sysmon scenario into the SQLite ledger with composite event keys.
2. **Deterministic Slicing API:** Given a `poi_key` (PoI), generates the bidirectional slice ($\mathcal{B}(s) \cup \mathcal{F}(s)$) strictly bounded by $\Delta T$ within $<3$ seconds.
3. **Lossless Contraction Engine:** Automatically collapses linear intermediate chains while generating automated proof logs demonstrating 100% reachability preservation and exact subpath expansion fidelity.
4. **Interactive Provenance Explorer (Beyond-MVP UI):**
   * Built with **Streamlit + Cytoscape.js**.
   * Renders the contracted provenance graph with distinct visual styles (color-coded nodes for Process, File, Registry, Network).
   * **Clickable Macro-Edges:** Clicking on any summarized edge opens a drawer displaying the ordered list of underlying Sysmon records directly from SQLite.
   * **Expand/Collapse Toggle:** Allows examiners to dynamically expand any macro-edge back into its original subpath within the visual canvas.
   * **PoI Centering & Path Highlighting:** Visual emphasis on the Root Cause $\to$ PoI attack path.
5. **Live Benchmark Demonstration:** A dashboard comparing raw graph vs. unpruned slice vs. contracted graph on two attack scenarios:
   * *Scenario A:* Living-off-the-Land Lateral Movement & Injection (Mordor Empire).
   * *Scenario B:* High-volume Ransomware file encryption burst.

---

## 7. Sixteen-Week Master Implementation Schedule

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               16-WEEK EXECUTION SCHEDULE                               │
├───────┬────────────────────┬───────────────────────────────────────────────────────────┤
│ Phase │ Dates              │ Milestone & Deliverables                                  │
├───────┼────────────────────┼───────────────────────────────────────────────────────────┤
│ 1     │ Oct 25 – Nov 08    │ Ingestion Engine & SQLite Composite Ledger                │
│       │ (Weeks 1–2)        │ • Mordor JSON parser & composite key indexer              │
│       │                    │ • SQLite event ledger & ProcessGUID resolver              │
│       │                    │ • Synthetic DAG correctness test suite (Theorem 1 test)   │
├───────┼────────────────────┼───────────────────────────────────────────────────────────┤
│ 2     │ Nov 09 – Nov 22    │ Event DAG Builder & Deterministic Slicing                 │
│       │ (Weeks 3–4)        │ • Strict-order monotonic DAG builder with causal rules    │
│       │                    │ • Deterministic backward/forward slice traverser          │
│       │                    │ • Unit tests for tie-breaking and cycle prevention        │
├───────┼────────────────────┼───────────────────────────────────────────────────────────┤
│ 3     │ Nov 23 – Dec 06    │ Lossless Contraction & Reversible Expansion Module        │
│       │ (Weeks 5–6)        │ • Structural equivalence contraction algorithm            │
│       │                    │ • Macro-edge SQLite mapping ledger & Expand() API         │
│       │                    │ • Experimental Shannon relation entropy ablation module   │
├───────┼────────────────────┼───────────────────────────────────────────────────────────┤
│ 4     │ Dec 07 – Dec 20    │ Beyond-MVP Interactive Demo & Panel Review                │
│       │ (Weeks 7–8)        │ • Streamlit / Cytoscape.js interactive provenance visualizer│
│       │                    │ • Clickable macro-edge drilldown & dynamic expand toggle  │
│       │                    │ • MID-DECEMBER FORMAL COMMITTEE DEMO & BENCHMARK REPORT   │
├───────┼────────────────────┼───────────────────────────────────────────────────────────┤
│ 5     │ Dec 21 – Jan 10    │ Multi-Scenario Benchmark & Ablation Study                 │
│       │ (Weeks 9–11)       │ • Evaluation across 4 Mordor scenarios + controlled lab   │
│       │                    │ • Ablation: Slice vs CPR vs Entropy vs ProvGraph          │
│       │                    │ • Structural complexity metrics (SCR, Diameter, Degree)   │
├───────┼────────────────────┼───────────────────────────────────────────────────────────┤
│ 6     │ Jan 11 – Jan 24    │ Stress Testing, Scalability Profiling & Packaging         │
│       │ (Weeks 12–13)      │ • Performance profiling (10k, 50k, 100k events)           │
│       │                    │ • Memory optimization & SQLite query pushdown             │
│       │                    │ • Standalone CLI tool packaging & documentation           │
├───────┼────────────────────┼───────────────────────────────────────────────────────────┤
│ 7     │ Jan 25 – Feb 15    │ Final Thesis Writing & Paper Manuscript                   │
│       │ (Weeks 14–16)      │ • Complete thesis chapters (Intro, Theory, Eval, Results) │
│       │                    │ • Submission-ready paper draft for DFRWS / FSI:DI         │
│       │                    │ • FINAL THESIS DEFENSE AT NFSU                            │
└───────┴────────────────────┴───────────────────────────────────────────────────────────┘
```

---

## 8. Experimental Evaluation Protocol

### 8.1. Evaluation Scenarios
1. **Mordor Empire PowerShell Stager (`host_0_sysmon.json`):** Living-off-the-land download cradle, registry persistence, and reflective DLL injection.
2. **Mordor Cobalt Strike HTTPS Beaconing:** Command execution, service creation, and remote named pipe communications.
3. **Controlled Ransomware Burst Dataset:** Pre-recorded Sysmon telemetry of simulated file mass-renaming and encryption loop executed in an isolated VM environment.
4. **Mordor Credential Dumping (Mimikatz / LSASS Access):** Process memory handle access and suspicious file write (`lsass.dmp`).

### 8.2. Baseline Configurations for Ablation
Every scenario will be evaluated across 5 pipeline configurations:
* **$B_1$ (Raw Telemetry Window):** Full event activity window without slicing or reduction.
* **$B_2$ (Standard Causal Slice):** Uncontracted bidirectional slice from PoI.
* **$B_3$ (Structural Equivalence Contraction):** Intermediate linear chain collapsing without entropy weighting.
* **$B_4$ (Shannon Relation Entropy Heuristic):** Candidate heuristic ranking nodes by categorical edge diversity.
* **$B_5$ (ProvGraph-DFIR Full Pipeline):** Strict-order event DAG + bidirectional slice + lossless reversible contraction.

### 8.3. Evaluation Metrics

| Metric | Formula | Target | Scientific Justification |
| :--- | :--- | :--- | :--- |
| **Graph Size Reduction (GSR)** | $1 - \frac{\|V'\| + \|E'\|}{\|V_{\text{slice}}\| + \|E_{\text{slice}}\|}$ | $\ge 70\%$ | Quantifies visual simplification relative to unpruned slice |
| **Contraction Reachability Invariant** | $\mathbb{I}(\forall a, b \in V', a \rightsquigarrow b \text{ in } \mathcal{G}_{\text{slice}} \iff a \rightsquigarrow b \text{ in } \mathcal{G}')$ | **100% (Guaranteed)** | Formal mathematical theorem proven in Theorem 2 |
| **Expansion Fidelity** | $\frac{\|\text{Restored Vertices \& Edges via Expand()}\|}{\|\text{Original Subpath Vertices \& Edges}\|}$ | **100% (Lossless)** | Guarantees bidirectional invertibility of macro-edges |
| **Telemetry Attack Path Recall** | $\frac{\|\text{Recoverable Ground-Truth ATT\&CK Steps in } \mathcal{G}\|}{\|\text{Total Ground-Truth ATT\&CK Steps}\|}$ | Empirical ($R_{\text{telemetry}}$) | Evaluates sensor completeness and ETW visibility gaps |
| **Pipeline Attack Path Recall** | $\frac{\|\text{Recoverable Ground-Truth Steps in } \mathcal{G}'\|}{\|\text{Recoverable Ground-Truth Steps in } \mathcal{G}\|}$ | **100% (Guaranteed)** | Proves slicing and contraction introduce zero evidence loss |
| **Evidence Retention Rate** | $\frac{\|\text{Retrievable Raw Event Payloads}\|}{\|\text{Total Ingested Events}\|}$ | **100%** | Full chain-of-custody preservation in SQLite ledger |
| **Graph Structural Complexity Ratio (SCR)**| $\frac{\|V'\| + \|E'\|}{\|V_{\text{slice}}\| + \|E_{\text{slice}}\|}$ | $\le 0.30$ | Primary topological simplification measure |
| **Topology Metrics (Secondary)** | $\frac{\text{Diameter}(\mathcal{G}')}{\text{Diameter}(\mathcal{G}_{\text{slice}})}, \quad \frac{\text{AvgDeg}(\mathcal{G}')}{\text{AvgDeg}(\mathcal{G}_{\text{slice}})}$ | Reported per scenario | Structural complexity indicators (reported separately) |
| **Execution Latency** | Clock time (Ingest + Slice + Contract) | $< 10\text{ sec}$ | Operational triage feasibility for 100k events |

---

## 9. Repository Architecture

```text
ProvGraph-DFIR/
├── README.md
├── pyproject.toml
├── configs/
│   ├── default_config.yaml
│   └── scenarios.yaml
├── data/
│   ├── raw_mordor/              # Pre-indexed Mordor JSON datasets
│   └── test_fixtures/           # Controlled synthetic DAG fixtures
├── src/
│   └── provgraph/
│       ├── __init__.py
│       ├── ingestion/
│       │   ├── mordor_loader.py # Ingests Mordor Sysmon JSON
│       │   └── evtx_loader.py   # Native EVTX parser
│       ├── ledger/
│       │   ├── schema.py        # SQLite schema initialization
│       │   └── database.py      # Event & Macro-edge CRUD & indexing
│       ├── graph/
│       │   ├── models.py        # EventNode, MacroEdge dataclasses
│       │   ├── causal_rules.py  # Explicit edge inference engine
│       │   └── dag_builder.py   # Strict-order DAG constructor
│       ├── slicing/
│       │   ├── deterministic.py # Bidirectional BFS traverser
│       │   └── poi_selector.py  # Selects PoI via composite key
│       ├── contraction/
│       │   ├── lossless.py      # Macro-edge contraction engine
│       │   ├── expansion.py     # Expand() inverse reconstruction API
│       │   └── entropy_eval.py  # Shannon entropy ablation calculator
│       ├── visualization/
│       │   ├── graph_export.py  # Exports to Cytoscape JSON
│       │   └── app.py           # Streamlit Interactive UI (Mid-Dec demo)
│       └── evaluation/
│           ├── ground_truth.py  # MITRE ATT&CK ground-truth verifier
│           └── benchmark.py     # Metrics calculator (Reduction, Time, SCR)
├── tests/
│   ├── test_ledger.py           # SQLite integrity & composite key tests
│   ├── test_dag_builder.py      # Monotonic order & Theorem 1 DAG tests
│   ├── test_slicing.py          # Bidirectional determinism & window tests
│   ├── test_contraction.py      # Reachability invariant tests
│   └── test_expansion.py        # Exact reversible expansion tests
└── experiments/
    ├── run_mordor_empire.py     # Mid-Dec demo scenario A
    ├── run_mordor_ransomware.py # Mid-Dec demo scenario B
    └── run_ablation_matrix.py   # Baseline comparison script
```

---

## 10. Kill Criteria and Technical Risk Controls

1. **The Shannon Entropy Failure Condition:**  
   * *Trigger:* If ablation experiments demonstrate that Shannon edge-type entropy assigns lower scores to malicious bursts (ransomware encryptions, exfiltration) than to benign `svchost.exe` churn in $>50\%$ of runs.  
   * *Action:* Formally reject Shannon entropy in the thesis results. Anchor the thesis contribution on proving *why* categorical entropy fails in DFIR and validate structural equivalence contraction as the superior paradigm.
2. **The Graph Memory Wall:**  
   * *Trigger:* If NetworkX in-memory graph allocation exceeds 8 GB on a 100,000-event dataset during slicing.  
   * *Action:* Push the slicing traversal into SQLite recursive Common Table Expressions (`WITH RECURSIVE`), instantiating NetworkX objects *only* for the extracted sliced subgraph.
3. **The Mid-December Demo Fallback:**  
   * *Trigger:* If the Streamlit visualizer experiences performance lags on large graphs before December 15.  
   * *Action:* Fall back to exporting pre-rendered, zoomable Cytoscape.js HTML files with an embedded SQLite JSON search table.

---

## 11. Immediate Action Plan (Starting Now)

| Step | Action Item | Target Completion | Verification Test |
| :---: | :--- | :--- | :--- |
| **1** | Initialize repository directory layout and virtual environment | Day 1 | `pytest` runs cleanly |
| **2** | Download Mordor Empire Stager dataset (`host_0_sysmon.json`) | Day 2 | JSON integrity validated |
| **3** | Implement `ledger/schema.py` with composite keys and `macro_edges` | Day 5 | SQLite schema handles missing process creates without crash |
| **4** | Build `graph/causal_rules.py` and `graph/dag_builder.py` | Day 9 | Zero directed cycles detected across all tests (Theorem 1 holds) |
| **5** | Implement `slicing/deterministic.py` (Bidirectional + PoI window) | Day 14 | Identical slice hashes across 10 repeated runs |
| **6** | Implement `contraction/lossless.py` and `contraction/expansion.py` | Day 21 | Transitive reachability holds 100% and `Expand()` matches original |
| **7** | Construct Streamlit visualizer with click-to-expand drilldown | Day 35 | Clickable macro-edge drilldown and expand/collapse working |
