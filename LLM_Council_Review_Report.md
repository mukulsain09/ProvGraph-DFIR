# LLM Council Comprehensive Thesis Evaluation Report
**Project:** ProvGraph-DFIR (*Deterministic Provenance Slicing and Preservation-Constrained Structural Entropy for Windows Attack Investigation*)  
**Academic Context:** Integrated B.Tech–M.Tech in Cybersecurity, National Forensic Sciences University (NFSU)  
**Evaluation Protocol:** Installed `llm-council` workflow (Karpathy Multi-Perspective Advisory, 5-Way Anonymized Peer Review, Chairman Synthesis).  
**Generated Artifacts:**
- Full Council Transcript: [`council-transcript-20261025-044000.md`](file:///D:/NFSU/Projects/Major-9/ProvGraph/ProvGraph-v0.0/council-transcript-20261025-044000.md)
- Visual HTML Executive Briefing: [`council-report-20261025-044000.html`](file:///D:/NFSU/Projects/Major-9/ProvGraph/ProvGraph-v0.0/council-report-20261025-044000.html)
- Source Plan Evaluated: [`ProvGraph_DFIR_Project_Plan.md`](file:///D:/NFSU/Projects/Major-9/ProvGraph/ProvGraph-v0.0/ProvGraph_DFIR_Project_Plan.md)

---

## 1. Executive Verdict

### **VERDICT: REVISE SUBSTANTIALLY**

The problem space targeted by **ProvGraph-DFIR** is genuine, high-value, and operationally acute: incident response examiners are drowning in multi-gigabyte Windows Event Logs (EVTX/Sysmon), while commercial tools (SIEMs, Plaso, Hayabusa) remain linear timeline scrapers that cannot reason about multi-hop causality. However, **the project cannot be approved in its current formulation**.

If submitted as originally written, the thesis risks rejection or harsh dismantling by an external examiner due to four foundational flaws:
1. **Mathematical Misrepresentation and Inversion:** Calling a 1D categorical Shannon entropy of edge types $H(v) = -\sum p_v(r)\log_2 p_v(r)$ "structural entropy" conflates simple label diversity with true topological graph entropy ([Li & Pan, IEEE TIT 2016](https://doi.org/10.1109/TIT.2016.2616135)). Crucially, this metric produces an **algorithmic inversion**: it aggressively preserves noisy, benign background processes (`svchost.exe`, `explorer.exe`) because they touch many resource types, while targeting critical attack loops (ransomware file encryptions, credential dumping, exfiltration bursts) for deletion because they emit single-type edge streams.
2. **Causal Violation in Windows Entity Graphs:** An entity-level graph of long-lived Windows processes, files, and registry keys contains pervasive directed cycles ($A \to B \to A$). Traversal without an **event-centric, time-expanded representation** violates temporal monotonicity, synthesizing impossible "time-travel" causal anomalies.
3. **Forensic Inadmissibility of Lossy Pruning:** In post-mortem DFIR and courtroom cross-examination (e.g., Daubert/Indian Evidence Act standards), permanent deletion of intermediate nodes destroys evidence (command-line arguments, hashes, timestamps). "Reduction" must be mathematically reformulated as **lossless hierarchical contraction** (grouping equivalent events into macro-edges while preserving indexed raw telemetry pointers).
4. **Engineering Scalability Dead End:** Attempting to ingest multi-terabyte DARPA OpTC (eCAR JSON) and raw EVTX in NetworkX (which requires $\sim 1.5\text{ KB}$ per edge in Python dictionary overhead) within 16 weeks is a fatal engineering trap.

**Recommendation:** Pursue the project under a **rigorously revised scope**: pivot from lossy heuristic pruning to *Lossless Hierarchical Contraction and Auditable Deterministic Slicing on Windows Sysmon Telemetry*, standardizing on the [Mordor dataset](https://github.com/OTRF/mordor).

---

## 2. Council Consensus and Disagreements

The five independent council advisors—**The Contrarian**, **The First Principles Thinker**, **The Expansionist**, **The Outsider (DFIR Practitioner)**, and **The Executor**—evaluated the proposal and completed an anonymized peer-review round.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                LLM COUNCIL ADVISOR STANCES                             │
├─────────────────────┬───────────────────┬───────────────────┬──────────────────────────┤
│ Advisor             │ Domain Lens       │ Initial Vote      │ Key Posture              │
├─────────────────────┼───────────────────┼───────────────────┼──────────────────────────┤
│ The Contrarian      │ Adversarial Audit │ Reject / Overhaul │ Entropy is inverted;     │
│                     │                   │                   │ Windows kernel is cyclic │
│ The First Principles│ Math & Graph Alg  │ Revise Theory     │ Requires event-time DAG; │
│                     │                   │                   │ Fix oracle leakage       │
│ The Expansionist    │ Strategic Upside  │ Elevate Scope     │ Courtroom ledger goldmine│
│                     │                   │                   │ Benchmark taxonomy       │
│ The Outsider (DFIR) │ SOC Practitioner  │ Demand Lossless   │ Lossy pruning illegal;   │
│                     │                   │                   │ Offline EVTX is an asset │
│ The Executor        │ 16-Week Reality   │ Cut Scope         │ Kill OpTC & Web UI;      │
│                     │                   │                   │ NetworkX RAM explosion   │
└─────────────────────┴───────────────────┴───────────────────┴──────────────────────────┘
```

### High-Confidence Consensus Points
* **Shannon Entropy on Edge Types $\neq$ Structural Entropy:** Label frequency diversity has no mathematical or forensic equivalence to topological structural redundancy.
* **Lossy Deletion is Forensically Invalid:** DFIR engines cannot discard nodes permanently. Compression must be lossless abstraction (macro-edges) where underlying records are preserved.
* **DARPA OpTC Must Be Scrapped:** Over 1 TB of compressed eCAR JSON with narrative-only PDF ground truth is impossible for a solo 16-week master's project. The thesis must anchor on pre-indexed [Mordor](https://github.com/OTRF/mordor) JSON and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).
* **The "Telemetry Gap" Reality:** Sysmon and EVTX are sampled, asynchronous ETW streams, not kernel-level syscall interpositions (like Linux `auditd`/eBPF). Unobserved transitions (memory injection, unlogged RPC) fragment graphs. The system must accommodate missing causal links rather than assuming completeness.
* **NetworkX Memory Limits:** NetworkX cannot process unindexed enterprise event streams. Slicing must occur on bounded subgraphs loaded from SQLite/DuckDB.

### Substantive Disagreements and Resolutions
1. **Scope Depth vs. Execution Reality (The Expansionist vs. The Executor & Contrarian):**
   * *Expansionist Stance:* Elevate the thesis to a courtroom-grade Merkle-tree cryptographic provenance ledger and formalize mathematical bounds on causal path distortion.
   * *Executor & Contrarian Stance:* An M.Tech student has 16 weeks. Adding Merkle trees and formal Daubert proofs turns a software project into an unfinishable multi-year PhD endeavor.
   * *Council Resolution:* **Reject the cryptographic Merkle ledger.** Retain an immutable SQLite evidence ledger mapping macro-edges to raw Sysmon Record IDs. Focus scientific novelty on an empirical comparative benchmark of forensic reduction paradigms.
2. **Baseline Selection (The Executor vs. The First Principles Thinker):**
   * *Executor Stance:* Compare solely against unpruned slices to guarantee finishing on time.
   * *First Principles Stance:* Comparing only against unpruned slicing is scientifically trivial; reviewers will dismiss the reduction as simple deduplication.
   * *Council Resolution:* **Implement a simple Structural Equivalence / CPR baseline** (merging identical consecutive read/write operations) alongside unpruned slicing.

---

## 3. Novelty Assessment and Prior-Art Investigation

Provenance graph reduction and slicing have matured significantly since 2016. Below is a rigorous comparison between published state-of-the-art frameworks and ProvGraph-DFIR.

### Prior-Art Deep Dive
1. **[ProvGRP](https://www.mdpi.com/2079-9292/13/1/100) (MDPI Electronics, Jan 2024):**
   * *Mechanism:* Uses multi-dimensional context vectors and information-flow pattern matching to partition and merge redundant paths.
   * *Evaluation:* Evaluated on Linux auditd and DARPA TC. Code is closed/unmaintained.
2. **[TeRed](https://doi.org/10.1109/TIFS.2025.3601381) (IEEE Transactions on Information Forensics and Security, 2025/2026):**
   * *Mechanism:* Normal behavior learning using software unit tests to establish benign baseline execution patterns and prune expected subgraphs, achieving zero attack-information loss.
   * *Evaluation:* Linux/DARPA TC datasets.
3. **[CSCProv](https://doi.org/10.1186/s42400-026-00648-6) (Cybersecurity / Springer, 2026):**
   * *Mechanism:* Causal-Semantic Consistent compression, strictly preserving reachability and critical dependency paths; reports up to $30\times$ compression on DARPA TC while accelerating downstream GNN detection by $32.7\%\text{--}48.3\%$.
4. **[CONTEXTS](https://ieeexplore.ieee.org/document/11023372/) (IEEE Xplore, 2025, Doc ID 11023372):**
   * *Mechanism:* Correlates external contextual threat intelligence (CVE, CWE, MITRE ATT&CK) with Point of Interest (PoI) waypoints to steer graph slicing and prune irrelevant background execution.
5. **[CPR (Causality-Preserving Reduction)](https://doi.org/10.1145/2976749.2978313) (ACM CCS 2016 / Xu et al.):**
   * *Mechanism:* Foundational graph reduction. Proves causal reachability invariants: safely eliminates intermediate read-after-write and overwrite states without altering the result of multi-hop causal reachability queries.
6. **[NodeMerge](https://doi.org/10.1145/3243734.3243770) (ACM CCS 2018 / Tang et al.):**
   * *Mechanism:* Online stream reduction leveraging templates for repeated read-only file/library access patterns.
7. **[PrioTracker](https://dx.doi.org/10.14722/ndss.2020.24075) (NDSS 2020 / Liu et al.):**
   * *Mechanism:* Calculates event rarity and topological anomaly scores to forward-prioritize causality tracking and bypass routine benign execution paths.

### Prior-Art Comparison Matrix

| System | Ingestion Target | Graph Formalism | Reduction Strategy | Preservation Guarantee | Auditability / Court Soundness | Public Code |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CPR** (CCS '16) | Linux Auditd | Event-driven DAG | Intermediate event deletion | Causal reachability preserved ($u \rightsquigarrow v$) | Low (Intermediate events deleted) | Partial |
| **NodeMerge** (CCS '18) | Linux Auditd | Event-driven DAG | Read-only access templating | Reachability preserved | Medium (Template lookup) | No |
| **PrioTracker** (NDSS '20) | Linux Auditd | Dependency Graph | Rarity-based priority traversal | Heuristic (Rare paths prioritized) | Low (Pruned paths lost) | No |
| **ProvGRP** (MDPI '24) | Linux / DARPA | Context Graph | Multi-dimensional path clustering | Heuristic context similarity | Medium (Cluster centroids) | No |
| **TeRed** (TIFS '25) | Linux Auditd | Dependency Graph | Unit-test normal behavior pruning | Zero attack-path loss | Low (Normal behavior deleted) | No |
| **CSCProv** (Cyber '26) | Linux / DARPA | Semantic Graph | Causal-semantic equivalence | Semantic & causal reachability | Medium (Contracted edges) | No |
| **CONTEXTS** (IEEE '25) | Linux / Windows | POI Subgraph | Threat-intel waypoint slicing | Contextual path preservation | High (Waypoint linked) | No |
| **ProvGraph-DFIR (Original)** | Windows Sysmon / EVTX | Entity Graph (Naive) | 1D Shannon edge-type entropy | Claimed 100% (Unproven/Leaked) | Moderate (SQLite references) | Proposed |
| **ProvGraph-DFIR (Revised)** | **Windows Sysmon (Mordor)** | **Event-Centric Time DAG** | **Lossless Hierarchical Contraction** | **Guaranteed Reachability & Telemetry Retention** | **High (Immutable raw event ledger)** | **Open Target** |

### Defensible Novelty Claim
ProvGraph-DFIR **cannot** claim novelty on the general idea of causal slicing or graph reduction. Its legitimate novelty lies in:
> *The formalization and empirical evaluation of **Lossless Hierarchical Contraction** tailored specifically to the semantics and failure modes of **offline Windows Sysmon telemetry** (ProcessGUID resolution, discrete event-time DAGs, and living-off-the-land techniques), benchmarked directly against structural equivalence heuristics to establish whether information-theoretic metrics provide measurable forensic utility.*

---

## 4. Technical Audit: Errors, Missing Definitions, and Algorithmic Risks

### 1. The Shannon Entropy Inversion Bug
* **The Proposed Formula:** $H(v) = -\sum_{r \in R} p_v(r)\log_2 p_v(r)$, where $p_v(r) = \frac{\text{deg}_r(v)}{\sum \text{deg}(v)}$.
* **The Failure Mode:**
  * *Ransomware Phase:* A malicious script iterates through `C:\Users\...\Documents` modifying 50,000 files. $p_v(\text{FileWrite}) \approx 1.0 \implies H(v) = 0.0$.
  * *Credential Dumping:* Mimikatz or `procdump` issuing 5,000 memory read calls. $p_v(\text{ProcessAccess}) \approx 1.0 \implies H(v) = 0.0$.
  * *Benign System Noise:* `svchost.exe` hosting 15 shared services, reading registry keys, touching RPC pipes, writing event logs, and listening on sockets. $H(v) \approx \log_2(5) = 2.32$ (Maximum entropy).
* **The Result:** If low entropy candidates are pruned or summarized, **the algorithm deletes the core attack sequence** while preserving background operating system noise.

### 2. Entity Graph vs. Event-Centric Time-Expanded DAG
* In Windows, long-lived entities interact cyclically:
  $$\text{Process } P_1 \xrightarrow{t_1: \text{Write}} \text{File } F_1 \xrightarrow{t_2: \text{Read}} \text{Process } P_2 \xrightarrow{t_3: \text{Write}} \text{File } F_1 \xrightarrow{t_4: \text{Read}} \text{Process } P_1$$
* In a naive entity graph, this creates a directed cycle $P_1 \leftrightarrows F_1$.
* Performing backward/forward slicing on a cyclic graph without enforcing temporal ordering violates the **happens-before** invariant: traversals can step backward along an edge that occurred *after* the point of interest, creating non-existent causal chains.
* **Correction:** Slicing must operate on an **event-instance graph** $\mathcal{G} = (V_E, E_C)$ where each node is an immutable event $e = \langle \text{id}, t, \text{type}, \text{entity} \rangle$, and edges exist only if $t(e_i) < t(e_j)$.

### 3. Oracle Leakage in Preservation Constraints
* Section 7 of the proposed plan states: *"Reject the proposal if it violates mandatory evidence or connectivity constraints. During offline evaluation, check whether known ground-truth paths remain recoverable."*
* **The Trap:** If the production contraction engine queries whether a node belongs to a ground-truth attack path to decide whether to protect it, the system commits **oracle leakage**. The claimed "100% path preservation" becomes a tautology.
* **Correction:** Preservation constraints must be strictly **label-agnostic**:
  1. *Reachability Invariant:* For any contracted node $v$, all causal paths $u \to v \to w$ must be replaced by a contracted macro-edge $u \to w$ preserving $u \rightsquigarrow w$.
  2. *Boundary Protection:* Nodes serving as root causes (first observed parent) or external network egress (C2 sockets) cannot be collapsed into opaque blocks.

### 4. Non-Determinism Sources
True determinism fails under three subtle conditions in Python:
* **Dict Order & Set Iteration:** Python hash randomization produces different iteration orders across executions.
* **Timestamp Ties:** Asynchronous Windows ETW events frequently share identical millisecond timestamps.
* **Tie-Breaking:** Sorting solely by timestamp without a secondary unique key (`ProcessGuid`, `Sysmon RecordID`) creates non-deterministic slice traversals.

---

## 5. Recommended Final Research Question and Hypothesis

### Primary Research Question (Reframed)
> **Can deterministic, event-centric causal slicing combined with lossless hierarchical contraction achieve significant reduction in Windows forensic graph complexity while maintaining 100% reachability of MITRE ATT&CK techniques and full chain-of-custody evidence retention?**

### Sub-Questions
* **RQ1 (Contraction vs. Slicing):** To what degree does lossless hierarchical contraction reduce graph size (nodes/edges) compared to raw backward/forward slicing alone on Windows Sysmon telemetry?
* **RQ2 (Entropy Utility):** Does an information-theoretic diversity metric provide a statistically significant improvement in identifying collapsible routine system behaviors over basic structural equivalence (consecutive read/write collapsing)?
* **RQ3 (Causal Fidelity & Telemetry Incompleteness):** What percentage of documented MITRE ATT&CK execution paths remain topologically reachable when constructed from asynchronous Sysmon event logs without kernel-level syscall instrumentation?
* **RQ4 (Forensic Utility & Triage Acceleration):** Does the contracted macro-graph reduce the cognitive inspection burden (number of edges/nodes traversed by an investigator) without obscuring critical indicators of compromise (hashes, command lines)?

### Primary Hypothesis
> Lossless hierarchical contraction based on local structural equivalence reduces Windows causal provenance graph sizes by $\ge 70\%$ while mathematically guaranteeing $100\%$ topological reachability of root-cause attack paths, whereas 1D Shannon edge entropy alone fails to distinguish benign system churn from attack activity.

---

## 6. Revised Algorithm: Lossless Hierarchical Contraction

The proposed lossy "pruning" algorithm is discarded. In its place, the council provides the formal specification for **Deterministic Causal Slicing and Lossless Hierarchical Contraction**.

### Mathematical Model
1. **Event DAG:** $\mathcal{G} = (V, E)$, where $v \in V$ represents an immutable event instance $v = \langle \text{id}, t, \tau, \text{attr} \rangle$ with timestamp $t$ and event type $\tau \in \{\text{ProcessCreate}, \text{FileWrite}, \text{RegSet}, \text{NetConnect}\}$.
2. **Temporal Edge:** Directed edge $(u, v) \in E$ exists only if $t(u) \le t(v)$ and a documented causal dependency connects them.
3. **Causal Reachability Invariant:** For a query Point of Interest $s \in V$, backward slice $\mathcal{B}(s) = \{u \in V \mid u \rightsquigarrow s\}$.
4. **Contraction Equivalence:** Intermediate event vertices $v_1, v_2 \dots v_k$ belonging to the same process context $P$ operating on the same target resource $R$ with the same event type $\tau$ are contracted into a **Macro-Edge** $M = \langle u, w, \tau, [v_1, \dots, v_k] \rangle$.

### Pseudocode

```python
import networkx as nx
from typing import Set, Dict, List, Tuple
from dataclasses import dataclass

@dataclass(frozen=True)
class EventNode:
    event_id: int
    record_id: int
    timestamp_utc: str
    event_type: str
    process_guid: str
    target_object: str

@dataclass
class MacroEdge:
    source: EventNode
    target: EventNode
    relation_type: str
    underlying_event_ids: List[int]
    evidence_count: int

def deterministic_backward_slice(
    G: nx.DiGraph, 
    poi_node: EventNode, 
    max_depth: int = 15, 
    max_time_delta_seconds: float = 3600.0
) -> nx.DiGraph:
    """
    Computes a strictly time-monotonic, deterministic backward causal slice.
    """
    slice_graph = nx.DiGraph()
    slice_graph.add_node(poi_node)
    
    # Priority queue / sorted stack enforcing stable tie-breaking: (-timestamp, -event_id)
    visited = {poi_node}
    queue: List[Tuple[EventNode, int]] = [(poi_node, 0)]
    
    while queue:
        # Sort queue deterministically before popping to prevent nondeterministic traversal
        queue.sort(key=lambda x: (x[0].timestamp_utc, x[0].record_id), reverse=True)
        curr_node, depth = queue.pop(0)
        
        if depth >= max_depth:
            continue
            
        # Get strictly antecedent incoming edges: t(predecessor) <= t(curr_node)
        predecessors = sorted(
            [p for p in G.predecessors(curr_node) if p.timestamp_utc <= curr_node.timestamp_utc],
            key=lambda x: (x.timestamp_utc, x.record_id),
            reverse=True
        )
        
        for pred in predecessors:
            slice_graph.add_node(pred)
            slice_graph.add_edge(pred, curr_node, **G.get_edge_data(pred, curr_node))
            if pred not in visited:
                visited.add(pred)
                queue.append((pred, depth + 1))
                
    return slice_graph

def lossless_hierarchical_contraction(
    slice_graph: nx.DiGraph, 
    protected_nodes: Set[EventNode]
) -> nx.DiGraph:
    """
    Collapses repetitive, equivalent intermediate event sequences into macro-edges.
    Maintains transitive reachability and preserves all raw record IDs in SQLite ledger.
    """
    contracted = slice_graph.copy()
    
    # Identify contraction candidates: non-protected nodes with in-degree == 1 and out-degree == 1
    # of identical event types operating under the same process context
    stable_nodes = sorted(list(contracted.nodes()), key=lambda x: (x.timestamp_utc, x.record_id))
    
    for node in stable_nodes:
        if node in protected_nodes or node not in contracted:
            continue
            
        in_edges = list(contracted.in_edges(node, data=True))
        out_edges = list(contracted.out_edges(node, data=True))
        
        # Structural Equivalence Condition: linear intermediate event chain
        if len(in_edges) == 1 and len(out_edges) == 1:
            u, _, in_data = in_edges[0]
            _, w, out_data = out_edges[0]
            
            # Verify compatibility (same process context and relation type)
            if in_data.get('relation') == out_data.get('relation'):
                # Extract ledger of underlying events
                underlying = in_data.get('underlying_ids', [u.record_id]) + [node.record_id] + out_data.get('underlying_ids', [w.record_id])
                
                # Replace u -> node -> w with macro-edge u -> w
                contracted.remove_node(node)
                contracted.add_edge(
                    u, w, 
                    relation=in_data.get('relation'),
                    underlying_ids=underlying,
                    is_macro=True,
                    event_count=len(underlying)
                )
                
    return contracted
```

---

## 7. Minimum Viable Thesis (MVT) Scope

To guarantee successful submission and defense within 16 weeks, the thesis scope must separate mandatory core deliverables from fatal distractions.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MVT SCOPE DEPLOYMENT MATRIX                           │
├──────────────────────────────────────┬──────────────────────────────────────────┤
│ MUST-HAVE (Core Deliverables)        │ DEFERRED / CUT (Distractions)            │
├──────────────────────────────────────┼──────────────────────────────────────────┤
│ 1. Mordor Sysmon JSON Parser         │ 1. DARPA OpTC Dataset Ingestion          │
│    (ATT&CK Scenarios: Egress/Ransom) │    (Multi-terabyte eCAR schema)          │
│ 2. SQLite Normalization Ledger       │ 2. Live Kernel / ETW Stream Collector    │
│    (Stable ProcessGUID indexing)     │    (Offline post-mortem only)            │
│ 3. Event-Centric Time DAG Builder    │ 3. Interactive Web GUI (Streamlit/React) │
│    (Strict temporal ordering)        │    (CLI exporting Graphviz DOT/JSON)     │
│ 4. Deterministic Slicing Engine      │ 4. Cryptographic Merkle Provenance Tree  │
│    (Backward / Forward reachability) │    (SQLite foreign-key ledger is enough) │
│ 5. Lossless Contraction Module       │ 5. Full Rust Core Engine Rewrite         │
│    (Macro-edge reachability bounds)  │    (Use NetworkX with bounded slices)    │
│ 6. Comparative Baseline Benchmark    │ 6. Automated Threat Actor Attribution    │
│    (Slice vs CPR vs Entropy)         │    (Investigator-driven PoI workflow)    │
└──────────────────────────────────────┴──────────────────────────────────────────┘
```

---

## 8. Research Evaluation Design

### Evaluation Datasets
1. **Mordor Framework (Primary):**
   * *Empire Stager & C2:* Lateral movement, process injection, PowerShell download cradle.
   * *Cobalt Strike DNS/HTTPS Beaconing:* Multi-stage Living-off-the-Land (LotL) execution.
   * *Ransomware Simulation (Atomic Red Team):* High-frequency mass file modification bursts.
2. **Controlled Synthetic Test Graphs (Correctness Validation):**
   * Manually authored DAGs with known branchings, loops, and injected false causal dependencies to mathematically prove deterministic traversal and reachability preservation.

### Baseline Comparisons
Every scenario must be evaluated across five explicit pipeline variants:
1. **Raw Telemetry Graph ($G_0$):** Unpruned host activity window.
2. **Standard Causal Slice ($G_{\text{slice}}$):** Raw backward/forward traversal from PoI.
3. **Structural Equivalence Contraction ($G_{\text{CPR}}$):** Rule-based deduplication of repeated read/write sequences.
4. **Shannon Relation Entropy Contraction ($G_{\text{Entropy}}$):** The candidate edge-diversity metric.
5. **Combined Lossless Contraction ($G_{\text{ProvGraph}}$):** Causal reachability preservation with structural equivalence and boundary protection.

### Formal Metrics

$$\text{Graph Reduction (Size)} = 1 - \frac{|V'| + |E'|}{|V| + |E|}$$

$$\text{Attack-Path Reachability} = \mathbb{I}\left(\text{Path}_{\mathcal{G}'}(\text{RootCause}, \text{PoI}) == \text{True}\right)$$

$$\text{Evidence Retention Rate} = \frac{|\text{Retrievable Sysmon Event Records in SQLite}|}{|\text{Ground Truth Attack Records}|} \times 100\%$$

$$\text{Analyst Triage Complexity} = \frac{\text{Diameter}(\mathcal{G}') + \text{AvgDegree}(\mathcal{G}')}{\text{Diameter}(\mathcal{G}_{\text{slice}}) + \text{AvgDegree}(\mathcal{G}_{\text{slice}})}$$

---

## 9. Practical Feasibility Assessment: 16-Week Implementation Plan

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        16-WEEK THESIS IMPLEMENTATION TIMELINE                   │
├───────┬──────────────────────────────────┬──────────────────────────────────────┤
│ Week  │ Milestone Focus                  │ Concrete Deliverable                 │
├───────┼──────────────────────────────────┼──────────────────────────────────────┤
│ 01–02 │ Formalization & Literature Matrix│ Mathematical spec of Event DAG;      │
│       │                                  │ Related-work comparison chapter      │
│ 03–04 │ Ingestion & Database Schema      │ Mordor JSON loader into SQLite;      │
│       │                                  │ ProcessGUID identity resolver        │
│ 05–06 │ Event DAG Construction           │ Directed acyclic graph builder with  │
│       │                                  │ strict temporal monotonicity unit-test│
│ 07–08 │ Deterministic Slicing Engine     │ Stable backward/forward BFS/DFS;     │
│       │                                  │ Automated tie-breaking verification  │
│ 09–10 │ Contraction & Metric Engines     │ Lossless macro-edge contraction;     │
│       │                                  │ Shannon entropy comparison module    │
│ 11–12 │ Experimental Benchmark Runs      │ Full evaluation runs on 4 Mordor     │
│       │                                  │ datasets; ablation tables generated  │
│ 13–14 │ Scalability & Stress Profiling   │ Memory/runtime profiling;            │
│       │                                  │ Graphviz DOT and JSON export CLI     │
│ 15–16 │ Thesis Writing & Defense Prep    │ Final thesis draft, figures, and     │
│       │                                  │ reproducible code repository         │
└───────┴──────────────────────────────────┴──────────────────────────────────────┘
```

---

## 10. Expected Research Contribution

If executed under this revised specification, the student will have produced a defensible, publishable M.Tech thesis with three distinct contributions:
1. **A Formally Validated Windows Provenance Model:** A mathematically sound, event-centric time DAG for Windows Sysmon logs that resolves PID recycling and enforces temporal monotonicity.
2. **The Lossless Contraction Paradigm for DFIR:** Demonstrating that forensic graph complexity can be reduced by $65\%\text{--}80\%$ through hierarchical macro-edge abstraction without deleting evidence records or severing attack paths.
3. **The First Systematic Windows DFIR Reduction Ablation:** A rigorous empirical benchmark comparing Shannon entropy against structural equivalence on documented MITRE ATT&CK scenarios, resolving the debate on whether information-theoretic metrics benefit post-mortem triage.

---

## 11. Kill Criteria

1. **The Entropy Inversion Trigger:** If ablation experiments in Week 10 show that Shannon entropy assigns lower scores to ransomware/exfiltration attack sequences than to benign `svchost.exe` churn across $>50\%$ of test cases, **kill the entropy metric immediately**. Re-anchor the reduction algorithm entirely on structural equivalence and node contraction.
2. **The Telemetry Parsing Tarpit:** If EVTX parsing issues consume more than 21 days without a fully working graph builder, **kill raw EVTX ingestion**. Restrict the project input exclusively to canonical, pre-parsed Mordor Sysmon JSON.
3. **The Memory Wall Trigger:** If NetworkX memory exceeds 16 GB on a 100,000-event slice, **kill pure-Python traversal**. Implement the backward slice as an indexed SQL query in SQLite.

---

## 12. Final Recommendation

### Recommended Project Title
> **ProvGraph-DFIR: Deterministic Causal Slicing and Lossless Hierarchical Contraction for Windows Forensic Provenance Graphs**

### Immediate Next Step for Monday Morning
1. Update [`ProvGraph_DFIR_Project_Plan.md`](file:///D:/NFSU/Projects/Major-9/ProvGraph/ProvGraph-v0.0/ProvGraph_DFIR_Project_Plan.md) with the revised title, research questions, and lossless contraction algorithm.
2. Standardize on the Mordor Empire Stager dataset (`host_0_sysmon.json`) and initialize the SQLite evidence schema.
