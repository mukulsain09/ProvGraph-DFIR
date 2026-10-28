"""Exports NetworkX provenance graphs to Cytoscape.js format with forensic styling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx

EVENT_COLOR_MAP: dict[str, str] = {
    "ProcessCreate": "#1E88E5",  # Blue
    "NetworkConnect": "#43A047",  # Green
    "ImageLoaded": "#00ACC1",  # Cyan
    "CreateRemoteThread": "#E53935",  # Crimson Red (Injection)
    "ProcessAccess": "#D81B60",  # Magenta / Forensic Alert (LSASS Access)
    "FileCreate": "#FB8C00",  # Amber / Orange
    "RegistryObject": "#8E24AA",  # Purple
    "RegistryValueSet": "#AB47BC",  # Violet
    "ProcessTerminate": "#78909C",  # Muted Grey
    "Default": "#546E7A",
}


def export_cytoscape_elements(
    graph: nx.DiGraph, poi_key: str | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Converts a NetworkX DiGraph into Cytoscape.js elements with visual styling.

    Args:
        graph: The causal provenance graph (slice or contracted).
        poi_key: The Point of Interest key for visual emphasis.

    Returns:
        Dictionary with 'nodes' and 'edges' lists formatted for Cytoscape.js.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for node_key, attrs in graph.nodes(data=True):
        event_type = attrs.get("event_type", "Unknown")
        target_obj = attrs.get("target_object") or ""
        short_target = Path(target_obj).name if target_obj else ""
        label = f"{event_type}\n{short_target}" if short_target else event_type

        is_poi = node_key == poi_key
        if is_poi:
            node_class = "poi"
        elif attrs.get("is_macro_cluster"):
            node_class = "macro_cluster"
        else:
            node_class = event_type.lower()
        if is_poi:
            color = "#FDD835"
        elif attrs.get("is_macro_cluster"):
            color = "#8E24AA"
        else:
            color = EVENT_COLOR_MAP.get(event_type, EVENT_COLOR_MAP["Default"])

        nodes.append(
            {
                "data": {
                    "id": node_key,
                    "label": label,
                    "event_key": node_key,
                    "event_type": event_type,
                    "event_id": attrs.get("event_id"),
                    "host_name": attrs.get("host_name"),
                    "channel": attrs.get("channel"),
                    "record_id": attrs.get("record_id"),
                    "timestamp_utc": attrs.get("timestamp_utc"),
                    "timestamp_epoch": attrs.get("timestamp_epoch"),
                    "process_guid": attrs.get("process_guid"),
                    "parent_process_guid": attrs.get("parent_process_guid"),
                    "target_object": target_obj,
                    "hashes": attrs.get("hashes"),
                    "color": color,
                    "is_poi": is_poi,
                },
                "classes": node_class,
            }
        )

    for i, (u, v, data) in enumerate(graph.edges(data=True)):
        edge_id = f"e_{i}_{u}_{v}"
        is_macro = bool(data.get("is_macro", False))
        relation = data.get("relation_type", "CAUSAL")
        event_count = data.get("event_count", 1)

        if is_macro:
            label = f"{relation} [x{event_count}]"
            edge_class = "macro_edge"
            color = "#AB47BC"
            width = 4
        else:
            label = relation
            edge_class = "standard_edge"
            color = "#78909C"
            width = 2

        edges.append(
            {
                "data": {
                    "id": edge_id,
                    "source": u,
                    "target": v,
                    "label": label,
                    "relation_type": relation,
                    "is_macro": is_macro,
                    "macro_edge_id": data.get("macro_edge_id", ""),
                    "event_count": event_count,
                    "start_time_epoch": data.get("start_time_epoch"),
                    "end_time_epoch": data.get("end_time_epoch"),
                    "ordered_event_keys": data.get("ordered_event_keys", []),
                    "color": color,
                    "width": width,
                },
                "classes": edge_class,
            }
        )

    return {"nodes": nodes, "edges": edges}


def generate_cytoscape_html(
    elements: dict[str, list[dict[str, Any]]],
    poi_key: str | None = None,
    height: int = 680,
) -> str:
    """Generates a self-contained, interactive Cytoscape.js HTML visualization."""
    elements_json = json.dumps(elements)
    poi_id = poi_key or ""

    html_template = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>
  <style>
    body {{
      margin: 0;
      padding: 0;
      background-color: #0d1117;
      color: #c9d1d9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      overflow: hidden;
    }}
    #cy {{
      width: 100vw;
      height: {height}px;
      display: block;
      background: radial-gradient(#161b22 15%, transparent 16%) 0 0,
                  radial-gradient(#161b22 15%, transparent 16%) 8px 8px;
      background-size: 16px 16px;
      background-color: #0d1117;
    }}
    #toolbar {{
      position: absolute;
      top: 10px;
      left: 10px;
      z-index: 100;
      display: flex;
      gap: 8px;
    }}
    .btn {{
      background: #21262d;
      color: #58a6ff;
      border: 1px solid #30363d;
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 600;
    }}
    .btn:hover {{
      background: #30363d;
      color: #79c0ff;
    }}
    #details-panel {{
      position: absolute;
      bottom: 10px;
      right: 10px;
      width: 380px;
      max-height: 280px;
      overflow-y: auto;
      background: rgba(22, 27, 34, 0.95);
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 12px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      font-size: 12px;
      display: none;
      z-index: 100;
    }}
    #details-panel h4 {{
      margin: 0 0 8px 0;
      color: #58a6ff;
      font-size: 14px;
    }}
    .prop-row {{
      display: flex;
      margin-bottom: 4px;
    }}
    .prop-label {{
      font-weight: 600;
      width: 110px;
      color: #8b949e;
      flex-shrink: 0;
    }}
    .prop-val {{
      color: #f0f6fc;
      word-break: break-all;
    }}
  </style>
</head>
<body>
  <div id="toolbar">
    <button class="btn" onclick="cy.fit(null, 50)">Fit Graph</button>
    <button class="btn" onclick="centerPoI()">Focus PoI</button>
    <button class="btn" onclick="runLayout('dagre')">Hierarchical Layout</button>
    <button class="btn" onclick="runLayout('breadthfirst')">Breadth-First</button>
  </div>

  <div id="cy"></div>

  <div id="details-panel">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h4 id="panel-title">Forensic Element</h4>
      <span style="cursor:pointer; color:#8b949e;" onclick="hidePanel()">✕</span>
    </div>
    <div id="panel-content"></div>
  </div>

  <script>
    var elements = {elements_json};
    var poiId = "{poi_id}";

    var cy = cytoscape({{
      container: document.getElementById('cy'),
      elements: elements,
      style: [
        {{
          selector: 'node',
          style: {{
            'background-color': 'data(color)',
            'label': 'data(label)',
            'color': '#f0f6fc',
            'font-size': '11px',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'width': 65,
            'height': 65,
            'border-width': 2,
            'border-color': '#30363d',
            'text-outline-color': '#0d1117',
            'text-outline-width': 2
          }}
        }},
        {{
          selector: '.poi',
          style: {{
            'shape': 'diamond',
            'width': 85,
            'height': 85,
            'border-width': 4,
            'border-color': '#d81b60',
            'font-weight': 'bold',
            'font-size': '13px'
          }}
        }},
        {{
          selector: 'edge',
          style: {{
            'width': 'data(width)',
            'line-color': 'data(color)',
            'target-arrow-color': 'data(color)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '10px',
            'color': '#8b949e',
            'text-rotation': 'autorotate',
            'text-background-color': '#0d1117',
            'text-background-opacity': 0.8,
            'text-background-padding': 2
          }}
        }},
        {{
          selector: '.macro_edge',
          style: {{
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
            'font-weight': 'bold',
            'color': '#d2a8ff'
          }}
        }},
        {{
          selector: ':selected',
          style: {{
            'border-color': '#58a6ff',
            'border-width': 4,
            'line-color': '#58a6ff',
            'target-arrow-color': '#58a6ff'
          }}
        }}
      ],
      layout: {{
        name: 'dagre',
        rankDir: 'LR',
        nodeSep: 60,
        rankSep: 80,
        animate: true,
        animationDuration: 500
      }}
    }});

    function runLayout(layoutName) {{
      cy.layout({{
        name: layoutName,
        rankDir: 'LR',
        animate: true,
        animationDuration: 500
      }}).run();
    }}

    function centerPoI() {{
      if (poiId) {{
        var node = cy.getElementById(poiId);
        if (node.length > 0) {{
          cy.animate({{
            center: {{ eles: node }},
            zoom: 1.5,
            duration: 600
          }});
          node.select();
          showNodeDetails(node.data());
        }}
      }}
    }}

    function hidePanel() {{
      document.getElementById('details-panel').style.display = 'none';
    }}

    function showNodeDetails(data) {{
      var panel = document.getElementById('details-panel');
      var title = document.getElementById('panel-title');
      var content = document.getElementById('panel-content');

      title.innerText = (data.is_poi ? "⭐ [Point of Interest] " : "") + data.event_type;
      var rows = [
        ["Record ID", data.record_id],
        ["UTC Timestamp", data.timestamp_utc],
        ["Host", data.host_name],
        ["Process GUID", data.process_guid || "N/A"],
        ["Target / Object", data.target_object || "N/A"],
        ["Hashes", data.hashes || "N/A"]
      ];

      var html = "";
      rows.forEach(function(r) {{
        html += '<div class="prop-row">' +
          '<div class="prop-label">' + r[0] + ':</div>' +
          '<div class="prop-val">' + (r[1] || "-") + '</div></div>';
      }});
      content.innerHTML = html;
      panel.style.display = 'block';
    }}

    function showEdgeDetails(data) {{
      var panel = document.getElementById('details-panel');
      var title = document.getElementById('panel-title');
      var content = document.getElementById('panel-content');

      title.innerText = data.is_macro ? "🗂️ Contracted Macro-Edge" : "➡️ Causal Edge";
      var rows = [
        ["Relation", data.relation_type],
        ["Is Macro?", data.is_macro ? "Yes (" + data.event_count + " events)" : "No"],
        ["Macro ID", data.macro_edge_id || "None"],
        ["Source Key", data.source],
        ["Target Key", data.target]
      ];

      if (data.is_macro && data.ordered_event_keys) {{
        rows.push(["Collapsed Events", data.ordered_event_keys.length + " sequential records"]);
      }}

      var html = "";
      rows.forEach(function(r) {{
        html += '<div class="prop-row">' +
          '<div class="prop-label">' + r[0] + ':</div>' +
          '<div class="prop-val">' + (r[1] || "-") + '</div></div>';
      }});
      content.innerHTML = html;
      panel.style.display = 'block';
    }}

    cy.on('tap', 'node', function(evt) {{
      showNodeDetails(evt.target.data());
    }});

    cy.on('tap', 'edge', function(evt) {{
      showEdgeDetails(evt.target.data());
    }});

    cy.on('tap', function(evt) {{
      if (evt.target === cy) {{
        hidePanel();
      }}
    }});

    // Center on PoI on initial load
    setTimeout(function() {{
      centerPoI();
    }}, 400);
  </script>
</body>
</html>
"""
    return html_template


def export_interactive_html(
    graph: nx.DiGraph,
    output_path: Path | str,
    poi_key: str | None = None,
    title: str = "ProvGraph-DFIR Provenance Visualization",
) -> Path:
    """Exports a NetworkX provenance graph to a self-contained interactive Cytoscape.js HTML file.

    Args:
        graph: Sliced or contracted NetworkX DiGraph.
        output_path: Target HTML file path.
        poi_key: Point of Interest event key for centering and diamond highlight.
        title: Title of the visualization.

    Returns:
        Path to the generated HTML file.
    """
    elements = export_cytoscape_elements(graph, poi_key=poi_key)
    html_content = generate_cytoscape_html(elements, poi_key=poi_key)
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html_content, encoding="utf-8")
    return p
