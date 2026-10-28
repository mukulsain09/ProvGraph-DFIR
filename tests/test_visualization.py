"""Unit tests for Cytoscape.js visualization and graph export."""

from __future__ import annotations

import networkx as nx

from provgraph.visualization.graph_export import (
    EVENT_COLOR_MAP,
    export_cytoscape_elements,
    generate_cytoscape_html,
)


def test_export_cytoscape_elements() -> None:
    g = nx.DiGraph()
    poi = "h:c:100"
    g.add_node(
        poi,
        event_key=poi,
        event_type="ProcessCreate",
        event_id=1,
        target_object="C:\\whoami.exe",
        record_id=100,
    )
    mid = "h:c:101"
    g.add_node(
        mid,
        event_key=mid,
        event_type="NetworkConnect",
        event_id=3,
        target_object="1.1.1.1:443",
        record_id=101,
    )
    g.add_edge(poi, mid, relation_type="OPENS_SOCKET", is_macro=False)

    elements = export_cytoscape_elements(g, poi_key=poi)
    nodes = elements["nodes"]
    edges = elements["edges"]

    assert len(nodes) == 2
    assert len(edges) == 1

    poi_elem = next(n for n in nodes if n["data"]["id"] == poi)
    assert poi_elem["data"]["is_poi"] is True
    assert poi_elem["classes"] == "poi"
    assert poi_elem["data"]["color"] == "#FDD835"

    mid_elem = next(n for n in nodes if n["data"]["id"] == mid)
    assert mid_elem["data"]["is_poi"] is False
    assert mid_elem["data"]["color"] == EVENT_COLOR_MAP["NetworkConnect"]

    edge_elem = edges[0]
    assert edge_elem["data"]["relation_type"] == "OPENS_SOCKET"
    assert edge_elem["data"]["is_macro"] is False


def test_generate_cytoscape_html() -> None:
    g = nx.DiGraph()
    g.add_node("n1", event_type="ProcessCreate", record_id=1)
    elements = export_cytoscape_elements(g, poi_key="n1")

    html = generate_cytoscape_html(elements, poi_key="n1", height=500)
    assert "<!DOCTYPE html>" in html
    assert "cytoscape.min.js" in html
    assert "cytoscape-dagre" in html
    assert "poiId = \"n1\"" in html
    assert "details-panel" in html
