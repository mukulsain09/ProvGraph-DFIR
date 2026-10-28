"""Unit tests for ProvGraph-DFIR YAML configuration engine."""

from __future__ import annotations

from pathlib import Path

from provgraph.config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_SCENARIOS_PATH,
    PoiSelectorConfig,
    ProvGraphConfig,
    load_config,
    load_scenarios,
    save_config,
)


def test_load_default_config() -> None:
    """Verifies that default_config.yaml loads with expected thesis defaults."""
    assert DEFAULT_CONFIG_PATH.exists()
    config = load_config(DEFAULT_CONFIG_PATH)

    assert config.slicing.max_depth == 15
    assert config.slicing.max_delta_sec == 3600.0
    assert config.slicing.direction == "both"
    assert config.contraction.entropy_threshold == 1.0
    assert config.contraction.enable_fanout_contraction is True
    assert config.contraction.min_fanout_size == 3


def test_load_config_fallback_on_missing_file(tmp_path: Path) -> None:
    """Verifies fallback to default config when path does not exist."""
    missing = tmp_path / "nonexistent.yaml"
    config = load_config(missing)

    assert isinstance(config, ProvGraphConfig)
    assert config.slicing.max_depth == 15


def test_save_and_reload_config(tmp_path: Path) -> None:
    """Verifies round-trip saving and reloading of configuration."""
    cfg = ProvGraphConfig()
    cfg.slicing.max_depth = 42
    cfg.contraction.entropy_threshold = 0.75

    out_file = tmp_path / "test_config.yaml"
    save_config(cfg, out_file)
    assert out_file.exists()

    reloaded = load_config(out_file)
    assert reloaded.slicing.max_depth == 42
    assert reloaded.contraction.entropy_threshold == 0.75


def test_load_scenarios_catalog() -> None:
    """Verifies that scenarios.yaml contains all thesis benchmark scenarios."""
    assert DEFAULT_SCENARIOS_PATH.exists()
    catalog = load_scenarios(DEFAULT_SCENARIOS_PATH)

    assert len(catalog.scenarios) >= 5
    ids = {s.id for s in catalog.scenarios}
    assert {
        "empire_vbs",
        "bitsadmin",
        "empire_mimikatz",
        "metasploit",
        "ransomware_burst",
    }.issubset(ids)

    # Test lookup
    vbs = catalog.get_scenario("empire_vbs")
    assert vbs is not None
    assert vbs.name == "Empire VBS Launcher"
    assert vbs.technique == "T1059.005"
    assert len(vbs.ground_truth_steps) == 3

    # Test step conversion
    gt_steps = vbs.to_ground_truth_steps()
    assert len(gt_steps) == 3
    assert gt_steps[0].step_id == "S1"
    assert gt_steps[0].technique_id == "T1059.005"


def test_poi_selector_to_predicate() -> None:
    """Verifies that PoiSelectorConfig generates valid filtering predicates."""
    selector = PoiSelectorConfig(event_id=1, target_substring="whoami")
    pred = selector.to_predicate()

    match_attrs = {
        "event_id": 1,
        "target_object": "C:\\Windows\\System32\\whoami.exe",
    }
    non_match_id = {
        "event_id": 11,
        "target_object": "C:\\Windows\\System32\\whoami.exe",
    }
    non_match_target = {
        "event_id": 1,
        "target_object": "C:\\Windows\\System32\\cmd.exe",
    }

    assert pred(match_attrs) is True
    assert pred(non_match_id) is False
    assert pred(non_match_target) is False
