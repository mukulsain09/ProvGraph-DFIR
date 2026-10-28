"""YAML Configuration Engine for ProvGraph-DFIR.

Loads and validates operational parameters, benchmark scenarios, and ground-truth definitions.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field

from provgraph.evaluation.ground_truth import GroundTruthStep

logger = logging.getLogger(__name__)

# Default search paths relative to project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "default_config.yaml"
DEFAULT_SCENARIOS_PATH = PROJECT_ROOT / "configs" / "scenarios.yaml"


class SlicingConfig(BaseModel):
    """Configuration parameters for deterministic causal graph slicing."""

    model_config = ConfigDict(extra="ignore")

    max_depth: int = Field(default=15, ge=1, description="Maximum traversal depth (hops)")
    max_delta_sec: float = Field(
        default=3600.0, ge=0.0, description="Max lookback/lookahead window in seconds"
    )
    direction: Literal["both", "backward", "forward"] = Field(
        default="both", description="Slicing direction"
    )


class ContractionConfig(BaseModel):
    """Configuration parameters for lossless hierarchical graph contraction."""

    model_config = ConfigDict(extra="ignore")

    entropy_threshold: float = Field(
        default=1.0, ge=0.0, description="Shannon entropy threshold H(v)"
    )
    enable_fanout_contraction: bool = Field(
        default=True, description="Collapse repetitive fan-out leaf actions"
    )
    min_fanout_size: int = Field(
        default=3, ge=2, description="Minimum leaf actions required to form a burst macro"
    )


class StorageConfig(BaseModel):
    """Configuration parameters for SQLite ledger persistence."""

    model_config = ConfigDict(extra="ignore")

    default_db_path: str = Field(
        default="data/ledger.db", description="Default SQLite evidence ledger path"
    )


class ProvGraphConfig(BaseModel):
    """Global configuration model for ProvGraph-DFIR pipeline."""

    model_config = ConfigDict(extra="ignore")

    slicing: SlicingConfig = Field(default_factory=SlicingConfig)
    contraction: ContractionConfig = Field(default_factory=ContractionConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)


class PoiSelectorConfig(BaseModel):
    """Declarative selector for locating a Point of Interest in the event graph."""

    model_config = ConfigDict(extra="ignore")

    event_id: int | None = None
    target_substring: str | None = None
    process_image: str | None = None
    process_guid: str | None = None

    def to_predicate(self) -> Callable[[dict[str, Any]], bool]:
        """Constructs a deterministic filter predicate for find_poi_by_predicate."""

        def _predicate(attrs: dict[str, Any]) -> bool:
            if self.event_id is not None and attrs.get("event_id") != self.event_id:
                return False
            if self.process_guid is not None and attrs.get("process_guid") != self.process_guid:
                return False
            if self.target_substring is not None:
                target = str(attrs.get("target_object") or "").lower()
                payload = str(attrs.get("raw_payload") or "").lower()
                substr = self.target_substring.lower()
                if substr not in target and substr not in payload:
                    return False
            if self.process_image is not None:
                payload = str(attrs.get("raw_payload") or "").lower()
                target = str(attrs.get("target_object") or "").lower()
                proc = self.process_image.lower()
                if proc not in payload and proc not in target:
                    return False
            return True

        return _predicate


class GroundTruthStepConfig(BaseModel):
    """Declarative definition of a MITRE ATT&CK ground-truth technique milestone."""

    model_config = ConfigDict(extra="ignore")

    step_id: str
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    expected_event_id: int | None = None
    expected_target_substring: str | None = None

    def to_ground_truth_step(self) -> GroundTruthStep:
        """Converts to evaluation model GroundTruthStep."""
        return GroundTruthStep(
            step_id=self.step_id,
            technique_id=self.technique_id,
            technique_name=self.technique_name,
            tactic=self.tactic,
            description=self.description,
            expected_event_id=self.expected_event_id,
            expected_target_substring=self.expected_target_substring,
        )


class ScenarioConfig(BaseModel):
    """Specification of an adversary evaluation scenario."""

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    file: str
    technique: str
    description: str = ""
    poi_selector: PoiSelectorConfig
    ground_truth_steps: list[GroundTruthStepConfig] = Field(default_factory=list)

    def to_ground_truth_steps(self) -> list[GroundTruthStep]:
        """Converts all configured steps into GroundTruthStep objects."""
        return [step.to_ground_truth_step() for step in self.ground_truth_steps]


class ScenariosCatalog(BaseModel):
    """Catalog of all benchmark evaluation scenarios."""

    model_config = ConfigDict(extra="ignore")

    scenarios: list[ScenarioConfig] = Field(default_factory=list)

    def get_scenario(self, identifier: str) -> ScenarioConfig | None:
        """Finds scenario by id or exact name (case-insensitive)."""
        target = identifier.lower().strip()
        for s in self.scenarios:
            if s.id.lower() == target or s.name.lower() == target:
                return s
        return None


def get_default_config_path() -> Path:
    """Returns the default configuration file path."""
    return DEFAULT_CONFIG_PATH


def get_default_scenarios_path() -> Path:
    """Returns the default scenarios file path."""
    return DEFAULT_SCENARIOS_PATH


def load_config(path: Path | str | None = None) -> ProvGraphConfig:
    """Loads and validates pipeline configuration from a YAML file.

    Falls back to default parameters if file is not found.
    """
    cfg_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not cfg_path.exists():
        logger.warning("Config file not found at %s. Using default settings.", cfg_path)
        return ProvGraphConfig()

    try:
        with open(cfg_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return ProvGraphConfig.model_validate(data)
    except Exception as e:
        logger.error("Failed to parse config at %s: %s. Using defaults.", cfg_path, e)
        return ProvGraphConfig()


def save_config(config: ProvGraphConfig, path: Path | str) -> None:
    """Saves a ProvGraphConfig instance to YAML."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config.model_dump(), f, default_flow_style=False, sort_keys=False)


def load_scenarios(path: Path | str | None = None) -> ScenariosCatalog:
    """Loads and validates the scenario benchmark catalog from YAML."""
    sc_path = Path(path) if path is not None else DEFAULT_SCENARIOS_PATH
    if not sc_path.exists():
        logger.warning("Scenarios file not found at %s. Returning empty catalog.", sc_path)
        return ScenariosCatalog()

    try:
        with open(sc_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return ScenariosCatalog.model_validate(data)
    except Exception as e:
        logger.error("Failed to parse scenarios file at %s: %s", sc_path, e)
        return ScenariosCatalog()
