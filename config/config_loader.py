"""Utilities for loading and validating AUVAP context rules."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List

__all__ = [
    "ConfigurationError",
    "load_context_rules",
    "validate_config",
    "get_ignore_rules",
    "get_priority_rules",
]


class ConfigurationError(Exception):
    """Raised when the supplied context configuration is invalid."""


_REQUIRED_TOP_LEVEL = {
    "company_name",
    "environment",
    "server_purpose",
    "exploitation_constraints",
    "ignore_rules",
    "priority_rules",
    "force_include",
    "safety_constraints",
}

_PRIORITY_VALUES = {"critical", "high", "medium", "low"}
_IGNORE_RULE_TYPES = {"port", "service", "cvss_threshold", "attack_vector", "plugin_id"}
_PRIORITY_RULE_TYPES = {"service", "port", "cvss_range", "attack_vector"}
_FORCE_INCLUDE_TYPES = {"plugin_id", "cve"}
_SPECIFICITY_ORDER = {
    "plugin_id": 0,
    "cve": 0,
    "port": 1,
    "service": 2,
    "cvss_threshold": 3,
    "cvss_range": 3,
    "attack_vector": 4,
}


def load_context_rules(file_path: str) -> Dict[str, Any]:
    """Load, parse, and validate the context rules JSON file."""

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    last_error: Exception | None = None
    for encoding in ("utf-8", "latin-1", "utf-8-sig"):
        try:
            with path.open("r", encoding=encoding, errors="strict") as handle:
                config = json.load(handle)
            break
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"Invalid JSON in configuration file: {exc}") from exc
    else:
        raise ConfigurationError(f"Unable to decode configuration file: {last_error}")

    try:
        validate_config(config)
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc

    return config


def validate_config(config: Dict[str, Any]) -> bool:
    """Validate schema and values of the context rules."""

    missing = _REQUIRED_TOP_LEVEL - config.keys()
    if missing:
        raise ValueError(f"Missing required configuration sections: {sorted(missing)}")

    _validate_exploitation_constraints(config["exploitation_constraints"])
    _validate_safety_constraints(config["safety_constraints"])
    _validate_ignore_rules(config.get("ignore_rules", []))
    _validate_priority_rules(config.get("priority_rules", []))
    _validate_force_include(config.get("force_include", []))

    return True


def get_ignore_rules(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return ignore rules sorted by specificity."""

    rules = list(config.get("ignore_rules", []))
    rules.sort(key=lambda rule: _SPECIFICITY_ORDER.get(rule.get("type"), 99))
    return rules


def get_priority_rules(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return priority rules sorted by specificity."""

    rules = list(config.get("priority_rules", []))
    rules.sort(key=lambda rule: _SPECIFICITY_ORDER.get(rule.get("type"), 99))
    return rules


def _validate_exploitation_constraints(section: Dict[str, Any]) -> None:
    required_fields = {"access_type", "description", "agent_capabilities", "agent_limitations"}
    missing = required_fields - section.keys()
    if missing:
        raise ValueError(f"Missing exploitation_constraints fields: {sorted(missing)}")

    if not isinstance(section.get("agent_capabilities"), list) or not isinstance(
        section.get("agent_limitations"), list
    ):
        raise ValueError("agent_capabilities and agent_limitations must be lists")


def _validate_safety_constraints(section: Dict[str, Any]) -> None:
    required_fields = {
        "max_exploits_per_run",
        "timeout_per_exploit",
        "allowed_ip_ranges",
        "forbidden_commands",
        "sandbox_required",
    }
    missing = required_fields - section.keys()
    if missing:
        raise ValueError(f"Missing safety_constraints fields: {sorted(missing)}")

    ip_ranges = section.get("allowed_ip_ranges", [])
    if not isinstance(ip_ranges, list):
        raise ValueError("allowed_ip_ranges must be a list")

    for cidr in ip_ranges:
        try:
            ipaddress.ip_network(cidr)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR notation in allowed_ip_ranges: {cidr}") from exc

    forbidden = section.get("forbidden_commands", [])
    if not isinstance(forbidden, list):
        raise ValueError("forbidden_commands must be a list")


def _validate_ignore_rules(rules: List[Dict[str, Any]]) -> None:
    for rule in rules:
        rule_type = rule.get("type")
        if rule_type not in _IGNORE_RULE_TYPES:
            raise ValueError(f"Unsupported ignore rule type: {rule_type}")
        if "value" not in rule:
            raise ValueError("Each ignore rule must include a value")


def _validate_priority_rules(rules: List[Dict[str, Any]]) -> None:
    for rule in rules:
        rule_type = rule.get("type")
        if rule_type not in _PRIORITY_RULE_TYPES:
            raise ValueError(f"Unsupported priority rule type: {rule_type}")
        priority = rule.get("priority")
        if priority not in _PRIORITY_VALUES:
            raise ValueError(f"Invalid priority value: {priority}")


def _validate_force_include(rules: List[Dict[str, Any]]) -> None:
    for rule in rules:
        rule_type = rule.get("type")
        if rule_type not in _FORCE_INCLUDE_TYPES:
            raise ValueError(f"Unsupported force_include type: {rule_type}")
        if "value" not in rule:
            raise ValueError("Each force_include rule must include a value")
