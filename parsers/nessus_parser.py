"""Nessus XML parser that converts scan output into structured findings."""

from __future__ import annotations

import logging
import re
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("auvap.parsers.nessus")

_VERSION_HINTS = (
    r"(?P<service>\b[a-zA-Z0-9\-_/]+\b)[\s:/-]+(?P<version>[0-9]+(?:\.[0-9A-Za-z]+)+)",
    r"version\s*(?P<version>[0-9]+(?:\.[0-9A-Za-z]+)+)",
)
_SERVICE_ALIASES = {
    "www": "http",
    "httpd": "http",
    "domain": "dns",
    "ms-sql-s": "mssql",
    "postgresql": "postgres",
    "msrdp": "rdp",
    "netbios-ssn": "smb",
}


def parse_nessus_file(file_path: str) -> List[Dict[str, Any]]:
    """Parse a Nessus .nessus XML file into a list of vulnerability dicts."""

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Nessus file not found: {file_path}")

    content = _read_file_with_fallbacks(path)
    if content is None:
        return []

    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        logger.error("Malformed Nessus XML: %s", exc)
        return []

    findings: List[Dict[str, Any]] = []
    for report_host in root.findall(".//ReportHost"):
        host_properties = _extract_host_properties(report_host.find("HostProperties"))
        host_ip = report_host.get("name", host_properties.get("host-ip", ""))
        host_fqdn = host_properties.get("host-fqdn", "")
        operating_system = host_properties.get("operating-system", "")

        for report_item in report_host.findall("ReportItem"):
            finding = _parse_report_item(
                report_item,
                host_ip,
                host_fqdn,
                operating_system,
            )
            findings.append(finding)

    return findings


def normalize_service_name(service: Optional[str]) -> str:
    """Normalize Nessus service names to simplified lowercase aliases."""

    if not service:
        return "unknown"

    service_lower = service.lower()
    return _SERVICE_ALIASES.get(service_lower, service_lower)


def extract_version(plugin_output: Optional[str], service: str) -> Optional[str]:
    """Attempt to extract a service version string from plugin output."""

    if not plugin_output:
        return None

    if service:
        normalized_service = re.escape(service)
        direct_pattern = re.compile(
            rf"{normalized_service}[\s/:-]+(?P<version>[0-9]+(?:\.[0-9A-Za-z]+)+)",
            re.IGNORECASE,
        )
        match = direct_pattern.search(plugin_output)
        if match:
            return match.group("version")

    for pattern in _VERSION_HINTS:
        hint_match = re.search(pattern, plugin_output, flags=re.IGNORECASE)
        if hint_match and hint_match.groupdict().get("version"):
            return hint_match.group("version")
    return None


def _read_file_with_fallbacks(path: Path) -> Optional[str]:
    try:
        for encoding in ("utf-8", "latin-1"):
            try:
                return path.read_text(encoding=encoding)
            except UnicodeDecodeError:
                continue
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.error("Failed to read Nessus file %s: %s", path, exc)
        return None


def _extract_host_properties(element: Optional[ET.Element]) -> Dict[str, str]:
    properties: Dict[str, str] = {}
    if element is None:
        return properties
    for tag in element.findall("tag"):
        name = tag.get("name")
        if name:
            properties[name] = (tag.text or "").strip()
    return properties


def _parse_report_item(
    report_item: ET.Element,
    host_ip: str,
    host_fqdn: str,
    operating_system: str,
) -> Dict[str, Any]:
    service_raw = report_item.get("svc_name", "")
    service = normalize_service_name(service_raw)
    plugin_output = _text(report_item.find("plugin_output"))
    description = _text(report_item.find("description"))
    version = extract_version(plugin_output, service)

    risk_factor_text = _text(report_item.find("risk_factor"))

    finding = {
        "finding_id": str(uuid.uuid4()),
        "host": host_ip,
        "host_fqdn": host_fqdn,
        "operating_system": operating_system,
        "port": _safe_int(report_item.get("port")),
        "protocol": (report_item.get("protocol") or report_item.get("svc_type") or "tcp").lower(),
        "service": service,
        "version": version,
        "plugin_id": report_item.get("pluginID", ""),
        "plugin_name": report_item.get("pluginName", ""),
        "cvss": _float(report_item.find("cvss_base_score")),
        "cvss_vector": _text(report_item.find("cvss_vector")),
        "severity": risk_factor_text.capitalize() if risk_factor_text else "None",
        "cve_list": _collect_text(report_item, "cve"),
        "description": description,
        "solution": _text(report_item.find("solution")),
        "plugin_output": plugin_output,
        "references": _collect_text(report_item, "see_also"),
        "exploit_available": "exploit" in description.lower(),
    }
    return finding


def _text(element: Optional[ET.Element]) -> str:
    return (element.text or "").strip() if element is not None else ""


def _float(element: Optional[ET.Element]) -> float:
    try:
        return float(_text(element))
    except (TypeError, ValueError):
        return 0.0


def _collect_text(parent: ET.Element, tag_name: str) -> List[str]:
    values: List[str] = []
    for element in parent.findall(tag_name):
        text = _text(element)
        if text:
            values.append(text)
    return values


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
