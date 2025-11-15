"""Comprehensive report generation for AUVAP runs."""

from __future__ import annotations

import importlib
import importlib.util
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Tuple

_jinja_spec = importlib.util.find_spec("jinja2")
if _jinja_spec:
    jinja2 = importlib.import_module("jinja2")
    Environment = getattr(jinja2, "Environment")
    FileSystemLoader = getattr(jinja2, "FileSystemLoader")
    select_autoescape = getattr(jinja2, "select_autoescape")
else:  # pragma: no cover
    Environment = None
    FileSystemLoader = None
    select_autoescape = None


def generate_report(data: Dict[str, Any], output_format: str = "json", output_path: str | None = None) -> Dict[str, Any]:
    """Generate an AUVAP report in JSON, HTML, or Markdown format."""

    summary, statistics = _summarize(data)
    content = {
        "summary": summary,
        "statistics": statistics,
        "details": data,
    }

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = Path(output_path or f"report_{timestamp}.{_extension(output_format)}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        output_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
    elif output_format == "html":
        _render_template("report.html.j2", content, str(output_path))
    elif output_format == "markdown":
        _render_template("report.md.j2", content, str(output_path))
    else:
        raise ValueError(f"Unsupported report format: {output_format}")

    return {
        "output_file": str(output_path),
        "summary": summary,
        "statistics": statistics,
    }


def _summarize(data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    classified = data.get("classified_vulnerabilities", {})
    scripts = data.get("vulnerabilities_with_scripts", [])
    executions = data.get("execution_results", [])

    severity_counts = Counter(vuln.get("priority", "unknown") for vuln in scripts)
    attack_vector_counts = Counter(vuln.get("attack_vector", "Unknown") for vuln in scripts)
    service_counts = Counter(_extract_service_name(vuln) for vuln in scripts)

    successful_exploits = sum(1 for result in executions if result.get("success"))
    failed_exploits = len(executions) - successful_exploits

    summary = {
        "scan_timestamp": data.get("scan_metadata", {}).get("timestamp"),
        "total_findings": data.get("total_findings", 0),
        "remote_exploitable": classified.get("remote_exploitable_count", 0),
        "scripts_generated": sum(1 for vuln in scripts if vuln.get("script_generation", {}).get("status") == "generated"),
        "scripts_executed": len(executions),
        "successful_exploits": successful_exploits,
        "failed_exploits": failed_exploits,
        "critical_actions": [v.get("vuln_id") for v in scripts if v.get("priority") == "critical"],
    }

    statistics = {
        "severity_breakdown": dict(severity_counts),
        "attack_vectors": dict(attack_vector_counts),
        "services": dict(service_counts),
        "execution_status": {
            "successful": successful_exploits,
            "failed": failed_exploits,
            "not_attempted": classified.get("remote_exploitable_count", 0) - len(executions),
        },
        "rag_memory": data.get("rag_statistics", {}),
    }

    return summary, statistics


def _render_template(template_name: str, context: Dict[str, Any], output_path: str) -> None:
    if Environment is None or FileSystemLoader is None or select_autoescape is None:
        raise RuntimeError("Jinja2 is required for HTML/Markdown report generation")
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)
    Path(output_path).write_text(template.render(**context), encoding="utf-8")


def _extension(format_name: str) -> str:
    return {
        "json": "json",
        "html": "html",
        "markdown": "md",
    }[format_name]


def _extract_service_name(vuln: Dict[str, Any]) -> str:
    return (
        vuln.get("service")
        or (vuln.get("finding") or {}).get("service")
        or "unknown"
    )
