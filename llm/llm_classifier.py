"""LLM-powered vulnerability classification and prioritization."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any, Dict, List

from .openrouter_client import APIError, JSONParseError, OpenRouterClient

logger = logging.getLogger("auvap.llm.classifier")

_CLASSIFICATION_MAX_TOKENS = 1800
_PRIORITY_LEVELS = {"critical", "high", "medium", "low"}


def classify_and_prioritize_vulnerabilities(
    findings: List[Dict[str, Any]],
    context_rules: Dict[str, Any],
    api_client: OpenRouterClient,
) -> Dict[str, Any]:
    """Use LLM #1 to classify, filter, and prioritize Nessus findings."""

    if not findings:
        return {
            "total_analyzed": 0,
            "remote_exploitable_count": 0,
            "filtered_out_count": 0,
            "filtered_reasons": {},
            "vulnerabilities": [],
        }

    prompt = build_classification_prompt(findings, context_rules)
    logger.debug("Classification prompt token estimate=%s", api_client.estimate_tokens(prompt))

    try:
        response = api_client.call_with_json_response(
            prompt=prompt,
            temperature=0.3,
            max_tokens=_CLASSIFICATION_MAX_TOKENS,
        )
        parsed = parse_classification_response(response)
        validate_classification(parsed, len(findings))
        return parsed
    except (JSONParseError, APIError) as exc:
        logger.warning("LLM classification unavailable (%s). Using heuristic fallback.", exc)
        return _fallback_classification(findings)


def build_classification_prompt(findings: List[Dict[str, Any]], context_rules: Dict[str, Any]) -> str:
    """Construct the comprehensive prompt for LLM #1."""

    context_section = _format_context(context_rules)
    findings_section = _format_findings(findings)

    instructions = """
TASK DESCRIPTION:
- Analyze every vulnerability provided below using the supplied organizational context.
- Classify each finding with attack_vector (Network/Adjacent/Local/Physical) and exploitability (High/Medium/Low).
- FILTER OUT items that require local or physical access. Only remote/adjacent items stay.
- PRIORITIZE remaining findings by scoring each 0-100 with weights:
  * CVSS score 40%
  * Exploitability level 30%
  * Service criticality 20%
  * Attack vector accessibility 10%
- ASSIGN sequential IDs in priority order (VULN-001, VULN-002, ...).
- Provide rationale explaining classification and prioritization decisions.

CLASSIFICATION CRITERIA:
- Attack Vector definitions:
  * Network: remotely exploitable over routed networks (KEEP).
  * Adjacent: requires same network segment (KEEP if remote agent can reach segment).
  * Local: needs pre-existing shell/session (FILTER OUT).
  * Physical: requires physical interaction (FILTER OUT).
- Remote Exploitable = True only for Network or Adjacent vectors.
- Exploitability level depends on complexity, public exploits, authentication requirements.

STRICT OUTPUT REQUIREMENTS:
- Reply with a single JSON object that matches the schema below.
- Use double quotes for every key and every string literal.
- Do not emit markdown fences, XML/HTML tags, comments, explanations, or any text outside the JSON object.
- Do not include trailing commas, NaN, Infinity, or other invalid JSON tokens.
- If uncertain about a value, choose the best deterministic value rather than adding prose.

OUTPUT SCHEMA (exact order is not important, but all fields are required):
{
    "total_analyzed": <int>,
    "remote_exploitable_count": <int>,
    "filtered_out_count": <int>,
    "filtered_reasons": {"Local access required": <int>, ...},
    "vulnerabilities": [
        {
            "vuln_id": "VULN-001",
            "priority": "critical|high|medium|low",
            "priority_score": <0-100>,
            "attack_vector": "Network|Adjacent",
            "remote_exploitable": true,
            "exploitability": "High|Medium|Low",
            "prerequisites": ["list"],
            "rationale": "detailed reasoning",
            "priority_reason": "why score assigned",
            "map_to_original_finding": <index from input list>,
            "finding": { ...original fields... }
        }
    ]
}
Ensure vulnerabilities array contains ONLY remote-exploitable findings sorted by priority_score descending.
""".strip()

    prompt = f"""
You are the classification brain of an automated penetration-testing system.
Analyze vulnerabilities with the following organizational context to decide what the remote-only exploitation agent should attempt.

{context_section}

{instructions}

FINDINGS LIST:
{findings_section}
""".strip()
    return prompt


def parse_classification_response(response: Any) -> Dict[str, Any]:
    """Normalize and validate the JSON payload returned by the LLM."""

    if isinstance(response, str):
        try:
            data = json.loads(response)
        except json.JSONDecodeError as exc:
            raise ValueError("LLM response was not valid JSON") from exc
    elif isinstance(response, dict):
        data = response
    else:
        raise TypeError("Classification response must be str or dict")

    vulnerabilities = data.get("vulnerabilities", [])
    vulnerabilities.sort(key=lambda item: item.get("priority_score", 0), reverse=True)
    data["vulnerabilities"] = vulnerabilities

    return data


def validate_classification(data: Dict[str, Any], original_count: int) -> bool:
    """Ensure the classification payload is internally consistent."""

    total = data.get("total_analyzed")
    remote_count = data.get("remote_exploitable_count")
    filtered_count = data.get("filtered_out_count")
    vulnerabilities = data.get("vulnerabilities", [])

    if total != original_count:
        raise ValueError("total_analyzed must match number of input findings")

    if remote_count != len(vulnerabilities):
        logger.warning(
            "remote_exploitable_count mismatch: declared=%s actual=%s. Auto-correcting.",
            remote_count,
            len(vulnerabilities),
        )
        data["remote_exploitable_count"] = len(vulnerabilities)
        remote_count = len(vulnerabilities)

    if filtered_count is None or remote_count is None:
        raise ValueError("Missing filtered or remote counts in classification data")

    if filtered_count + remote_count != total:
        logger.warning(
            "Count mismatch: filtered=%s remote=%s total=%s. Auto-correcting filtered.",
            filtered_count,
            remote_count,
            total,
        )
        data["filtered_out_count"] = total - remote_count
        filtered_count = data["filtered_out_count"]

    for index, vuln in enumerate(vulnerabilities, start=1):
        if not vuln.get("remote_exploitable"):
            raise ValueError(f"Non-remote vulnerability present: {vuln.get('vuln_id')}")
        vuln_id = vuln.get("vuln_id", "")
        expected = f"VULN-{index:03d}"
        if vuln_id != expected:
            raise ValueError("Invalid vulnerability ID sequence")

        score = vuln.get("priority_score")
        if not isinstance(score, (int, float)) or not 0 <= score <= 100:
            raise ValueError(f"Priority score out of bounds for {vuln_id}")

        priority = str(vuln.get("priority", "")).lower()
        if priority not in _PRIORITY_LEVELS:
            raise ValueError(f"Invalid priority level for {vuln_id}")

        mapping_index = vuln.get("map_to_original_finding")
        if not isinstance(mapping_index, int) or not 1 <= mapping_index <= original_count:
            logger.warning(
                "map_to_original_finding invalid for %s: %s (expected 1-%s). Skipping mapping check.",
                vuln_id,
                mapping_index,
                original_count,
            )

    return True


# Helpers -----------------------------------------------------------------------

def _format_context(context: Dict[str, Any]) -> str:
    company = context.get("company_name", "Unknown Org")
    environment = context.get("environment", "Unknown")
    purpose = context.get("server_purpose", "Not provided")
    constraints = context.get("exploitation_constraints", {})
    safety = context.get("safety_constraints", {})

    capabilities = ", ".join(constraints.get("agent_capabilities", [])) or "Not specified"
    limitations = ", ".join(constraints.get("agent_limitations", [])) or "Not specified"

    return (
        f"CONTEXT:\n"
        f"- Company: {company}\n"
        f"- Environment: {environment}\n"
        f"- Server purpose: {purpose}\n"
        f"- Agent capabilities: {capabilities}\n"
        f"- Agent limitations: {limitations}\n"
        f"- Safety: max exploits/run {safety.get('max_exploits_per_run', 'n/a')}, timeout per exploit {safety.get('timeout_per_exploit', 'n/a')} seconds."
    )


def _format_findings(findings: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for idx, finding in enumerate(findings, start=1):
        description = _truncate(finding.get("description", ""), 240)
        lines.append(
            f"[{idx}] host={finding.get('host')} port={finding.get('port')} service={finding.get('service')} "
            f"cvss={finding.get('cvss')} severity={finding.get('severity')} plugin={finding.get('plugin_name')}\n"
            f"     desc={description}"
        )
    return "\n".join(lines)


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else f"{text[:limit-3]}..."


def _fallback_classification(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic prioritization used when the LLM response cannot be parsed."""

    filtered_reasons: Dict[str, int] = defaultdict(int)
    prioritized: List[Dict[str, Any]] = []

    for index, finding in enumerate(findings, start=1):
        vector = (finding.get("cvss_vector") or "").upper()
        attack_vector = "Network"
        remote = True
        reason = "Local access required"
        if "AV:L" in vector or "AV:P" in vector:
            remote = False
        elif "AV:A" in vector:
            attack_vector = "Adjacent"
        if not remote:
            filtered_reasons[reason] += 1
            continue

        exploitability = _determine_exploitability(finding)
        score = _heuristic_score(finding, attack_vector, exploitability)
        priority = _score_to_priority(score)
        vuln_id = f"VULN-{len(prioritized) + 1:03d}"

        prioritized.append(
            {
                "vuln_id": vuln_id,
                "priority": priority,
                "priority_score": score,
                "attack_vector": attack_vector,
                "remote_exploitable": True,
                "exploitability": exploitability,
                "prerequisites": _build_prerequisites(finding),
                "rationale": _build_rationale(finding, attack_vector, exploitability),
                "priority_reason": _priority_reason(finding, score),
                "map_to_original_finding": index,
                "finding": finding,
            }
        )

    return {
        "total_analyzed": len(findings),
        "remote_exploitable_count": len(prioritized),
        "filtered_out_count": len(findings) - len(prioritized),
        "filtered_reasons": dict(filtered_reasons),
        "vulnerabilities": prioritized,
    }


def _determine_exploitability(finding: Dict[str, Any]) -> str:
    cvss = float(finding.get("cvss") or 0.0)
    description = (finding.get("description") or "").lower()
    plugin_output = (finding.get("plugin_output") or "").lower()
    if finding.get("exploit_available") or "unauthenticated" in description or "blank password" in plugin_output:
        return "High"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def _heuristic_score(finding: Dict[str, Any], attack_vector: str, exploitability: str) -> int:
    cvss = float(finding.get("cvss") or 0.0)
    cvss_component = min(100.0, max(0.0, cvss)) / 10 * 40
    exploitability_component = {"High": 30, "Medium": 20, "Low": 10}[exploitability]
    service_component = _service_criticality(finding.get("service")) * 20
    attack_component = 10 if attack_vector == "Network" else 7
    score = cvss_component + exploitability_component + service_component + attack_component
    return int(min(100, round(score)))


def _service_criticality(service: Any) -> float:
    critical = {"http", "https", "ssh", "smb", "rdp", "mysql", "postgres", "mssql"}
    important = {"ftp", "smtp", "imap", "pop3", "dns"}
    service_name = str(service or "").lower()
    if service_name in critical:
        return 1.0
    if service_name in important:
        return 0.6
    return 0.3 if service_name else 0.2


def _score_to_priority(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _build_prerequisites(finding: Dict[str, Any]) -> List[str]:
    host = finding.get("host") or "target"
    port = finding.get("port") or "?"
    service = finding.get("service") or "service"
    prerequisites = [f"Network access to {host}:{port}/{service}"]
    if "credential" in (finding.get("description") or "").lower():
        prerequisites.append("Valid credentials or credential wordlist")
    return prerequisites


def _build_rationale(finding: Dict[str, Any], attack_vector: str, exploitability: str) -> str:
    cvss = finding.get("cvss")
    service = finding.get("service")
    severity = finding.get("severity")
    return (
        f"CVSS {cvss} {severity} issue on {service} is {attack_vector.lower()} accessible "
        f"with {exploitability.lower()} exploitability per heuristic rules."
    )


def _priority_reason(finding: Dict[str, Any], score: int) -> str:
    service = finding.get("service")
    return f"Score {score} derived from CVSS, exploitability indicators, and {service} criticality."
