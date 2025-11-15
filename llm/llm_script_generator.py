"""LLM #2 exploit script generation with optional RAG context."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from .openrouter_client import OpenRouterClient

logger = logging.getLogger("auvap.llm.script_generator")

_SCRIPT_MAX_TOKENS = 2200
_SCRIPT_MAX_ATTEMPTS = 3
_DEFAULT_RAG_RESPONSE = {
    "successful_examples": [],
    "failed_examples": [],
    "lessons": [],
    "query": "",
}


def generate_exploit_scripts(
    vulnerabilities: List[Dict[str, Any]],
    context_rules: Dict[str, Any],
    rag_memory: Optional[Any],
    api_client: OpenRouterClient,
) -> List[Dict[str, Any]]:
    """Generate exploit scripts for each vulnerability using the LLM."""

    enriched: List[Dict[str, Any]] = []
    for vuln in vulnerabilities:
        rag_data = _fetch_rag_context(rag_memory, vuln)
        logger.debug(
            "Building script for %s | RAG summary: %s",
            vuln.get("vuln_id"),
            summarize_rag_experience(rag_data),
        )
        vuln.setdefault("script_generation", {})
        vuln["script_generation"]["rag_summary"] = summarize_rag_experience(rag_data)
        prompt = build_rag_enhanced_prompt(vuln, context_rules, rag_data)
        last_error: Optional[str] = None
        for attempt in range(1, _SCRIPT_MAX_ATTEMPTS + 1):
            try:
                response = api_client.call_with_json_response(
                    prompt=prompt,
                    temperature=0.7,
                    max_tokens=_SCRIPT_MAX_TOKENS,
                )
                parsed = parse_script_response(response)
                vuln["script_generation"].update(parsed)
                vuln["script_generation"]["status"] = "generated"
                break
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                logger.warning(
                    "LLM script generation attempt %s/%s failed for %s: %s",
                    attempt,
                    _SCRIPT_MAX_ATTEMPTS,
                    vuln.get("vuln_id"),
                    exc,
                )
        else:
            vuln.setdefault("script_generation", {})
            vuln["script_generation"].update(
                {
                    "status": "failed",
                    "error": last_error or "LLM failed to return valid JSON",
                }
            )

        enriched.append(vuln)

    return enriched


def build_rag_enhanced_prompt(
    vuln: Dict[str, Any],
    context_rules: Dict[str, Any],
    rag_experience: Dict[str, Any],
) -> str:
    """Construct the LLM prompt that blends vulnerability data with RAG context."""

    context_section = _format_context(context_rules)
    vuln_section = _format_vulnerability(vuln)
    rag_section = _format_rag_section(rag_experience)

    instructions = """
SCRIPT REQUIREMENTS:
- Output valid JSON with explicit fields listed below.
- Provide full Python 3 code as a string assigned to "exploit_script".
- Define exploit(target_ip: str, target_port: int) returning {"success": bool, "message": str, "evidence": str}.
- Include resource cleanup, exception handling, and 30s timeout protections (e.g., socket timeouts or Paramiko timeouts).
- Generate WEAPONIZED exploits that achieve real compromise: reverse shells, command execution, credential extraction, privilege escalation.
- For successful exploitation, return evidence of compromise (e.g., command output, shell banner, extracted credentials).
- Use appropriate payloads: reverse shells (netcat, Python socket), command injection, authentication bypass, file read/write.
- Avoid system-destructive operations (rm -rf /, mkfs, dd to critical devices, shutdown, reboot) but DO execute reconnaissance commands (whoami, id, uname, cat /etc/passwd, etc.).
- Focus exclusively on the provided host and port.
- Suggest libraries/approaches from successful past examples and avoid techniques noted as failures.
- Provide success indicators and execution notes to help the runner interpret outcomes.

OUTPUT JSON SCHEMA:
{
  "vuln_id": "VULN-###",
  "exploit_script": "<python code>",
  "exploit_type": "brute_force|rce|sqli|xss|default_creds|etc",
  "techniques_applied": ["paramiko", "requests", ...],
  "techniques_avoided": ["what failed before"],
  "improvements_over_past": "text",
  "success_indicators": ["string", ...],
  "execution_notes": "text"
}
Wrap the JSON output between <json> and </json> tags and include no other text.
""".strip()

    return f"""
You are LLM #2 inside an autonomous penetration-testing platform.
Generate a WEAPONIZED exploit script that achieves real system compromise using the latest intelligence.

{context_section}

TARGET VULNERABILITY:
{vuln_section}

LEARNING FROM MEMORY:
{rag_section}

{instructions}
""".strip()


def parse_script_response(response: Any) -> Dict[str, Any]:
    """Ensure the script generation payload matches expectations."""

    if isinstance(response, str):
        try:
            data = json.loads(response)
        except json.JSONDecodeError as exc:
            raise ValueError("LLM script response not valid JSON") from exc
    elif isinstance(response, dict):
        data = response
    else:
        raise TypeError("Script response must be str or dict")

    required_fields = {
        "vuln_id",
        "exploit_script",
        "exploit_type",
        "techniques_applied",
        "techniques_avoided",
        "improvements_over_past",
        "success_indicators",
        "execution_notes",
    }
    missing = required_fields - data.keys()
    if missing:
        raise ValueError(f"Script response missing fields: {sorted(missing)}")

    return data


def summarize_rag_experience(rag_experience: Dict[str, Any]) -> str:
    """Produce a brief textual summary for logging/debugging."""

    success = len(rag_experience.get("successful_examples", []))
    failure = len(rag_experience.get("failed_examples", []))
    lessons = len(rag_experience.get("lessons", []))
    return f"success={success}, failure={failure}, lessons={lessons}"


# Internal helpers --------------------------------------------------------------

def _fetch_rag_context(rag_memory: Optional[Any], vuln: Dict[str, Any]) -> Dict[str, Any]:
    if rag_memory is None:
        return _empty_rag_response()

    try:
        return rag_memory.retrieve_relevant_experience(vuln, top_k=5)  # type: ignore[attr-defined]
    except AttributeError:
        logger.warning("RAG memory object missing retrieve_relevant_experience; falling back")
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to query RAG memory for %s: %s", vuln.get("vuln_id"), exc)
    return _empty_rag_response()


def _empty_rag_response() -> Dict[str, Any]:
    return {
        "successful_examples": [],
        "failed_examples": [],
        "lessons": [],
        "query": "",
    }


def _format_context(context: Dict[str, Any]) -> str:
    company = context.get("company_name", "Unknown Org")
    environment = context.get("environment", "Unknown")
    constraints = context.get("exploitation_constraints", {})
    safety = context.get("safety_constraints", {})
    capabilities = constraints.get("agent_capabilities", []) or []
    limitations = constraints.get("agent_limitations", []) or []
    capabilities_text = ", ".join(capabilities) if capabilities else "None"
    limitations_text = ", ".join(limitations) if limitations else "None"

    return (
        f"CONTEXT:\n"
        f"- Company: {company}\n"
        f"- Environment: {environment}\n"
        f"- Agent capabilities: {capabilities_text}\n"
        f"- Agent limitations: {limitations_text}\n"
        f"- Safety max exploits/run: {safety.get('max_exploits_per_run', 'n/a')} | timeout: {safety.get('timeout_per_exploit', 'n/a')}s"
    )


def _format_vulnerability(vuln: Dict[str, Any]) -> str:
    return (
        f"- ID: {vuln.get('vuln_id')} (priority {vuln.get('priority')} score {vuln.get('priority_score')})\n"
        f"- Target: host={vuln.get('host')} port={vuln.get('port')} service={vuln.get('service')} version={vuln.get('version')}\n"
        f"- Attack vector: {vuln.get('attack_vector')} | Exploitability: {vuln.get('exploitability')}\n"
        f"- Prerequisites: {', '.join(vuln.get('prerequisites', []) or ['none'])}\n"
        f"- Rationale: {vuln.get('rationale')}"
    )


def _format_rag_section(rag_experience: Dict[str, Any]) -> str:
    successful = rag_experience.get("successful_examples", []) or []
    failed = rag_experience.get("failed_examples", []) or []
    lessons = rag_experience.get("lessons", []) or []

    success_lines = _format_examples(successful, tag="SUCCESS")
    failure_lines = _format_examples(failed, tag="FAILURE")
    lesson_lines = _format_lessons(lessons)

    summary = (
        f"Query: {rag_experience.get('query') or 'n/a'}\n"
        f"Matches -> successes: {len(successful)} | failures: {len(failed)} | lessons: {len(lessons)}"
    )

    sections = [
        summary,
        "Successful approaches:\n" + (success_lines or "- None"),
        "Failed approaches to avoid:\n" + (failure_lines or "- None"),
        "Key lessons:\n" + (lesson_lines or "- None"),
    ]
    return "\n\n".join(sections)


def _format_examples(examples: List[Dict[str, Any]], tag: str) -> str:
    lines: List[str] = []
    for example in examples:
        metadata = example.get("metadata", {})
        similarity = example.get("similarity")
        if isinstance(similarity, (int, float)):
            similarity_str = f"{similarity:.2f}"
        else:
            similarity_str = "n/a"
        lines.append(
            f"- [{tag}] service={metadata.get('service')} version={metadata.get('version')} "
            f"type={metadata.get('exploit_type')} similarity={similarity_str}"
        )
        key_excerpt = metadata.get("script_excerpt") or example.get("document")
        if key_excerpt:
            lines.append(f"    snippet={_truncate(str(key_excerpt), 160)}")
    return "\n".join(lines)


def _format_lessons(lessons: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for lesson in lessons:
        lines.append(f"- Lessons: {lesson.get('document') or lesson.get('metadata', {}).get('summary', '')}")
    return "\n".join(lines)


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else f"{text[:limit-3]}..."
