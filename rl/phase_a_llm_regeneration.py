"""Phase A: LLM-based Script Regeneration with Error Feedback.

This module implements the first phase of the two-phase training approach:
- Phase A: Use LLM to regenerate broken scripts based on error messages
- Phase B: Use PPO to fine-tune working scripts for optimization

Phase A iteratively improves scripts using LLM feedback until they work or max attempts reached.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from execution.executor import execute_exploit_script

logger = logging.getLogger("auvap.rl.phase_a")


class PhaseARegenerator:
    """
    LLM-based script regeneration with error feedback.

    Iteratively improves exploit scripts by:
    1. Executing script and capturing errors
    2. Analyzing error types and root causes
    3. Requesting LLM to regenerate with specific fixes
    4. Repeating until success or max attempts
    """

    def __init__(
        self,
        llm_client: Any,
        rag_memory: Optional[Any] = None,
        remote_executor: Optional[Any] = None,
        max_regeneration_attempts: int = 5,
        success_threshold: float = 0.0,  # Any execution without crash counts as "working"
    ):
        self.llm_client = llm_client
        self.rag_memory = rag_memory
        self.remote_executor = remote_executor
        self.max_regeneration_attempts = max_regeneration_attempts
        self.success_threshold = success_threshold

    def regenerate_until_working(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        context_rules: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Regenerate script using LLM until it works or max attempts reached.

        Returns:
            {
                "success": bool,  # True if script works
                "final_script": str,
                "attempts": int,
                "execution_results": List[Dict],
                "improvement_log": List[str],
            }
        """

        current_script = initial_script
        execution_results = []
        improvement_log = []

        for attempt in range(1, self.max_regeneration_attempts + 1):
            logger.info(
                "Phase A | Attempt %s/%s for %s",
                attempt,
                self.max_regeneration_attempts,
                vuln.get("vuln_id"),
            )

            # Execute script and capture result
            result = self._execute_script(vuln, current_script)
            execution_results.append(result)

            # Check if script is "working" (executed without crashing)
            if self._is_script_working(result):
                logger.info(
                    "Phase A | Script is now working after %s attempts | success=%s",
                    attempt,
                    result.get("success"),
                )
                return {
                    "success": True,
                    "final_script": current_script,
                    "attempts": attempt,
                    "execution_results": execution_results,
                    "improvement_log": improvement_log,
                    "phase": "A_complete",
                }

            # Analyze error and request regeneration
            if attempt < self.max_regeneration_attempts:
                error_analysis = self._analyze_error(result, execution_results)
                improvement_log.append(
                    f"Attempt {attempt}: {error_analysis['error_summary']}"
                )

                # Request LLM to regenerate script with specific fixes
                logger.info("Phase A | Requesting LLM regeneration: %s", error_analysis['fix_request'])
                new_script = self._request_llm_regeneration(
                    vuln=vuln,
                    current_script=current_script,
                    error_analysis=error_analysis,
                    context_rules=context_rules,
                )

                if new_script and new_script != current_script:
                    current_script = new_script
                    logger.debug("Phase A | LLM generated new script (%s chars)", len(current_script))
                else:
                    logger.warning("Phase A | LLM returned identical or empty script, using original")

        # Max attempts reached without success
        logger.warning(
            "Phase A | Failed to fix script after %s attempts for %s",
            self.max_regeneration_attempts,
            vuln.get("vuln_id"),
        )
        return {
            "success": False,
            "final_script": current_script,
            "attempts": self.max_regeneration_attempts,
            "execution_results": execution_results,
            "improvement_log": improvement_log,
            "phase": "A_failed",
        }

    def _execute_script(self, vuln: Dict[str, Any], script: str) -> Dict[str, Any]:
        """Execute script on remote VM or locally."""

        try:
            if self.remote_executor:
                result = self.remote_executor.execute_script_remote(
                    vuln, script, timeout=60
                )
            else:
                result = execute_exploit_script(vuln, script, timeout=60)
            return result
        except Exception as exc:
            logger.error("Phase A | Script execution failed: %s", exc)
            return {
                "success": False,
                "error_message": str(exc),
                "evidence": None,
                "execution_time": 0.0,
            }

    def _is_script_working(self, result: Dict[str, Any]) -> bool:
        """
        Check if script is "working" (can execute without crashing).

        Working means:
        - No SyntaxError, NameError, IndentationError
        - Script actually ran (even if exploit failed)
        - Bonus: Collected some evidence
        """

        error_msg = result.get("error_message") or ""
        error_type = result.get("error_type") or ""
        traceback = result.get("traceback") or ""
        evidence = result.get("evidence") or ""

        # Fatal errors that mean script is broken
        fatal_errors = [
            "SyntaxError",
            "NameError",
            "IndentationError",
            "ModuleNotFoundError",
            "ImportError",
        ]

        # Check for fatal errors
        for fatal in fatal_errors:
            if fatal in error_type or fatal in traceback:
                return False

        # If script succeeded, it's definitely working
        if result.get("success"):
            return True

        # If script ran and collected evidence, it's working (just needs optimization)
        if evidence and len(evidence) > 30:
            logger.info("Phase A | Script collected evidence, considering it 'working'")
            return True

        # If script ran without fatal errors, it's working (even if exploit failed)
        # This allows Phase B PPO to optimize it
        if not any(fatal in traceback for fatal in fatal_errors):
            logger.info("Phase A | Script executed without fatal errors, considering it 'working'")
            return True

        return False

    def _analyze_error(
        self,
        result: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        """Analyze error and determine root cause + fix strategy."""

        error_msg = result.get("error_message") or ""
        error_type = result.get("error_type") or ""
        traceback = result.get("traceback") or ""

        # Categorize error
        if "AttributeError" in error_type or "has no attribute" in error_msg:
            if "OP_NO" in error_msg or "ssl" in error_msg.lower():
                return {
                    "error_summary": f"SSL constant incompatibility: {error_msg[:100]}",
                    "error_category": "ssl_compatibility",
                    "fix_request": "Remove all ssl.OP_NO_* constants and context.options assignments. Use ssl.PROTOCOL_SSLv23 instead of PROTOCOL_TLS.",
                }

        if "SyntaxError" in error_type:
            return {
                "error_summary": f"Syntax error: {error_msg[:100]}",
                "error_category": "syntax",
                "fix_request": "Fix Python syntax errors. Ensure code is Python 3.4+ compatible (no f-strings, no walrus operator).",
            }

        if "NameError" in error_type or "not defined" in error_msg:
            return {
                "error_summary": f"Undefined variable: {error_msg[:100]}",
                "error_category": "undefined_variable",
                "fix_request": "Add missing imports or define undefined variables.",
            }

        if "timeout" in error_msg.lower():
            return {
                "error_summary": f"Connection timeout: {error_msg[:100]}",
                "error_category": "timeout",
                "fix_request": "Increase timeout values or simplify connection logic.",
            }

        if "SSLError" in error_msg or "SSL" in error_msg:
            return {
                "error_summary": f"SSL/TLS error: {error_msg[:100]}",
                "error_category": "ssl_handshake",
                "fix_request": "Use compatible SSL protocols (SSLv23). Handle SSL handshake errors gracefully.",
            }

        # Generic error
        return {
            "error_summary": f"{error_type}: {error_msg[:100]}",
            "error_category": "runtime_error",
            "fix_request": f"Fix the following error: {error_msg[:200]}",
        }

    def _request_llm_regeneration(
        self,
        vuln: Dict[str, Any],
        current_script: str,
        error_analysis: Dict[str, str],
        context_rules: Dict[str, Any],
    ) -> Optional[str]:
        """Request LLM to regenerate script with specific fixes."""

        prompt = self._build_regeneration_prompt(
            vuln, current_script, error_analysis, context_rules
        )

        try:
            # Call LLM with regeneration request
            response = self.llm_client.call_with_json_response(
                prompt=prompt,
                temperature=0.7,
                max_tokens=2500,
            )

            # Extract new script from response
            if isinstance(response, dict):
                new_script = response.get("exploit_script")
                if new_script:
                    logger.info("Phase A | LLM regenerated script successfully")
                    return new_script
            elif isinstance(response, str):
                # Try to parse as JSON
                import json
                try:
                    data = json.loads(response)
                    return data.get("exploit_script")
                except json.JSONDecodeError:
                    logger.warning("Phase A | LLM response is not valid JSON")

            logger.warning("Phase A | LLM response missing 'exploit_script' field")
            return None

        except Exception as exc:
            logger.error("Phase A | LLM regeneration failed: %s", exc)
            return None

    def _build_regeneration_prompt(
        self,
        vuln: Dict[str, Any],
        current_script: str,
        error_analysis: Dict[str, str],
        context_rules: Dict[str, Any],
    ) -> str:
        """Build prompt for LLM script regeneration with error context."""

        vuln_id = vuln.get("vuln_id")
        service = vuln.get("service") or vuln.get("finding", {}).get("service", "unknown")
        port = vuln.get("port") or vuln.get("finding", {}).get("port", 0)

        return f"""
You are an expert exploit developer. A generated exploit script has FAILED with the following error:

ERROR ANALYSIS:
- Category: {error_analysis['error_category']}
- Summary: {error_analysis['error_summary']}

FIX REQUIRED:
{error_analysis['fix_request']}

TARGET:
- Vulnerability ID: {vuln_id}
- Service: {service} on port {port}
- Description: {vuln.get('rationale', 'N/A')}

CURRENT BROKEN SCRIPT:
```python
{current_script}
```

REQUIREMENTS:
1. Fix the specific error identified above
2. Target environment: Metasploitable 2 running on 192.168.126.128
3. Python 3.4 compatibility required (no f-strings, no walrus operator, no Python 3.6+ features)
4. SSL compatibility: Use ssl.PROTOCOL_SSLv23, avoid ssl.OP_NO_* constants
5. STARTTLS handling: Use starttls_response.lstrip().startswith("220") for SMTP
6. Return dict with {{"success": bool, "message": str, "evidence": str}}
7. Include error handling and timeouts

OUTPUT JSON:
{{
  "exploit_script": "<COMPLETE FIXED PYTHON CODE>",
  "changes_made": ["list of specific fixes applied"],
  "explanation": "brief explanation of the fix"
}}

Wrap JSON between <json> and </json> tags.
""".strip()
