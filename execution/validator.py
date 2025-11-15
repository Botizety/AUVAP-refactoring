"""Exploit script validation utilities."""

from __future__ import annotations

import ast
import re
from typing import Dict, List

_REQUIRED_RETURN_KEYS = {"success", "message", "evidence"}
_FORBIDDEN_PATTERNS = [
    r"rm\s+-rf",
    r"mkfs",
    r"dd\s+if=/dev/zero",
    r"shutdown",
    r"reboot",
    r"poweroff",
    r"os\.system.*rm",
    r"subprocess\..*rm\s+-rf",
    r"eval\(.*input",
    r"exec\(.*input",
    r"__import__\(\s*['\"]os['\"]\)\s*\.system",
]
_TIMEOUT_HINTS = ["timeout", "settimeout", "read_timeout", "connect_timeout"]


def validate_exploit_script(script: str) -> Dict[str, List[str] | bool]:
    """Validate exploit script safety and structure before execution."""

    result = {"valid": True, "errors": [], "warnings": [], "safety_issues": []}
    _check_syntax(script, result)
    _check_structure(script, result)
    _check_forbidden_patterns(script, result)
    _check_timeout_presence(script, result)
    _check_return_structure(script, result)

    result["valid"] = not result["errors"] and not result["safety_issues"]
    return result


def _check_syntax(script: str, result: Dict[str, List[str] | bool]) -> None:
    try:
        ast.parse(script)
    except SyntaxError as exc:
        result["errors"].append(f"Syntax error: {exc}")


def _check_structure(script: str, result: Dict[str, List[str] | bool]) -> None:
    if "def exploit" not in script:
        result["errors"].append("Missing exploit function definition")
    if "return {" not in script and "return{" not in script:
        result["errors"].append("Missing structured return statement")
    if "if __name__ == __main__" not in script and "if __name__ == '__main__'" not in script:
        result["warnings"].append("Script lacks __main__ guard")


def _check_forbidden_patterns(script: str, result: Dict[str, List[str] | bool]) -> None:
    lowered = script.lower()
    for pattern in _FORBIDDEN_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            result["safety_issues"].append(f"Forbidden pattern detected: {pattern}")


def _check_timeout_presence(script: str, result: Dict[str, List[str] | bool]) -> None:
    if not any(hint in script for hint in _TIMEOUT_HINTS):
        result["warnings"].append("No timeout handling detected")


def _check_return_structure(script: str, result: Dict[str, List[str] | bool]) -> None:
    for key in _REQUIRED_RETURN_KEYS:
        if key not in script:
            result["errors"].append(f"Missing '{key}' in return structure")