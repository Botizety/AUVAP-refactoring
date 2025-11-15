"""Unit tests for the exploit script validator."""

from __future__ import annotations

from execution.validator import validate_exploit_script


def _base_script(timeout_line: str = "socket.setdefaulttimeout(5)") -> str:
    return f"""import socket


def exploit(target_ip, target_port):
    {timeout_line}
    return {{"success": True, "message": "done", "evidence": "ok"}}


if __name__ == '__main__':
    exploit('127.0.0.1', 22)
"""


def test_valid_script_passes_validation() -> None:
    result = validate_exploit_script(_base_script())
    assert result["valid"] is True
    assert not result["errors"]
    assert not result["safety_issues"]


def test_missing_exploit_function_fails() -> None:
    script = "print('hello world')"
    result = validate_exploit_script(script)
    assert result["valid"] is False
    assert "Missing exploit function definition" in result["errors"][0]


def test_forbidden_pattern_detected() -> None:
    script = _base_script().replace("return", "import os\nos.system('rm -rf /')\nreturn")
    result = validate_exploit_script(script)
    assert result["valid"] is False
    assert any("Forbidden pattern" in issue for issue in result["safety_issues"])


def test_timeout_warning_triggered() -> None:
    script = _base_script(timeout_line="pass")
    result = validate_exploit_script(script)
    assert "No timeout handling" in result["warnings"][0]