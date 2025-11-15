"""Tests for the exploit executor module."""

from __future__ import annotations

import textwrap
from typing import Dict

import pytest  # type: ignore[import-not-found]

from execution.executor import ExecutionError, execute_exploit_script


def _simple_script(success: bool = True) -> str:
    return textwrap.dedent(
        f"""
        import sys
        import time

        def exploit(target_ip, target_port):
            time.sleep(0.05)
            return {{"success": {str(success)}, "message": "ok", "evidence": "flag"}}

        if __name__ == '__main__':
            result = exploit(sys.argv[1], int(sys.argv[2]))
            print(f"success: {{result['success']}}")
            if result['success']:
                print("exploit successful")
            else:
                print("failed")
        """
    )


def _vuln() -> Dict[str, str | int]:
    return {"host": "127.0.0.1", "port": 9999}


def test_executor_successful_run(tmp_path) -> None:
    result = execute_exploit_script(_vuln(), _simple_script(True), timeout=5)
    assert result["success"] is True
    assert "flag" in (result["evidence"] or "")


def test_executor_handles_failure(tmp_path) -> None:
    result = execute_exploit_script(_vuln(), _simple_script(False), timeout=5)
    assert result["success"] is False
    assert result["error_message"]


def test_executor_rejects_invalid_script() -> None:
    script = "print('hi')"
    with pytest.raises(ExecutionError):
        execute_exploit_script(_vuln(), script)