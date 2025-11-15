"""Safe execution engine for generated exploit scripts."""

from __future__ import annotations

import contextlib
import io
import os
import queue
import shutil
import tempfile
import threading
import time
import traceback
from typing import Any, Dict

from .validator import validate_exploit_script


class ExecutionError(RuntimeError):
    """Raised when exploit execution cannot be completed."""


def execute_exploit_script(vuln: Dict[str, Any], script: str, timeout: int = 60) -> Dict[str, Any]:
    """Execute a validated exploit script inside an isolated thread."""

    validation = validate_exploit_script(script)
    if not validation["valid"]:
        raise ExecutionError(f"Script failed validation: {validation}")

    target_ip = str(vuln.get("host"))
    if not target_ip:
        raise ExecutionError("Vulnerability entry missing target host")

    port = int(vuln.get("port", 0))
    result_queue: queue.Queue = queue.Queue()
    start_time = time.time()
    
    thread = threading.Thread(
        target=_executor_worker,
        args=(script, target_ip, port, result_queue),
        daemon=True,
    )
    thread.start()
    thread.join(timeout)
    execution_time = time.time() - start_time

    if thread.is_alive():
        # Thread is still running after timeout
        return {
            "success": False,
            "message": "Execution timed out",
            "evidence": None,
            "execution_time": timeout,
            "stdout": "",
            "stderr": "",
            "return_code": None,
            "error_message": "Timeout expired",
        }

    try:
        payload = result_queue.get_nowait()
    except queue.Empty:
        return {
            "success": False,
            "message": "Exploit failed",
            "evidence": None,
            "execution_time": execution_time,
            "stdout": "",
            "stderr": "",
            "return_code": None,
            "error_message": "Execution produced no result",
        }

    return _build_result_from_payload(payload, execution_time)


def _build_result_from_payload(payload: Dict[str, Any], execution_time: float) -> Dict[str, Any]:
    stdout = (payload.get("stdout") or "").strip()
    stderr = (payload.get("stderr") or "").strip()

    if payload.get("error"):
        return {
            "success": False,
            "message": "Exploit failed",
            "evidence": None,
            "execution_time": execution_time,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": 1,
            "error_message": payload.get("error"),
        }

    result = payload.get("result") or {}
    success = bool(result.get("success"))
    evidence = result.get("evidence") or stdout
    message = result.get("message") or ("Exploit executed" if success else "Exploit failed")
    error_message = None if success else result.get("error_message") or stderr or "Exploit returned failure"

    return {
        "success": success,
        "message": message,
        "evidence": evidence,
        "execution_time": execution_time,
        "stdout": stdout,
        "stderr": stderr,
        "return_code": 0 if success else 1,
        "error_message": error_message,
    }


def _executor_worker(script: str, target_ip: str, target_port: int, result_queue: queue.Queue) -> None:
    """Run exploit code inside a thread and communicate structured output."""

    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    temp_dir = tempfile.mkdtemp(prefix="auvap_exec_")
    original_cwd = os.getcwd()
    try:
        os.chdir(temp_dir)
        namespace: Dict[str, Any] = {"__name__": "__auvap_exploit__", "__file__": os.path.join(temp_dir, "exploit.py")}
        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            exec(compile(script, namespace["__file__"], "exec"), namespace)
            exploit = namespace.get("exploit")
            if not callable(exploit):
                raise RuntimeError("Exploit function 'exploit' not found")
            result = exploit(target_ip, target_port)
            if not isinstance(result, dict):
                raise RuntimeError("Exploit function must return a dictionary")
        result_queue.put(
            {
                "result": result,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
            }
        )
    except Exception as exc:  # noqa: BLE001
        result_queue.put(
            {
                "error": f"{exc}",
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        os.chdir(original_cwd)
        shutil.rmtree(temp_dir, ignore_errors=True)