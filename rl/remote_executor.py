"""Remote execution engine for running exploit scripts on a VM from Mac."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TypeVar

import paramiko

logger = logging.getLogger("auvap.rl.remote_executor")

T = TypeVar("T")


class RemoteVMExecutor:
    """
    Execute exploit scripts on a remote VM via SSH.
    
    Transfers script to VM, executes in isolated environment, returns results.
    Used by PPO training to run exploits on VM instead of Mac host.
    """
    
    def __init__(
        self,
        vm_host: str,
        vm_port: int = 22,
        vm_user: str = "kali",
        vm_password: Optional[str] = None,
        vm_key_path: Optional[str] = None,
        python_path: str = "python3",
        workspace_dir: str = "/tmp/auvap_rl",
    ):
        self.vm_host = vm_host
        self.vm_port = vm_port
        self.vm_user = vm_user
        self.vm_password = vm_password
        self.vm_key_path = vm_key_path
        self.python_path = python_path
        self.workspace_dir = workspace_dir
        
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self._connected = False
        
    def connect(self) -> None:
        """Establish SSH connection to VM."""
        
        if self._connected and self.ssh_client:
            return
        
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Configure for legacy SSH (Metasploitable2 compatibility)
        ssh_options = {
            "disabled_algorithms": {"pubkeys": [], "keys": []},
        }
        
        try:
            if self.vm_key_path:
                key_path = Path(self.vm_key_path).expanduser()
                pkey = paramiko.RSAKey.from_private_key_file(str(key_path))
                self.ssh_client.connect(
                    hostname=self.vm_host,
                    port=self.vm_port,
                    username=self.vm_user,
                    pkey=pkey,
                    timeout=10,
                    **ssh_options,
                )
            else:
                self.ssh_client.connect(
                    hostname=self.vm_host,
                    port=self.vm_port,
                    username=self.vm_user,
                    password=self.vm_password,
                    timeout=10,
                    **ssh_options,
                )
            
            self._connected = True
            logger.info("Connected to VM %s@%s:%s", self.vm_user, self.vm_host, self.vm_port)
            transport = self.ssh_client.get_transport()
            if transport:
                transport.set_keepalive(30)
            
            # Create workspace directory on VM
            self._exec_command(f"mkdir -p {self.workspace_dir}")
            
        except Exception as exc:
            logger.error("Failed to connect to VM: %s", exc)
            raise RuntimeError(f"VM connection failed: {exc}") from exc
    
    def disconnect(self) -> None:
        """Close SSH connection."""
        
        if self.ssh_client:
            self.ssh_client.close()
        self._connected = False
        logger.info("Disconnected from VM %s", self.vm_host)
    
    def execute_script_remote(
        self,
        vuln: Dict[str, Any],
        script: str,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """
        Execute exploit script on remote VM.
        
        Returns same format as local executor for compatibility with PPO environment.
        """
        
        if not self._connected:
            self.connect()
        
        # Generate unique script filename
        script_id = f"exploit_{vuln.get('vuln_id', 'unknown')}_{os.urandom(4).hex()}"
        remote_script_path = f"{self.workspace_dir}/{script_id}.py"
        remote_result_path = f"{self.workspace_dir}/{script_id}_result.json"
        
        # Prepare wrapper script that captures execution results
        wrapper = self._build_wrapper_script(script, vuln, remote_result_path)
        
        try:
            # Transfer script to VM
            self._write_remote_file(remote_script_path, wrapper)
            
            # Execute script on VM with timeout
            command = f"timeout {timeout}s {self.python_path} {remote_script_path} 2>&1"
            stdout, stderr, exit_code = self._exec_command(command, timeout=timeout + 5)
            
            # Log execution details for debugging
            if exit_code != 0:
                logger.warning("Script execution failed on VM | exit_code=%s stdout=%s stderr=%s", 
                             exit_code, stdout[:200] if stdout else "", stderr[:200] if stderr else "")
            
            # Small delay to ensure file is written (disk flush)
            import time
            time.sleep(0.5)
            
            # Retrieve execution result JSON
            result = self._read_remote_result(remote_result_path)
            
            # Clean up remote files
            self._exec_command(f"rm -f {remote_script_path} {remote_result_path}")
            
            if result:
                # Add stdout/stderr from remote execution
                result["stdout"] = stdout
                result["stderr"] = stderr
                result["return_code"] = exit_code
                return result
            
            # Fallback if no result JSON (script crashed)
            return {
                "success": False,
                "message": "Exploit failed on VM",
                "evidence": None,
                "execution_time": 0.0,
                "stdout": stdout,
                "stderr": stderr,
                "return_code": exit_code,
                "error_message": stderr or "Script execution failed",
            }
            
        except Exception as exc:  # noqa: BLE001
            logger.error("Remote execution failed: %s", exc)
            return {
                "success": False,
                "message": "Remote execution error",
                "evidence": None,
                "execution_time": 0.0,
                "stdout": "",
                "stderr": str(exc),
                "return_code": 1,
                "error_message": str(exc),
            }
    
    def _build_wrapper_script(
        self,
        exploit_script: str,
        vuln: Dict[str, Any],
        result_path: str,
    ) -> str:
        """Build Python wrapper that executes exploit and saves results as JSON."""
        
        # Extract host/port from nested 'finding' dict if present
        finding = vuln.get("finding", {})
        target_ip = finding.get("host", vuln.get("host", "127.0.0.1"))
        target_port = finding.get("port", vuln.get("port", 0))
        
        # Strip type hints and f-strings for Python 3.4 compatibility
        import re
        # Remove type hints: (arg: type) -> returntype:
        exploit_script_compat = re.sub(r'(\w+)\s*:\s*[\w\[\]\.]+(\s*[,\)])', r'\1\2', exploit_script)
        exploit_script_compat = re.sub(r'\)\s*->\s*[\w\[\]\.]+\s*:', '):', exploit_script_compat)
        
        # Remove Python 3.6+ SSL constants not available in Python 3.4
        # ssl.OP_NO_TLSv1_1, ssl.OP_NO_TLSv1_2, ssl.OP_NO_TLSv1_3, etc.
        exploit_script_compat = re.sub(r'ssl\.OP_NO_\w+', '0  # Removed incompatible SSL constant', exploit_script_compat)
        # Remove SSLContext with specific protocol versions not in 3.4
        exploit_script_compat = re.sub(r'ssl\.PROTOCOL_TLS_CLIENT', 'ssl.PROTOCOL_SSLv23', exploit_script_compat)
        exploit_script_compat = re.sub(r'ssl\.PROTOCOL_TLS_SERVER', 'ssl.PROTOCOL_SSLv23', exploit_script_compat)
        exploit_script_compat = re.sub(r'ssl\.PROTOCOL_TLS\b', 'ssl.PROTOCOL_SSLv23', exploit_script_compat)
        # Remove context.options = lines that try to set SSL options
        exploit_script_compat = re.sub(r'context\.options\s*[|]?=\s*ssl\.OP_\w+.*', '# Removed incompatible SSL option', exploit_script_compat)
        
        # Convert bytes.hex() to binascii.hexlify() for Python 3.4 compatibility
        # Add import at the top if .hex() is used
        if '.hex()' in exploit_script_compat:
            # Add binascii import after other imports
            exploit_script_compat = 'import binascii\n' + exploit_script_compat
            # Replace variable.hex() with binascii.hexlify(variable).decode('ascii')
            exploit_script_compat = re.sub(r'(\w+)\.hex\(\)', r"binascii.hexlify(\1).decode('ascii')", exploit_script_compat)
        
        # Convert f-strings to .format() style
        # f"text {var}" or f"text {var:.2f}" -> "text {}".format(var) or "text {:.2f}".format(var)
        def convert_fstring(match):
            content = match.group(1)
            # Extract variables with optional format specs: {var} or {var:.2f}
            vars_info = re.findall(r'\{([^:}]+)(?::([^}]+))?\}', content)
            vars_list = [v[0] for v in vars_info]
            # Replace {var:spec} with {:spec} or {var} with {}
            template = re.sub(r'\{[^:}]+(:([^}]+))?\}', lambda m: '{' + (m.group(1) or '') + '}', content)
            if vars_list:
                return '"{}"'.format(template) + '.format({})'.format(", ".join(vars_list))
            return '"{}"'.format(template)
        
        exploit_script_compat = re.sub(r'f"([^"]*)"', convert_fstring, exploit_script_compat)
        exploit_script_compat = re.sub(r"f'([^']*)'", lambda m: convert_fstring(type('M', (), {'group': lambda s, x: m.group(x)})()), exploit_script_compat)
        
        # Python 3.4 compatible wrapper (no f-strings, compatible exception handling)
        wrapper = '''#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Remote exploit execution wrapper for AUVAP PPO training."""

from __future__ import print_function
import json
import sys
import time
import traceback

# Embedded exploit script
''' + exploit_script_compat + '''

def main():
    """Execute exploit and save results."""
    
    target_ip = "''' + target_ip + '''"
    target_port = ''' + str(target_port) + '''
    result_path = "''' + result_path + '''"
    
    start_time = time.time()
    
    try:
        # Call exploit function
        if not callable(globals().get("exploit")):
            raise RuntimeError("Exploit function 'exploit' not found in script")
        
        result = exploit(target_ip, target_port)
        execution_time = time.time() - start_time
        
        if not isinstance(result, dict):
            raise RuntimeError("Exploit function must return a dictionary")
        
        # Add execution metadata
        result["execution_time"] = execution_time
        result["target_ip"] = target_ip
        result["target_port"] = target_port
        
        # Save result JSON
        with open(result_path, "w") as f:
            json.dump(result, f)
        
        # Print for debugging
        print(json.dumps(result, indent=2))
        
        sys.exit(0 if result.get("success") else 1)
        
    except Exception as exc:
        execution_time = time.time() - start_time
        error_result = {
            "success": False,
            "message": "Exploit failed",
            "evidence": None,
            "execution_time": execution_time,
            "error_message": str(exc),
            "traceback": traceback.format_exc(),
        }
        
        # Save error result
        try:
            with open(result_path, "w") as f:
                json.dump(error_result, f)
        except:
            pass
        
        print(json.dumps(error_result, indent=2), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
        return wrapper
    
    def _write_remote_file(self, remote_path: str, content: str) -> None:
        """Write file to remote VM via SFTP."""
        
        if not self.ssh_client:
            raise RuntimeError("Not connected to VM")

        def _upload() -> None:
            if not self.ssh_client:
                raise RuntimeError("Not connected to VM")
            sftp = self.ssh_client.open_sftp()
            try:
                with sftp.open(remote_path, "w") as f:
                    f.write(content)
                sftp.chmod(remote_path, 0o755)
            finally:
                sftp.close()

        self._with_reconnect(_upload)
    
    def _read_remote_result(self, remote_path: str) -> Optional[Dict[str, Any]]:
        """Read execution result JSON from VM using cat command instead of SFTP."""
        
        if not self.ssh_client:
            return None

        try:
            # Use cat command instead of SFTP to avoid file handle issues
            stdout, stderr, exit_code = self._exec_command(f"cat {remote_path}", timeout=10)
            
            if exit_code != 0:
                logger.warning("Result file not found on VM: %s", remote_path)
                return None
            
            if not stdout:
                logger.warning("Result file is empty: %s", remote_path)
                return None
            
            # Parse JSON from stdout
            try:
                return json.loads(stdout)
            except json.JSONDecodeError as exc:
                logger.warning("Failed to parse result JSON from %s: %s", remote_path, exc)
                logger.debug("Raw stdout: %s", stdout[:500])
                return None
                
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to read result from VM: %s", exc)
            return None
    
    def _exec_command(
        self,
        command: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Execute command on VM and return stdout, stderr, exit code."""
        
        if not self.ssh_client:
            raise RuntimeError("Not connected to VM")

        def _run() -> tuple[str, str, int]:
            if not self.ssh_client:
                raise RuntimeError("Not connected to VM")
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()

            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")

            return stdout_text, stderr_text, exit_code

        try:
            return self._with_reconnect(_run)
        except Exception as exc:
            logger.error("Command execution failed after reconnect attempt: %s", exc)
            return "", str(exc), 1

    def _with_reconnect(self, func: Callable[[], T]) -> T:
        """Ensure SSH connection is active before running func, reconnecting if needed."""

        self._ensure_connection()
        try:
            return func()
        except (paramiko.SSHException, OSError) as exc:
            logger.warning("SSH session issue detected (%s). Reconnecting and retrying once.", exc)
            self._reset_connection()
            self.connect()
            return func()

    def _ensure_connection(self) -> None:
        """Reconnect if transport is no longer active."""

        if not self._transport_active():
            self._connected = False
        if not self._connected:
            self.connect()

    def _transport_active(self) -> bool:
        if not self.ssh_client:
            return False
        transport = self.ssh_client.get_transport()
        return bool(transport and transport.is_active())

    def _reset_connection(self) -> None:
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:  # noqa: BLE001
                pass
        self._connected = False
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False


def create_remote_executor_from_env() -> Optional[RemoteVMExecutor]:
    """
    Create RemoteVMExecutor from environment variables.
    
    Required env vars:
    - RL_VM_HOST: VM hostname/IP
    
    Optional env vars:
    - RL_VM_PORT: SSH port (default: 22)
    - RL_VM_USER: SSH username (default: kali)
    - RL_VM_PASSWORD: SSH password (if not using key)
    - RL_VM_KEY_PATH: Path to SSH private key (if not using password)
    - RL_VM_PYTHON: Python path on VM (default: python3)
    - RL_VM_WORKSPACE: Workspace directory on VM (default: /tmp/auvap_rl)
    """
    
    vm_host = os.environ.get("RL_VM_HOST")
    if not vm_host:
        logger.warning("RL_VM_HOST not set, remote execution disabled")
        return None
    
    vm_port = int(os.environ.get("RL_VM_PORT", "22"))
    vm_user = os.environ.get("RL_VM_USER", "kali")
    vm_password = os.environ.get("RL_VM_PASSWORD")
    vm_key_path = os.environ.get("RL_VM_KEY_PATH")
    python_path = os.environ.get("RL_VM_PYTHON", "python3")
    workspace_dir = os.environ.get("RL_VM_WORKSPACE", "/tmp/auvap_rl")
    
    if not vm_password and not vm_key_path:
        logger.error("Either RL_VM_PASSWORD or RL_VM_KEY_PATH must be set")
        return None
    
    return RemoteVMExecutor(
        vm_host=vm_host,
        vm_port=vm_port,
        vm_user=vm_user,
        vm_password=vm_password,
        vm_key_path=vm_key_path,
        python_path=python_path,
        workspace_dir=workspace_dir,
    )
