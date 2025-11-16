"""Gym environment for exploit script modification and execution."""

from __future__ import annotations

import ast
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from execution.executor import execute_exploit_script

logger = logging.getLogger("auvap.rl.script_env")


class ExploitScriptEnv(gym.Env):
    """
    Reinforcement learning environment for iteratively improving exploit scripts.
    
    Agent observes script structure, execution results, and target metadata, then
    chooses modifications (adjust timeout, toggle SSL verification, change payload, etc.).
    Reward is based on exploit success and execution feedback.
    """

    metadata = {"render_modes": ["human"]}

    def __init__(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        max_modifications: int = 10,
        timeout_range: Tuple[int, int] = (5, 120),
        remote_executor: Optional[Any] = None,
    ):
        super().__init__()
        self.vuln = vuln
        self.initial_script = initial_script
        self.max_modifications = max_modifications
        self.timeout_range = timeout_range
        self.remote_executor = remote_executor
        
        self.current_script = initial_script
        self.modification_count = 0
        self.execution_history: List[Dict[str, Any]] = []
        self.best_reward = 0.0  # Changed from -inf to prevent NaN issues
        
        # --- Action space: discrete modifications ---
        # 0: increase timeout, 1: decrease timeout, 2: toggle SSL verify,
        # 3: add retry logic, 4: change payload encoding, 5: adjust delay,
        # 6: modify connection parameters, 7: done (terminate episode)
        self.action_space = spaces.Discrete(8)
        
        # --- Observation space: script features + execution feedback + error tracking ---
        # [timeout_val, ssl_verify(0/1), retry_count, payload_length, has_error_handling,
        #  last_success(0/1), last_execution_time, modification_count, target_port,
        #  syntax_error, attribute_error, ssl_error, timeout_error, script_lines, consecutive_failures]
        self.observation_space = spaces.Box(
            low=np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], dtype=np.float32),
            high=np.array([300, 1, 10, 10000, 1, 1, 300, self.max_modifications, 65535,
                          1, 1, 1, 1, 1000, 50], dtype=np.float32),
            dtype=np.float32,
        )

        # Track consecutive failures for better learning
        self.consecutive_failures = 0
        
    def reset(self, seed: Optional[int] = None, options: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        super().reset(seed=seed)
        
        # Reset episode state but PRESERVE execution_history to track all attempts across episodes
        self.current_script = self.initial_script
        self.modification_count = 0
        self.consecutive_failures = 0
        # Keep last 50 results to prevent memory leak
        if len(self.execution_history) > 50:
            self.execution_history = self.execution_history[-50:]
        self.best_reward = 0.0  # Changed from -inf to prevent NaN issues
        obs = self._get_observation(last_result=None)
        info = {"vuln_id": self.vuln.get("vuln_id"), "reset": True}
        return obs, info
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        """Apply action, execute script, compute reward."""
        
        self.modification_count += 1
        terminated = False
        truncated = self.modification_count >= self.max_modifications
        
        # Action 7 = "done" signal from agent
        if action == 7:
            terminated = True
            obs = self._get_observation(last_result=None)
            reward = self.best_reward if self.execution_history else -10.0
            info = {"terminated_by_agent": True, "best_reward": self.best_reward}
            return obs, reward, terminated, truncated, info
        
        # Apply modification based on action
        modification_applied = self._apply_action(action)
        
        # Execute modified script (remote VM if configured, local otherwise)
        try:
            if self.remote_executor:
                result = self.remote_executor.execute_script_remote(
                    self.vuln, self.current_script, timeout=60
                )
                logger.debug("Executed script on remote VM")
            else:
                result = execute_exploit_script(self.vuln, self.current_script, timeout=60)
                logger.debug("Executed script locally")
            self.execution_history.append(result)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Script execution failed: %s", exc)
            result = {
                "success": False,
                "error_message": str(exc),
                "execution_time": 0.0,
                "evidence": None,
            }
            self.execution_history.append(result)
        
        # Compute reward
        reward = self._compute_reward(result, modification_applied)
        self.best_reward = max(self.best_reward, reward)

        # Track consecutive failures and terminate on success
        if result.get("success"):
            terminated = True
            self.consecutive_failures = 0
            logger.info("Script succeeded! Terminating episode early.")
        else:
            self.consecutive_failures += 1

        # Build observation
        obs = self._get_observation(last_result=result)

        info = {
            "action": action,
            "modification_applied": modification_applied,
            "success": result.get("success"),
            "execution_time": result.get("execution_time"),
            "error_message": result.get("error_message"),
            "error_type": result.get("error_type"),
            "best_reward": self.best_reward,
            "consecutive_failures": self.consecutive_failures,
        }

        return obs, reward, terminated, truncated, info
    
    def _apply_action(self, action: int) -> str:
        """Modify current_script based on action, return description."""
        
        if action == 0:  # Increase timeout
            self.current_script = self._modify_timeout(self.current_script, increase=True)
            return "increased_timeout"
        elif action == 1:  # Decrease timeout
            self.current_script = self._modify_timeout(self.current_script, increase=False)
            return "decreased_timeout"
        elif action == 2:  # Toggle SSL verification
            self.current_script = self._toggle_ssl_verify(self.current_script)
            return "toggled_ssl_verify"
        elif action == 3:  # Add retry logic
            self.current_script = self._add_retry_logic(self.current_script)
            return "added_retry_logic"
        elif action == 4:  # Change payload encoding
            self.current_script = self._change_payload_encoding(self.current_script)
            return "changed_payload_encoding"
        elif action == 5:  # Adjust delay
            self.current_script = self._adjust_delay(self.current_script)
            return "adjusted_delay"
        elif action == 6:  # Modify connection parameters
            self.current_script = self._modify_connection_params(self.current_script)
            return "modified_connection_params"
        return "no_modification"
    
    def _compute_reward(self, result: Dict[str, Any], modification: str) -> float:
        """
        Reward structure with DETAILED SHAPING for partial progress:
        - Success: +100
        - Script compiled (no SyntaxError): +10
        - Connected to target (evidence of banner): +15
        - Protocol negotiated (STARTTLS/EHLO): +25
        - Evidence collected (>50 chars): +30
        - Fast execution bonus: +10-20
        - Syntax/compilation error: -15
        - Repeated error: -12
        - Timeout: -8
        - New error type (exploration): +2
        """

        error_msg = result.get("error_message") or ""
        error_type = result.get("error_type") or ""
        evidence = result.get("evidence") or ""
        traceback_str = result.get("traceback") or ""

        # FULL SUCCESS
        if result.get("success"):
            base_reward = 100.0
            # Bonus for fast exploits
            exec_time = result.get("execution_time", 60.0)
            if exec_time < 5.0:
                base_reward += 20.0
            elif exec_time < 15.0:
                base_reward += 10.0
            return np.clip(base_reward, -50.0, 150.0)

        # PARTIAL SUCCESS - Reward shaping for progress
        partial_reward = 0.0

        # Check if script compiled (no SyntaxError/NameError/AttributeError in traceback)
        compilation_errors = ["SyntaxError", "NameError", "IndentationError"]
        if not any(err in traceback_str for err in compilation_errors):
            partial_reward += 10.0  # Script at least compiled and started running

        # Check for connection progress (banner received)
        if "Banner:" in evidence or "220" in evidence or "SMTP" in evidence:
            partial_reward += 15.0  # Connected to target

        # Check for protocol negotiation (STARTTLS, EHLO, etc.)
        protocol_indicators = ["STARTTLS", "EHLO", "HELO", "250", "TLS"]
        if any(indicator in evidence for indicator in protocol_indicators):
            partial_reward += 25.0  # Successfully negotiated protocol

        # Check for substantial evidence collected
        if evidence and len(evidence) > 50:
            partial_reward += 30.0  # Collected meaningful evidence

        # If we got any partial progress, return positive reward
        if partial_reward > 0:
            return np.clip(partial_reward, -50.0, 150.0)

        # FAILURES - Penalize based on error type

        # Severe: Syntax/compilation errors (script fundamentally broken)
        if error_type in compilation_errors or any(err in error_msg for err in compilation_errors):
            # Check if this is a NEW error type (exploration bonus)
            if self.execution_history:
                prev_error_types = [h.get("error_type") for h in self.execution_history[:-1]]
                if error_type not in prev_error_types:
                    return np.clip(-13.0, -50.0, 150.0)  # New error type, slight bonus
            return np.clip(-15.0, -50.0, 150.0)

        # Repeated same error (not learning)
        if error_msg and self.execution_history:
            prev_errors = [h.get("error_message", "") for h in self.execution_history[:-1]]
            if error_msg in prev_errors:
                return np.clip(-12.0, -50.0, 150.0)

        # Timeout errors (could be progress, just slow)
        if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
            return np.clip(-8.0, -50.0, 150.0)

        # Generic runtime failure (better than compilation failure)
        # Give small exploration bonus for trying
        return np.clip(-6.0 + 2.0, -50.0, 150.0)
    
    def _get_observation(self, last_result: Optional[Dict[str, Any]]) -> np.ndarray:
        """Extract features from current script and last execution result + error tracking."""

        timeout_val = self._extract_timeout(self.current_script)
        ssl_verify = 1.0 if self._has_ssl_verify(self.current_script) else 0.0
        retry_count = self._count_retries(self.current_script)
        payload_length = self._estimate_payload_size(self.current_script)
        has_error_handling = 1.0 if "try:" in self.current_script else 0.0

        last_success = 0.0
        last_exec_time = 0.0
        syntax_error = 0.0
        attribute_error = 0.0
        ssl_error = 0.0
        timeout_error = 0.0

        if last_result:
            last_success = 1.0 if last_result.get("success") else 0.0
            last_exec_time = last_result.get("execution_time", 0.0)

            # Error type indicators
            error_msg = last_result.get("error_message") or ""
            error_type = last_result.get("error_type") or ""

            syntax_error = 1.0 if "SyntaxError" in error_msg or error_type == "SyntaxError" else 0.0
            attribute_error = 1.0 if "AttributeError" in error_msg or error_type == "AttributeError" else 0.0
            ssl_error = 1.0 if "SSLError" in error_msg or "SSL" in error_msg else 0.0
            timeout_error = 1.0 if "timeout" in error_msg.lower() else 0.0

        target_port = float(self.vuln.get("port", 0))
        script_lines = float(len(self.current_script.split('\n')))
        consecutive_fails = float(min(self.consecutive_failures, 50))

        obs = np.array(
            [
                timeout_val,
                ssl_verify,
                retry_count,
                payload_length,
                has_error_handling,
                last_success,
                last_exec_time,
                self.modification_count,
                target_port,
                syntax_error,
                attribute_error,
                ssl_error,
                timeout_error,
                script_lines,
                consecutive_fails,
            ],
            dtype=np.float32,
        )
        return obs
    
    # --- Script modification helpers ---
    
    def _modify_timeout(self, script: str, increase: bool) -> str:
        """Adjust timeout values in script."""
        pattern = r"timeout\s*=\s*(\d+)"
        matches = list(re.finditer(pattern, script, re.IGNORECASE))
        if not matches:
            # No explicit timeout, inject one
            return script.replace("def exploit(", "def exploit(\n    # Modified: added timeout\n")
        
        for match in reversed(matches):
            current = int(match.group(1))
            new_val = min(self.timeout_range[1], current + 10) if increase else max(self.timeout_range[0], current - 10)
            script = script[:match.start(1)] + str(new_val) + script[match.end(1):]
        return script
    
    def _toggle_ssl_verify(self, script: str) -> str:
        """Toggle verify=True/False in requests or similar."""
        if "verify=False" in script:
            return script.replace("verify=False", "verify=True")
        elif "verify=True" in script:
            return script.replace("verify=True", "verify=False")
        else:
            # Inject verify=False if requests is used
            if "requests." in script:
                return script.replace("requests.get(", "requests.get(verify=False, ").replace("requests.post(", "requests.post(verify=False, ")
        return script
    
    def _add_retry_logic(self, script: str) -> str:
        """Wrap main exploit logic in a retry loop."""
        # DISABLED: Causes indentation errors in Python 3.4
        # The modification breaks Python 3.4 syntax
        return script
    
    def _change_payload_encoding(self, script: str) -> str:
        """Switch between URL encoding, base64, or plain text payloads."""
        if "urllib.parse.quote" in script:
            return script.replace("urllib.parse.quote(", "# Agent removed encoding: (")
        elif "base64.b64encode" in script:
            return script.replace("base64.b64encode(", "# Agent removed base64: (")
        else:
            # Try to add URL encoding to any string payloads
            if 'payload = "' in script:
                return script.replace('payload = "', 'import urllib.parse\n    payload = urllib.parse.quote("')
        return script
    
    def _adjust_delay(self, script: str) -> str:
        """Modify time.sleep() values."""
        pattern = r"time\.sleep\((\d+\.?\d*)\)"
        matches = list(re.finditer(pattern, script))
        if not matches:
            return script
        
        for match in reversed(matches):
            current = float(match.group(1))
            new_val = max(0.1, current * 0.5)  # Reduce delay by half
            script = script[:match.start(1)] + f"{new_val:.1f}" + script[match.end(1):]
        return script
    
    def _modify_connection_params(self, script: str) -> str:
        """Adjust socket or connection settings."""
        # DISABLED: Causes syntax errors (inserts code after closing paren)
        # The modification breaks Python 3.4 syntax
        return script
    
    # --- Feature extraction ---
    
    def _extract_timeout(self, script: str) -> float:
        """Extract timeout value from script."""
        match = re.search(r"timeout\s*=\s*(\d+)", script, re.IGNORECASE)
        return float(match.group(1)) if match else 30.0
    
    def _has_ssl_verify(self, script: str) -> bool:
        """Check if SSL verification is enabled."""
        return "verify=True" in script or ("requests." in script and "verify=False" not in script)
    
    def _count_retries(self, script: str) -> float:
        """Count retry loops in script."""
        return float(script.count("for retry") + script.count("while retry"))
    
    def _estimate_payload_size(self, script: str) -> float:
        """Estimate payload size from script."""
        match = re.search(r'payload\s*=\s*["\'](.+?)["\']', script, re.DOTALL)
        if match:
            return float(len(match.group(1)))
        return 0.0
    
    def render(self, mode: str = "human") -> Optional[str]:
        """Render environment state for debugging."""
        if mode == "human":
            status = f"""
=== ExploitScriptEnv ===
Vuln ID: {self.vuln.get('vuln_id')}
Modifications: {self.modification_count}/{self.max_modifications}
Best Reward: {self.best_reward:.2f}
Executions: {len(self.execution_history)}
Last Success: {self.execution_history[-1].get('success') if self.execution_history else 'N/A'}
""".strip()
            return status
        return None
    
    def get_final_script(self) -> str:
        """Return the best modified script after training."""
        return self.current_script
    
    def get_best_result(self) -> Optional[Dict[str, Any]]:
        """Return the execution result with highest reward."""
        if not self.execution_history:
            return None
        # Find the result with success=True, or highest evidence length
        successes = [r for r in self.execution_history if r.get("success")]
        if successes:
            return successes[-1]
        return max(self.execution_history, key=lambda r: len(r.get("evidence") or ""))
