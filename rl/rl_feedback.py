"""Integration layer between PPO agent, LLM, and RAG memory system."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("auvap.rl.rl_feedback")

try:
    from rag.memory_system import RAGMemorySystem
    RAG_AVAILABLE = True
except (ImportError, OSError) as e:
    logger.warning("RAG memory system unavailable: %s", e)
    RAGMemorySystem = None  # type: ignore
    RAG_AVAILABLE = False

from rl.ppo_agent import PPOScriptAgent
from rl.script_env import ExploitScriptEnv
from rl.remote_executor import RemoteVMExecutor


class RLFeedbackLoop:
    """
    Manages bidirectional feedback between PPO agent and LLM/RAG system.
    
    - Agent modifies scripts and executes them
    - Results are stored in RAG for future retrieval
    - LLM receives structured feedback about what worked/failed
    - Agent learns from both immediate rewards and RAG-retrieved patterns
    """
    
    def __init__(
        self,
        ppo_agent: PPOScriptAgent,
        rag_memory: Optional[Any] = None,
        llm_client: Optional[Any] = None,
        remote_executor: Optional[RemoteVMExecutor] = None,
    ):
        self.ppo_agent = ppo_agent
        self.rag_memory = rag_memory
        self.llm_client = llm_client
        self.remote_executor = remote_executor
        
        if self.rag_memory is None:
            logger.warning("Running without RAG memory - results won't be persisted")
        
    def train_with_feedback(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        total_timesteps: int = 10_000,
        checkpoint_freq: int = 1000,
    ) -> Dict[str, Any]:
        """
        Train PPO agent on a single vulnerability with RAG/LLM feedback integration.
        
        Each training episode:
        1. Agent modifies script and executes
        2. Results stored in RAG
        3. Agent observes reward + RAG-retrieved similar attempts
        4. LLM receives structured feedback about modifications
        """
        
        # Create training environment (with remote VM executor if configured)
        env = ExploitScriptEnv(vuln, initial_script, max_modifications=10, remote_executor=self.remote_executor)
        
        # Retrieve relevant past experience from RAG (if available)
        rag_context = {}
        if self.rag_memory is not None:
            rag_context = self.rag_memory.retrieve_relevant_experience(vuln, top_k=5)
            logger.info(
                "RAG context | successes=%s failures=%s lessons=%s",
                len(rag_context.get("successful_examples", [])),
                len(rag_context.get("failed_examples", [])),
                len(rag_context.get("lessons", [])),
            )
        else:
            logger.info("Training without RAG context")
        
        # Create or load model
        if self.ppo_agent.model is None:
            self.ppo_agent.create_model(env, model_name=f"ppo_{vuln.get('vuln_id')}")
        
        # Train with checkpointing
        self.ppo_agent.train(
            total_timesteps=total_timesteps,
            checkpoint_freq=checkpoint_freq,
            model_name=f"ppo_{vuln.get('vuln_id')}",
        )
        
        # After training, run inference to get best script
        improvement_result = self.ppo_agent.improve_script(
            vuln, initial_script, max_modifications=10, deterministic=True
        )
        
        # Store final result in RAG (if available)
        best_result = improvement_result.get("best_result")
        final_script = improvement_result.get("final_script")
        
        if best_result and final_script and self.rag_memory is not None:
            self.rag_memory.store_execution_feedback(vuln, final_script, best_result)
            logger.info(
                "Stored RL-improved script in RAG | success=%s reward=%.2f",
                best_result.get("success"),
                improvement_result.get("best_reward"),
            )
        
        # Send feedback to LLM (if available)
        if self.llm_client:
            self._send_llm_feedback(vuln, initial_script, final_script, improvement_result)
        
        return improvement_result
    
    def improve_script_with_rag_guidance(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        max_modifications: int = 10,
    ) -> Dict[str, Any]:
        """
        Use trained agent to improve script, guided by RAG-retrieved experience.
        
        This is inference mode after training is complete.
        """
        
        # Retrieve similar past exploits (if RAG available)
        rag_context = {}
        if self.rag_memory is not None:
            rag_context = self.rag_memory.retrieve_relevant_experience(vuln, top_k=5)
        
        # Check if we have strong evidence of what works
        successful_examples = rag_context.get("successful_examples", [])
        if successful_examples:
            logger.info("Found %s successful examples in RAG", len(successful_examples))
            # Could inject RAG hints into script or observation here
        
        # Create environment with remote executor
        env = ExploitScriptEnv(vuln, initial_script, max_modifications=max_modifications, remote_executor=self.remote_executor)
        
        # Run agent inference
        improvement_result = self._run_inference_on_env(env, max_modifications)
        
        # Extract results
        final_script = env.get_final_script()
        best_result = env.get_best_result()
        
        improvement_result = {
            "final_script": final_script,
            "best_result": best_result,
            "modification_count": env.modification_count,
            "success": best_result.get("success") if best_result else False,
            "best_reward": env.best_reward,
        }
        
        # Store result in RAG (if available)
        best_result = improvement_result.get("best_result")
        final_script = improvement_result.get("final_script")
        
        if best_result and final_script and self.rag_memory is not None:
            self.rag_memory.store_execution_feedback(vuln, final_script, best_result)
        
        # Attach RAG context to result for transparency
        improvement_result["rag_context"] = {
            "successful_examples_count": len(successful_examples),
            "failed_examples_count": len(rag_context.get("failed_examples", [])),
            "lessons_count": len(rag_context.get("lessons", [])),
        }
        
        return improvement_result
    
    def _send_llm_feedback(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        final_script: str,
        improvement_result: Dict[str, Any],
    ) -> None:
        """Send structured feedback to LLM about RL modifications."""
        
        if not self.llm_client or not hasattr(self.llm_client, "call_with_json_response"):
            logger.warning("LLM client unavailable or unsupported for feedback")
            return
        
        feedback_prompt = self._build_llm_feedback_prompt(
            vuln, initial_script, final_script, improvement_result
        )
        
        try:
            response = self.llm_client.call_with_json_response(
                prompt=feedback_prompt,
                temperature=0.3,
                max_tokens=500,
            )
            logger.info("LLM feedback response: %s", response)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to send LLM feedback: %s", exc)
    
    def _build_llm_feedback_prompt(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        final_script: str,
        improvement_result: Dict[str, Any],
    ) -> str:
        """Build feedback prompt for LLM."""
        
        success = improvement_result.get("success", False)
        modifications = improvement_result.get("modification_count", 0)
        best_reward = improvement_result.get("best_reward", 0.0)
        
        return f"""
Reinforcement learning agent modified exploit script for {vuln.get('vuln_id')}.

Target: {vuln.get('service')} v{vuln.get('version')} on port {vuln.get('port')}
Modifications applied: {modifications}
Final success: {success}
Best reward: {best_reward:.2f}

Initial script length: {len(initial_script)} chars
Final script length: {len(final_script)} chars

Key changes made by RL agent:
{self._extract_script_diff_summary(initial_script, final_script)}

Please analyze these modifications and provide:
1. Assessment of RL agent's approach
2. Recommended improvements for future attempts
3. Patterns to remember for similar vulnerabilities

Return JSON:
{{
  "agent_assessment": "...",
  "recommended_improvements": ["..."],
  "patterns_to_remember": ["..."]
}}
""".strip()
    
    def _extract_script_diff_summary(self, initial: str, final: str) -> str:
        """Extract high-level summary of script changes."""
        
        changes = []
        
        if "timeout" in final and "timeout" not in initial:
            changes.append("- Added timeout parameter")
        if "verify=False" in final and "verify=False" not in initial:
            changes.append("- Disabled SSL verification")
        if "retry" in final and "retry" not in initial:
            changes.append("- Added retry logic")
        if final.count("time.sleep") < initial.count("time.sleep"):
            changes.append("- Reduced delays")
        if final.count("try:") > initial.count("try:"):
            changes.append("- Added error handling")
        
        if not changes:
            changes.append("- Modified script parameters")
        
        return "\n".join(changes)
    
    def _run_inference_on_env(self, env: ExploitScriptEnv, max_modifications: int) -> Dict[str, Any]:
        """Run PPO inference on environment."""
        
        if self.ppo_agent.model is None:
            raise RuntimeError("Model not initialized")
        
        obs, info = env.reset()
        done = False
        step_count = 0
        
        while not done and step_count < max_modifications:
            action, _ = self.ppo_agent.predict(obs, deterministic=True)
            obs, reward, terminated, truncated, info = env.step(int(action))
            done = terminated or truncated
            step_count += 1
        
        return {
            "modification_count": step_count,
            "best_reward": env.best_reward,
        }
