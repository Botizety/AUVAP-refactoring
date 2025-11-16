"""Two-Phase Training: LLM Regeneration + PPO Fine-Tuning.

This module orchestrates the complete two-phase training approach:
- Phase A: Use LLM to regenerate broken scripts based on error messages
- Phase B: Use PPO to fine-tune working scripts for optimization

Usage:
    python -m rl.two_phase_trainer --vulnerabilities reports/classification_report.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm.gemini_client import GeminiClient
from llm.openrouter_client import OpenRouterClient
from rag.memory_system import create_memory_system
from rl.phase_a_llm_regeneration import PhaseARegenerator
from rl.ppo_agent import PPOScriptAgent
from rl.remote_executor import create_remote_executor_from_env
from rl.rl_feedback import RLFeedbackLoop
from rl.script_env import ExploitScriptEnv
from utils.logging_config import setup_logging

logger = logging.getLogger("auvap.rl.two_phase")


class TwoPhaseTrainer:
    """
    Orchestrates two-phase training approach:
    1. Phase A: LLM regenerates scripts until they work
    2. Phase B: PPO optimizes working scripts for better success rate
    """

    def __init__(
        self,
        llm_client: Any,
        rag_dir: str,
        checkpoint_dir: str,
        device: str = "auto",
        remote_executor: Optional[Any] = None,
        phase_a_max_attempts: int = 5,
        phase_b_timesteps: int = 2000,
    ):
        self.llm_client = llm_client
        self.rag_memory = create_memory_system(persist_directory=rag_dir)
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.device = device
        self.remote_executor = remote_executor
        self.phase_a_max_attempts = phase_a_max_attempts
        self.phase_b_timesteps = phase_b_timesteps

        # Initialize Phase A regenerator
        self.phase_a = PhaseARegenerator(
            llm_client=llm_client,
            rag_memory=self.rag_memory,
            remote_executor=remote_executor,
            max_regeneration_attempts=phase_a_max_attempts,
        )

        # Initialize Phase B PPO agent (will be created per-vulnerability)
        self.ppo_agent = PPOScriptAgent(
            checkpoint_dir=str(self.checkpoint_dir),
            device=device,
        )

        # Initialize feedback loop
        self.feedback_loop = RLFeedbackLoop(
            ppo_agent=self.ppo_agent,
            rag_memory=self.rag_memory,
            llm_client=llm_client,
            remote_executor=remote_executor,
        )

    def train_on_vulnerability(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        context_rules: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Train on a single vulnerability using two-phase approach.

        Returns:
            {
                "vuln_id": str,
                "phase_a_result": Dict,  # LLM regeneration results
                "phase_b_result": Dict,  # PPO optimization results (if Phase A succeeded)
                "final_script": str,
                "final_success": bool,
            }
        """

        vuln_id = vuln.get("vuln_id")
        logger.info("=" * 80)
        logger.info("Two-Phase Training | Starting for %s", vuln_id)
        logger.info("=" * 80)

        # ============================================================
        # PHASE A: LLM REGENERATION UNTIL SCRIPT WORKS
        # ============================================================
        logger.info("PHASE A | Starting LLM-based regeneration for %s", vuln_id)

        phase_a_result = self.phase_a.regenerate_until_working(
            vuln=vuln,
            initial_script=initial_script,
            context_rules=context_rules,
        )

        # Store Phase A results in RAG
        if self.rag_memory and phase_a_result.get("final_script"):
            best_result = (
                phase_a_result["execution_results"][-1]
                if phase_a_result.get("execution_results")
                else {}
            )
            try:
                self.rag_memory.store_execution_feedback(
                    vuln,
                    phase_a_result["final_script"],
                    best_result,
                )
                logger.info("PHASE A | Stored results in RAG memory")
            except Exception as exc:
                logger.warning("PHASE A | Failed to store in RAG: %s", exc)

        # Check if Phase A succeeded
        if not phase_a_result.get("success"):
            logger.warning(
                "PHASE A | Failed to fix script for %s after %s attempts",
                vuln_id,
                phase_a_result.get("attempts"),
            )
            return {
                "vuln_id": vuln_id,
                "phase_a_result": phase_a_result,
                "phase_b_result": None,
                "final_script": phase_a_result["final_script"],
                "final_success": False,
                "phase_completed": "A_only",
            }

        working_script = phase_a_result["final_script"]
        logger.info(
            "PHASE A | SUCCESS! Script is now working after %s attempts",
            phase_a_result.get("attempts"),
        )

        # Check if script already achieved full success in Phase A
        last_exec = phase_a_result["execution_results"][-1]
        if last_exec.get("success"):
            logger.info("PHASE A | Script already fully successful, skipping Phase B")
            return {
                "vuln_id": vuln_id,
                "phase_a_result": phase_a_result,
                "phase_b_result": None,
                "final_script": working_script,
                "final_success": True,
                "phase_completed": "A_only_success",
            }

        # ============================================================
        # PHASE B: PPO FINE-TUNING FOR OPTIMIZATION
        # ============================================================
        logger.info("PHASE B | Starting PPO fine-tuning for %s", vuln_id)
        logger.info(
            "PHASE B | Working script status: success=%s, evidence_length=%s",
            last_exec.get("success"),
            len(last_exec.get("evidence") or ""),
        )

        # Create environment for working script
        env = ExploitScriptEnv(
            vuln=vuln,
            initial_script=working_script,
            max_modifications=50,  # More modifications for fine-tuning
            remote_executor=self.remote_executor,
        )

        # Create PPO model for this vulnerability
        self.ppo_agent.create_model(env, model_name=f"ppo_phase_b_{vuln_id}")

        # Train with PPO
        logger.info(
            "PHASE B | Training PPO for %s timesteps", self.phase_b_timesteps
        )
        self.ppo_agent.train(
            total_timesteps=self.phase_b_timesteps,
            checkpoint_freq=500,
            model_name=f"ppo_phase_b_{vuln_id}",
        )

        # Run inference to get optimized script
        phase_b_result = self.ppo_agent.improve_script(
            vuln=vuln,
            initial_script=working_script,
            max_modifications=50,
            deterministic=True,
        )

        # Store Phase B results in RAG
        if self.rag_memory and phase_b_result.get("final_script"):
            try:
                self.rag_memory.store_execution_feedback(
                    vuln,
                    phase_b_result["final_script"],
                    phase_b_result.get("best_result", {}),
                )
                logger.info("PHASE B | Stored results in RAG memory")
            except Exception as exc:
                logger.warning("PHASE B | Failed to store in RAG: %s", exc)

        logger.info(
            "PHASE B | Complete | success=%s reward=%.2f modifications=%s",
            phase_b_result.get("success"),
            phase_b_result.get("best_reward", 0.0),
            phase_b_result.get("modification_count"),
        )

        return {
            "vuln_id": vuln_id,
            "phase_a_result": phase_a_result,
            "phase_b_result": phase_b_result,
            "final_script": phase_b_result.get("final_script") or working_script,
            "final_success": phase_b_result.get("success", False),
            "phase_completed": "both",
        }

    def train_on_dataset(
        self,
        vulnerabilities: List[Dict[str, Any]],
        context_rules: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Train on multiple vulnerabilities using two-phase approach."""

        results = []

        for idx, vuln in enumerate(vulnerabilities):
            vuln_id = vuln.get("vuln_id")
            script_info = vuln.get("script_generation", {})
            initial_script = script_info.get("exploit_script")

            if not initial_script:
                logger.warning("Skipping %s: no initial script", vuln_id)
                continue

            logger.info(
                "Processing %s/%s: %s", idx + 1, len(vulnerabilities), vuln_id
            )

            try:
                result = self.train_on_vulnerability(
                    vuln=vuln,
                    initial_script=initial_script,
                    context_rules=context_rules,
                )
                results.append(result)

            except Exception as exc:
                logger.error("Training failed for %s: %s", vuln_id, exc, exc_info=True)
                results.append({
                    "vuln_id": vuln_id,
                    "error": str(exc),
                    "final_success": False,
                })

        # Summarize results
        total = len(results)
        phase_a_success = sum(
            1 for r in results if r.get("phase_a_result", {}).get("success")
        )
        phase_b_run = sum(1 for r in results if r.get("phase_b_result") is not None)
        final_success = sum(1 for r in results if r.get("final_success"))

        summary = {
            "total_vulnerabilities": total,
            "phase_a_success_count": phase_a_success,
            "phase_b_run_count": phase_b_run,
            "final_success_count": final_success,
            "success_rate": final_success / total if total > 0 else 0.0,
            "results": results,
        }

        logger.info("=" * 80)
        logger.info("Two-Phase Training Complete")
        logger.info("Total: %s | Phase A Success: %s | Phase B Run: %s | Final Success: %s",
                   total, phase_a_success, phase_b_run, final_success)
        logger.info("Success Rate: %.1f%%", summary["success_rate"] * 100)
        logger.info("=" * 80)

        return summary


def load_context_rules(config_path: str = "config/context_rules.yaml") -> Dict[str, Any]:
    """Load context rules from YAML file."""
    import yaml

    try:
        with open(config_path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Context rules file not found, using defaults")
        return {
            "company_name": "AUVAP Labs",
            "environment": "Metasploitable 2",
            "exploitation_constraints": {},
            "safety_constraints": {},
        }


def main(argv: List[str] | None = None) -> int:
    """CLI entry point for two-phase training."""

    parser = argparse.ArgumentParser(
        description="Two-Phase Training: LLM Regeneration + PPO Fine-Tuning"
    )
    parser.add_argument(
        "--vulnerabilities",
        required=True,
        help="Path to vulnerabilities JSON with generated scripts",
    )
    parser.add_argument(
        "--context-rules",
        default="config/context_rules.yaml",
        help="Path to context rules YAML",
    )
    parser.add_argument(
        "--rag-dir", default="./rag_memory", help="RAG persistence directory"
    )
    parser.add_argument(
        "--checkpoint-dir",
        default="./rl/checkpoints_two_phase",
        help="Directory for model checkpoints",
    )
    parser.add_argument(
        "--output",
        default="./reports/two_phase_results.json",
        help="Output path for results",
    )
    parser.add_argument(
        "--phase-a-attempts",
        type=int,
        default=5,
        help="Max LLM regeneration attempts in Phase A",
    )
    parser.add_argument(
        "--phase-b-timesteps",
        type=int,
        default=2000,
        help="PPO training timesteps in Phase B",
    )
    parser.add_argument(
        "--device", default="auto", help="Device for training (auto, cpu, cuda)"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args(argv or sys.argv[1:])

    setup_logging(log_level="DEBUG" if args.verbose else "INFO")

    # Load vulnerabilities
    with open(args.vulnerabilities, encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = (
        data.get("vulnerabilities_with_scripts")
        or data.get("vulnerabilities")
        or []
    )

    if not vulnerabilities:
        logger.error("No vulnerabilities found in %s", args.vulnerabilities)
        return 1

    logger.info("Loaded %s vulnerabilities", len(vulnerabilities))

    # Load context rules
    context_rules = load_context_rules(args.context_rules)

    # Initialize LLM client (try Gemini, fallback to OpenRouter)
    try:
        llm_client = GeminiClient()
        logger.info("Using Gemini LLM client")
    except Exception as exc:
        logger.warning("Gemini client unavailable (%s), trying OpenRouter", exc)
        try:
            llm_client = OpenRouterClient()
            logger.info("Using OpenRouter LLM client")
        except Exception as exc2:
            logger.error("No LLM client available: %s", exc2)
            return 1

    # Initialize remote executor
    remote_executor = create_remote_executor_from_env()
    if remote_executor:
        logger.info("Remote VM executor enabled")
        remote_executor.connect()
    else:
        logger.warning("Remote executor not configured, using local execution")

    # Initialize two-phase trainer
    trainer = TwoPhaseTrainer(
        llm_client=llm_client,
        rag_dir=args.rag_dir,
        checkpoint_dir=args.checkpoint_dir,
        device=args.device,
        remote_executor=remote_executor,
        phase_a_max_attempts=args.phase_a_attempts,
        phase_b_timesteps=args.phase_b_timesteps,
    )

    # Run two-phase training
    summary = trainer.train_on_dataset(
        vulnerabilities=vulnerabilities,
        context_rules=context_rules,
    )

    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    logger.info("Results saved to %s", output_path)

    # Disconnect remote executor
    if remote_executor:
        remote_executor.disconnect()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
