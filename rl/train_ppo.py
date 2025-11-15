"""Training harness for PPO agent on exploit script dataset."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from rag.memory_system import create_memory_system

from rl.ppo_agent import PPOScriptAgent
from rl.rl_feedback import RLFeedbackLoop
from rl.script_env import ExploitScriptEnv
from rl.remote_executor import create_remote_executor_from_env
from utils.logging_config import setup_logging

logger = logging.getLogger("auvap.rl.train_ppo")


def train_ppo_on_dataset(
    vulnerabilities: List[Dict[str, Any]],
    rag_dir: str,
    checkpoint_dir: str,
    total_timesteps: int = 10_000,
    checkpoint_freq: int = 1000,
    device: str = "auto",
    llm_client: Any = None,
) -> Dict[str, Any]:
    """
    Train PPO agent across multiple vulnerabilities.
    
    For each vulnerability with a generated script:
    1. Initialize environment with initial LLM-generated script
    2. Train PPO agent to improve script via modifications
    3. Store results in RAG memory
    4. Send feedback to LLM
    5. Checkpoint agent periodically
    """
    
    # Initialize RAG memory (falls back automatically if vector backend missing)
    rag_memory: Optional[Any] = create_memory_system(persist_directory=rag_dir)
    
    ppo_agent = PPOScriptAgent(checkpoint_dir=checkpoint_dir, device=device)
    
    # Initialize remote VM executor if configured
    remote_executor = create_remote_executor_from_env()
    if remote_executor:
        logger.info("Remote VM executor enabled for training")
        remote_executor.connect()
    else:
        logger.info("Using local execution for training")
    
    feedback_loop = RLFeedbackLoop(ppo_agent, rag_memory, llm_client, remote_executor=remote_executor)
    
    training_results = []
    
    for idx, vuln in enumerate(vulnerabilities):
        vuln_id = vuln.get("vuln_id")
        script_info = vuln.get("script_generation", {})
        initial_script = script_info.get("exploit_script")
        
        if not initial_script:
            logger.warning("Skipping %s: no exploit script", vuln_id)
            continue
        
        logger.info("Training PPO on vulnerability %s/%s: %s", idx + 1, len(vulnerabilities), vuln_id)
        
        try:
            result = feedback_loop.train_with_feedback(
                vuln=vuln,
                initial_script=initial_script,
                total_timesteps=total_timesteps,
                checkpoint_freq=checkpoint_freq,
            )
            
            training_results.append({
                "vuln_id": vuln_id,
                "success": result.get("success"),
                "modification_count": result.get("modification_count"),
                "best_reward": result.get("best_reward"),
            })
            
            logger.info(
                "Training complete for %s | success=%s modifications=%s reward=%.2f",
                vuln_id,
                result.get("success"),
                result.get("modification_count"),
                result.get("best_reward", 0.0),
            )
            
        except Exception as exc:  # noqa: BLE001
            logger.error("Training failed for %s: %s", vuln_id, exc)
            training_results.append({
                "vuln_id": vuln_id,
                "success": False,
                "error": str(exc),
            })
    
    # Save training summary
    summary = {
        "total_vulnerabilities": len(vulnerabilities),
        "trained_on": len(training_results),
        "successful_improvements": sum(1 for r in training_results if r.get("success")),
        "results": training_results,
    }
    
    summary_path = Path(checkpoint_dir) / "training_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    
    logger.info("Training summary saved to %s", summary_path)
    return summary


def run_inference_mode(
    vulnerabilities: List[Dict[str, Any]],
    rag_dir: str,
    checkpoint_dir: str,
    output_path: str,
    device: str = "auto",
) -> Dict[str, Any]:
    """
    Run inference with trained PPO agent to improve scripts.
    
    Loads latest checkpoint and applies learned policy to new/existing scripts.
    """
    
    # Initialize RAG memory (falls back automatically if vector backend missing)
    rag_memory: Optional[Any] = create_memory_system(persist_directory=rag_dir)
    
    ppo_agent = PPOScriptAgent(checkpoint_dir=checkpoint_dir, device=device)
    
    # Load latest checkpoint
    latest_checkpoint = ppo_agent.get_latest_checkpoint()
    if not latest_checkpoint:
        raise FileNotFoundError(f"No checkpoints found in {checkpoint_dir}")
    
    ppo_agent.load_model(str(latest_checkpoint))
    logger.info("Loaded checkpoint: %s", latest_checkpoint)
    
    # Initialize remote VM executor if configured
    remote_executor = create_remote_executor_from_env()
    if remote_executor:
        logger.info("Remote VM executor enabled for inference")
        remote_executor.connect()
    else:
        logger.info("Using local execution for inference")
    
    feedback_loop = RLFeedbackLoop(ppo_agent, rag_memory, llm_client=None, remote_executor=remote_executor)
    
    inference_results = []
    
    for idx, vuln in enumerate(vulnerabilities):
        vuln_id = vuln.get("vuln_id")
        script_info = vuln.get("script_generation", {})
        initial_script = script_info.get("exploit_script")
        
        if not initial_script:
            logger.warning("Skipping %s: no exploit script", vuln_id)
            continue
        
        logger.info("Running inference on %s/%s: %s", idx + 1, len(vulnerabilities), vuln_id)
        
        try:
            result = feedback_loop.improve_script_with_rag_guidance(
                vuln=vuln,
                initial_script=initial_script,
                max_modifications=10,
            )
            
            inference_results.append({
                "vuln_id": vuln_id,
                "success": result.get("success"),
                "modification_count": result.get("modification_count"),
                "best_reward": result.get("best_reward"),
                "final_script": result.get("final_script"),
                "rag_context": result.get("rag_context"),
            })
            
            logger.info(
                "Inference complete for %s | success=%s modifications=%s",
                vuln_id,
                result.get("success"),
                result.get("modification_count"),
            )
            
        except Exception as exc:  # noqa: BLE001
            logger.error("Inference failed for %s: %s", vuln_id, exc)
            inference_results.append({
                "vuln_id": vuln_id,
                "success": False,
                "error": str(exc),
            })
    
    # Save inference results
    output = {
        "total_vulnerabilities": len(vulnerabilities),
        "processed": len(inference_results),
        "successful_exploits": sum(1 for r in inference_results if r.get("success")),
        "results": inference_results,
    }
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    logger.info("Inference results saved to %s", output_file)
    return output


def main(argv: List[str] | None = None) -> int:
    """CLI entry point for PPO training."""
    
    parser = argparse.ArgumentParser(description="Train or run inference with PPO exploit agent")
    parser.add_argument("--mode", choices=["train", "inference"], required=True, help="Training or inference mode")
    parser.add_argument("--vulnerabilities", required=True, help="Path to vulnerabilities JSON (with scripts)")
    parser.add_argument("--rag-dir", default="./rag_memory", help="RAG persistence directory")
    parser.add_argument("--checkpoint-dir", default="./rl/checkpoints", help="Directory for model checkpoints")
    parser.add_argument("--output", default="./rl/inference_results.json", help="Output path for inference results")
    parser.add_argument("--timesteps", type=int, default=10_000, help="Total training timesteps per vulnerability")
    parser.add_argument("--checkpoint-freq", type=int, default=1000, help="Checkpoint save frequency")
    parser.add_argument("--device", default="auto", help="Device for training (auto, cpu, cuda)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args(argv or sys.argv[1:])
    
    setup_logging(log_level="DEBUG" if args.verbose else "INFO")
    
    # Load vulnerabilities from JSON
    with open(args.vulnerabilities, encoding="utf-8") as f:
        data = json.load(f)
    
    # Handle different JSON structures
    vulnerabilities = data.get("vulnerabilities_with_scripts") or data.get("vulnerabilities") or []
    
    if not vulnerabilities:
        logger.error("No vulnerabilities found in %s", args.vulnerabilities)
        return 1
    
    logger.info("Loaded %s vulnerabilities from %s", len(vulnerabilities), args.vulnerabilities)
    
    if args.mode == "train":
        train_ppo_on_dataset(
            vulnerabilities=vulnerabilities,
            rag_dir=args.rag_dir,
            checkpoint_dir=args.checkpoint_dir,
            total_timesteps=args.timesteps,
            checkpoint_freq=args.checkpoint_freq,
            device=args.device,
        )
    else:  # inference
        run_inference_mode(
            vulnerabilities=vulnerabilities,
            rag_dir=args.rag_dir,
            checkpoint_dir=args.checkpoint_dir,
            output_path=args.output,
            device=args.device,
        )
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
