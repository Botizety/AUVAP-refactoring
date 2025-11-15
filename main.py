"""Main pipeline orchestration for AUVAP."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.config_loader import ConfigurationError, load_context_rules
from execution.executor import ExecutionError, execute_exploit_script
from execution.validator import validate_exploit_script
from llm.llm_classifier import classify_and_prioritize_vulnerabilities
from llm.llm_script_generator import generate_exploit_scripts
from llm.openrouter_client import DEFAULT_MODEL as OPENROUTER_DEFAULT_MODEL, OpenRouterClient
from llm.gemini_client import DEFAULT_GEMINI_MODEL, GeminiClient
from parsers.nessus_parser import parse_nessus_file
from rag.memory_system import create_memory_system
from reporting.report_generator import generate_report
from utils.logging_config import setup_logging


def run_auvap_pipeline(
    nessus_file: str,
    config_file: str,
    provider: str,
    api_key: str | None,
    model_name: str | None,
    gemini_api_key: str | None,
    gemini_model: str | None,
    rag_dir: str,
    output_format: str,
    output_path: str | None,
    dry_run: bool,
    verbose: bool,
    rl_mode: str = "off",
    rl_timesteps: int = 10_000,
    rl_checkpoint_dir: str = "./rl/checkpoints",
) -> Dict[str, Any]:
    """Complete pipeline from Nessus parsing to reporting."""

    logger = setup_logging(log_level="DEBUG" if verbose else "INFO")
    logger.info("Starting AUVAP pipeline | RL mode: %s", rl_mode)

    # Initialize RAG memory (falls back to JSON persistence if vector store unavailable)
    rag_memory = create_memory_system(persist_directory=rag_dir)
    
    llm_client = _build_llm_client(
        provider=provider,
        openrouter_api_key=api_key,
        openrouter_model=model_name,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
    )

    findings = parse_nessus_file(nessus_file)
    logger.info("Parsed %s findings from Nessus file", len(findings))

    context_rules = load_context_rules(config_file)
    logger.info("Loaded context rules for %s", context_rules.get("company_name"))

    classifications = classify_and_prioritize_vulnerabilities(findings, context_rules, llm_client)
    vulnerabilities = classifications.get("vulnerabilities", [])
    logger.info("LLM classified %s remote exploitable findings", len(vulnerabilities))

    # Generate intermediate classification report (exploitable vulnerabilities only)
    classification_report_data = {
        "scan_metadata": {"timestamp": Path(nessus_file).stat().st_mtime},
        "total_findings": len(findings),
        "remote_exploitable_count": classifications.get("remote_exploitable_count", 0),
        "filtered_out_count": classifications.get("filtered_out_count", 0),
        "vulnerabilities": vulnerabilities,
    }
    classification_output = _get_intermediate_output_path(output_path, "classification")
    _write_simple_report(classification_report_data, classification_output)
    logger.info("Classification report written to %s", classification_output)

    rag_enriched = generate_exploit_scripts(vulnerabilities, context_rules, rag_memory, llm_client)
    logger.info("Generated scripts for %s vulnerabilities", len(rag_enriched))

    # Generate intermediate script generation report (only exploitable vulnerabilities with scripts)
    script_report_data = {
        "scan_metadata": {
            "timestamp": Path(nessus_file).stat().st_mtime,
            "scan_file": Path(nessus_file).name
        },
        "total_findings": len(findings),
        "remote_exploitable_count": len(vulnerabilities),
        "scripts_generated": len(rag_enriched),
        "vulnerabilities_with_scripts": rag_enriched
    }
    script_output = _get_intermediate_output_path(output_path, "scripts")
    _write_simple_report(script_report_data, script_output)
    logger.info("Script generation report written to %s", script_output)

    # Reinforcement learning integration
    if rl_mode in ("train", "inference"):
        logger.info("Initializing PPO agent for RL mode: %s", rl_mode)
        from rl.ppo_agent import PPOScriptAgent
        from rl.rl_feedback import RLFeedbackLoop
        from rl.remote_executor import create_remote_executor_from_env
        
        ppo_agent = PPOScriptAgent(checkpoint_dir=rl_checkpoint_dir, device="auto")
        
        # Initialize remote VM executor if configured
        remote_executor = create_remote_executor_from_env()
        if remote_executor:
            logger.info("Remote VM executor enabled - scripts will run on VM")
            try:
                remote_executor.connect()
            except Exception as exc:
                logger.error("Failed to connect to remote VM: %s", exc)
                raise SystemExit("Remote VM connection required but failed") from exc
        else:
            logger.info("Using local execution (set RL_VM_HOST to enable remote VM)")
        
        feedback_loop = RLFeedbackLoop(ppo_agent, rag_memory, llm_client, remote_executor=remote_executor)
        
        if rl_mode == "train":
            logger.info("Training PPO agent on %s vulnerabilities", len(rag_enriched))
            for vuln in rag_enriched:
                script_text = vuln.get("script_generation", {}).get("exploit_script")
                if not script_text:
                    continue
                try:
                    feedback_loop.train_with_feedback(
                        vuln=vuln,
                        initial_script=script_text,
                        total_timesteps=rl_timesteps,
                        checkpoint_freq=1000,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error("RL training failed for %s: %s", vuln.get("vuln_id"), exc)
        else:  # inference
            logger.info("Running RL inference on %s vulnerabilities", len(rag_enriched))
            latest_checkpoint = ppo_agent.get_latest_checkpoint()
            if latest_checkpoint:
                ppo_agent.load_model(str(latest_checkpoint))
                logger.info("Loaded checkpoint: %s", latest_checkpoint)
            else:
                logger.warning("No checkpoint found, skipping RL inference")

    execution_results: List[Dict[str, Any]] = []
    if not dry_run:
        for vuln in rag_enriched:
            script_info = vuln.get("script_generation", {})
            script_text = script_info.get("exploit_script")
            if not script_text:
                logger.warning("No script for %s", vuln.get("vuln_id"))
                continue
            
            # Apply RL improvements if in inference mode
            if rl_mode == "inference":
                try:
                    from rl.rl_feedback import RLFeedbackLoop
                    improvement = feedback_loop.improve_script_with_rag_guidance(
                        vuln=vuln,
                        initial_script=script_text,
                        max_modifications=10,
                    )
                    if improvement.get("success"):
                        script_text = improvement.get("final_script")
                        logger.info("RL improved script for %s", vuln.get("vuln_id"))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("RL improvement failed for %s: %s", vuln.get("vuln_id"), exc)
            
            validation = validate_exploit_script(script_text)
            if not validation["valid"]:
                logger.error("Script validation failed for %s: %s", vuln.get("vuln_id"), validation)
                continue
            try:
                result = execute_exploit_script(vuln, script_text)
            except ExecutionError as exc:
                logger.error("Execution failed for %s: %s", vuln.get("vuln_id"), exc)
                continue
            execution_results.append({"vuln_id": vuln.get("vuln_id"), **result})
            rag_memory.store_execution_feedback(vuln, script_text, result)

    report_data = {
        "scan_metadata": {"timestamp": Path(nessus_file).stat().st_mtime},
        "context_rules": context_rules,
        "total_findings": len(findings),
        "findings": findings,
        "classified_vulnerabilities": classifications,
        "vulnerabilities_with_scripts": rag_enriched,
        "execution_results": execution_results,
        "rag_statistics": rag_memory.get_statistics(),
    }
    report = generate_report(report_data, output_format=output_format, output_path=output_path)
    logger.info("Report written to %s", report["output_file"])
    return report


def _write_simple_report(data: Dict[str, Any], output_path: Optional[str]) -> None:
    """Write a simple JSON report without full report generator overhead."""
    if not output_path:
        output_path = "reports/classification_report.json"
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _get_intermediate_output_path(output_path: Optional[str], stage: str) -> Optional[str]:
    """Generate intermediate report path by inserting stage suffix before extension."""
    if not output_path:
        return None
    path = Path(output_path)
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    return str(parent / f"{stem}_{stage}{suffix}")


def _build_llm_client(
    provider: str,
    openrouter_api_key: Optional[str],
    openrouter_model: Optional[str],
    gemini_api_key: Optional[str],
    gemini_model: Optional[str],
):
    normalized_provider = (provider or "openrouter").lower()
    if normalized_provider == "gemini":
        resolved_key = gemini_api_key or os.environ.get("GEMINI_API_KEY")
        if not resolved_key:
            raise SystemExit("Gemini API key is required but missing")
        resolved_model = gemini_model or os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
        return GeminiClient(api_key=resolved_key, default_model=resolved_model)

    resolved_key = openrouter_api_key or os.environ.get("OPENROUTER_API_KEY")
    if not resolved_key:
        raise SystemExit("OpenRouter API key is required but missing")
    resolved_model = openrouter_model or os.environ.get("OPENROUTER_MODEL") or OPENROUTER_DEFAULT_MODEL
    return OpenRouterClient(api_key=resolved_key, default_model=resolved_model)


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AUVAP pipeline")
    parser.add_argument("--nessus", required=True, help="Path to Nessus .nessus file")
    parser.add_argument("--config", required=True, help="Path to context rules JSON")
    parser.add_argument("--api-key", default=os.environ.get("OPENROUTER_API_KEY"), help="OpenRouter API key")
    parser.add_argument(
        "--provider",
        default=os.environ.get("LLM_PROVIDER", "openrouter"),
        choices=["openrouter", "gemini"],
        help="LLM provider to use (defaults to LLM_PROVIDER env var or openrouter)",
    )
    parser.add_argument("--rag-dir", default="./rag_memory", help="RAG persistence directory")
    parser.add_argument(
        "--model",
        default=os.environ.get("OPENROUTER_MODEL"),
        help="OpenRouter model ID (defaults to OPENROUTER_MODEL env var or built-in choice)",
    )
    parser.add_argument("--gemini-api-key", default=os.environ.get("GEMINI_API_KEY"), help="Google Gemini API key")
    parser.add_argument(
        "--gemini-model",
        default=os.environ.get("GEMINI_MODEL"),
        help="Gemini model ID (defaults to GEMINI_MODEL env var or built-in choice)",
    )
    parser.add_argument("--output", default=None, help="Output path for the report")
    parser.add_argument("--format", default="json", choices=["json", "html", "markdown"], help="Report format")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--dry-run", action="store_true", help="Skip exploit execution")
    parser.add_argument("--rl-mode", choices=["train", "inference", "off"], default="off", help="Reinforcement learning mode: train PPO agent, run inference, or disable (default: off)")
    parser.add_argument("--rl-timesteps", type=int, default=10_000, help="Total timesteps for PPO training per vulnerability")
    parser.add_argument("--rl-checkpoint-dir", default="./rl/checkpoints", help="Directory for PPO model checkpoints")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    provider = (args.provider or "openrouter").lower()
    if provider == "gemini":
        if not args.gemini_api_key:
            raise SystemExit("Gemini API key must be provided via --gemini-api-key or GEMINI_API_KEY")
    else:
        if not args.api_key:
            raise SystemExit("OpenRouter API key must be provided via --api-key or OPENROUTER_API_KEY")
    run_auvap_pipeline(
        nessus_file=args.nessus,
        config_file=args.config,
        provider=provider,
        api_key=args.api_key,
        model_name=args.model,
        gemini_api_key=args.gemini_api_key,
        gemini_model=args.gemini_model,
        rag_dir=args.rag_dir,
        output_format=args.format,
        output_path=args.output,
        dry_run=args.dry_run,
        verbose=args.verbose,
        rl_mode=args.rl_mode,
        rl_timesteps=args.rl_timesteps,
        rl_checkpoint_dir=args.rl_checkpoint_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
