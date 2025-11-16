"""PPO agent for autonomous exploit script improvement via reinforcement learning."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback, CheckpointCallback, EvalCallback
from stable_baselines3.common.vec_env import DummyVecEnv

from rl.script_env import ExploitScriptEnv

logger = logging.getLogger("auvap.rl.ppo_agent")


class PPOScriptAgent:
    """
    Proximal Policy Optimization agent for learning to modify exploit scripts.
    
    Trains a policy network to choose script modifications that maximize exploit success.
    Integrates with AUVAP pipeline to persist results back to RAG memory and LLM feedback.
    """
    
    def __init__(
        self,
        checkpoint_dir: str = "./rl/checkpoints",
        tensorboard_log: str = "./rl/tensorboard",
        learning_rate: float = 1e-4,  # Lower for sparse reward tasks
        n_steps: int = 128,  # Match typical episode length (10-50 steps)
        batch_size: int = 32,  # Smaller for more frequent updates
        n_epochs: int = 10,
        gamma: float = 0.99,
        ent_coef: float = 0.05,  # Higher for more exploration
        device: str = "auto",
    ):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        self.tensorboard_log = tensorboard_log
        Path(self.tensorboard_log).mkdir(parents=True, exist_ok=True)
        
        self.learning_rate = learning_rate
        self.n_steps = n_steps
        self.batch_size = batch_size
        self.n_epochs = n_epochs
        self.gamma = gamma
        self.ent_coef = ent_coef
        self.device = device
        
        self.model: Optional[PPO] = None
        self.env: Optional[DummyVecEnv] = None
        
    def create_model(self, env: ExploitScriptEnv, model_name: str = "ppo_exploit_agent") -> PPO:
        """Initialize a new PPO model with the given environment."""
        
        self.env = DummyVecEnv([lambda: env])
        
        self.model = PPO(
            policy="MlpPolicy",
            env=self.env,
            learning_rate=self.learning_rate,
            n_steps=self.n_steps,
            batch_size=self.batch_size,
            n_epochs=self.n_epochs,
            gamma=self.gamma,
            ent_coef=self.ent_coef,
            verbose=1,
            tensorboard_log=self.tensorboard_log,
            device=self.device,
            max_grad_norm=0.5,  # Add gradient clipping to prevent NaN
            clip_range=0.2,  # Standard PPO clipping
        )
        
        logger.info(
            "Created PPO model '%s' | lr=%s n_steps=%s batch=%s device=%s",
            model_name,
            self.learning_rate,
            self.n_steps,
            self.batch_size,
            self.device,
        )
        return self.model
    
    def train(
        self,
        total_timesteps: int = 10_000,
        checkpoint_freq: int = 1000,
        eval_freq: int = 500,
        eval_episodes: int = 5,
        model_name: str = "ppo_exploit_agent",
    ) -> PPO:
        """Train the PPO agent with checkpointing and evaluation."""
        
        if self.model is None:
            raise RuntimeError("Model not initialized. Call create_model() first.")
        
        # Checkpoint callback
        checkpoint_callback = CheckpointCallback(
            save_freq=checkpoint_freq,
            save_path=str(self.checkpoint_dir),
            name_prefix=model_name,
            save_replay_buffer=False,
            save_vecnormalize=False,
        )
        
        # Training callback for custom logging
        training_callback = TrainingProgressCallback(log_freq=100)
        
        callbacks = [checkpoint_callback, training_callback]
        
        logger.info("Starting PPO training for %s timesteps", total_timesteps)
        self.model.learn(
            total_timesteps=total_timesteps,
            callback=callbacks,
            progress_bar=True,
        )
        
        # Save final model
        final_path = self.checkpoint_dir / f"{model_name}_final.zip"
        self.model.save(str(final_path))
        logger.info("Training complete. Final model saved to %s", final_path)
        
        return self.model
    
    def load_model(self, checkpoint_path: str) -> PPO:
        """Load a trained PPO model from checkpoint."""
        
        if not Path(checkpoint_path).exists():
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
        
        self.model = PPO.load(checkpoint_path, device=self.device)
        logger.info("Loaded PPO model from %s", checkpoint_path)
        return self.model
    
    def predict(self, observation: np.ndarray, deterministic: bool = True) -> tuple[np.ndarray, Optional[np.ndarray]]:
        """Run inference with trained agent."""
        
        if self.model is None:
            raise RuntimeError("Model not initialized. Call create_model() or load_model() first.")
        
        action, state = self.model.predict(observation, deterministic=deterministic)
        return action, state
    
    def improve_script(
        self,
        vuln: Dict[str, Any],
        initial_script: str,
        max_modifications: int = 10,
        deterministic: bool = True,
    ) -> Dict[str, Any]:
        """
        Use trained agent to iteratively improve an exploit script.
        
        Returns:
            Dict with final_script, best_result, modification_count, success
        """
        
        if self.model is None:
            raise RuntimeError("Model not initialized. Load a trained model first.")
        
        env = ExploitScriptEnv(vuln, initial_script, max_modifications=max_modifications)
        obs, info = env.reset()
        
        done = False
        step_count = 0
        
        while not done and step_count < max_modifications:
            action, _ = self.predict(obs, deterministic=deterministic)
            obs, reward, terminated, truncated, info = env.step(int(action))
            done = terminated or truncated
            step_count += 1
            
            logger.debug(
                "Step %s | action=%s mod=%s success=%s reward=%.2f",
                step_count,
                action,
                info.get("modification_applied"),
                info.get("success"),
                reward,
            )
        
        final_script = env.get_final_script()
        best_result = env.get_best_result()
        
        return {
            "final_script": final_script,
            "best_result": best_result,
            "modification_count": step_count,
            "success": best_result.get("success") if best_result else False,
            "best_reward": info.get("best_reward"),
        }
    
    def get_latest_checkpoint(self, model_name: str = "ppo_exploit_agent") -> Optional[Path]:
        """Find the most recent checkpoint for the given model."""
        
        checkpoints = list(self.checkpoint_dir.glob(f"{model_name}_*.zip"))
        if not checkpoints:
            return None
        
        # Sort by modification time
        latest = max(checkpoints, key=lambda p: p.stat().st_mtime)
        return latest


class TrainingProgressCallback(BaseCallback):
    """Custom callback for logging training progress and metrics."""
    
    def __init__(self, log_freq: int = 100, verbose: int = 0):
        super().__init__(verbose)
        self.log_freq = log_freq
        self.episode_rewards: list[float] = []
        self.episode_lengths: list[int] = []
        
    def _on_step(self) -> bool:
        """Called at each environment step."""

        # Log instant rewards from this step
        if hasattr(self, 'locals') and 'rewards' in self.locals:
            rewards = self.locals['rewards']
            for i, reward in enumerate(rewards):
                if reward != 0:  # Only log non-zero rewards
                    logger.debug("Step %s env_%s | instant_reward=%.2f", self.n_calls, i, reward)

        if self.n_calls % self.log_freq == 0:
            # Log current stats
            if len(self.episode_rewards) > 0:
                mean_reward = np.mean(self.episode_rewards[-100:])
                mean_length = np.mean(self.episode_lengths[-100:])
                logger.info(
                    "Step %s | episodes=%s | mean_reward=%.2f mean_length=%.1f",
                    self.n_calls,
                    len(self.episode_rewards),
                    mean_reward,
                    mean_length,
                )
            else:
                # Log even if no episodes completed yet
                if hasattr(self, 'locals') and 'rewards' in self.locals:
                    recent_rewards = self.locals.get('rewards', [])
                    if len(recent_rewards) > 0:
                        logger.info(
                            "Step %s | recent_reward=%.2f (no episodes completed yet)",
                            self.n_calls,
                            np.mean(recent_rewards),
                        )

        return True
    
    def _on_rollout_end(self) -> None:
        """Called at end of rollout."""
        
        # Extract episode stats from local variables (if available)
        if hasattr(self.locals, "infos"):
            for info in self.locals.get("infos", []):
                if "episode" in info:
                    self.episode_rewards.append(info["episode"]["r"])
                    self.episode_lengths.append(info["episode"]["l"])
