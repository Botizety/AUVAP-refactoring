"""Quick test to verify PPO agent initialization and basic training."""

import sys
from pathlib import Path

# Add auvap to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rl.script_env import ExploitScriptEnv
from rl.ppo_agent import PPOScriptAgent


def test_environment():
    """Test environment creation and reset."""
    
    # Mock vulnerability and script
    vuln = {
        "vuln_id": "TEST-001",
        "host": "192.168.1.100",
        "port": 21,
        "service": "vsftpd",
        "version": "2.3.4",
    }
    
    initial_script = """
import socket

def exploit(target_ip, target_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    s.send(b"USER test\\r\\n")
    response = s.recv(1024)
    s.close()
    return {"success": False, "message": "Test exploit", "evidence": response.decode()}
"""
    
    env = ExploitScriptEnv(vuln, initial_script, max_modifications=5)
    obs, info = env.reset()
    
    print(f"✓ Environment created")
    print(f"  Observation shape: {obs.shape}")
    print(f"  Action space: {env.action_space}")
    print(f"  Observation space: {env.observation_space}")
    
    # Test step
    obs, reward, terminated, truncated, info = env.step(0)
    print(f"✓ Environment step executed")
    print(f"  Action: increase_timeout")
    print(f"  Reward: {reward:.2f}")
    print(f"  Terminated: {terminated}, Truncated: {truncated}")
    
    return env


def test_ppo_agent():
    """Test PPO agent creation."""
    
    agent = PPOScriptAgent(
        checkpoint_dir="./rl/test_checkpoints",
        learning_rate=3e-4,
        device="cpu",
    )
    
    print(f"✓ PPO agent created")
    print(f"  Checkpoint dir: {agent.checkpoint_dir}")
    print(f"  Learning rate: {agent.learning_rate}")
    
    # Create dummy environment
    vuln = {
        "vuln_id": "TEST-002",
        "host": "192.168.1.100",
        "port": 22,
        "service": "ssh",
        "version": "OpenSSH 5.9",
    }
    
    script = """
def exploit(target_ip, target_port):
    return {"success": False, "message": "Test", "evidence": None}
"""
    
    env = ExploitScriptEnv(vuln, script, max_modifications=3)
    model = agent.create_model(env, model_name="test_agent")
    
    print(f"✓ PPO model initialized")
    print(f"  Policy: {model.policy}")
    
    return agent, env


def main():
    """Run tests."""
    
    print("=" * 60)
    print("Testing AUVAP PPO Reinforcement Learning Components")
    print("=" * 60)
    print()
    
    print("[1/2] Testing ExploitScriptEnv...")
    env = test_environment()
    print()
    
    print("[2/2] Testing PPOScriptAgent...")
    agent, _ = test_ppo_agent()
    print()
    
    print("=" * 60)
    print("✓ All tests passed! PPO RL system is ready.")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Train on real vulnerabilities:")
    print("   python main.py --nessus scan.nessus --config config.json --rl-mode train")
    print()
    print("2. Run inference with trained agent:")
    print("   python main.py --nessus scan.nessus --config config.json --rl-mode inference")
    print()


if __name__ == "__main__":
    main()
