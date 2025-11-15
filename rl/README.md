# PPO Reinforcement Learning for Autonomous Exploit Improvement

## Overview

AUVAP now includes a **Proximal Policy Optimization (PPO)** agent that learns to iteratively modify and improve exploit scripts through reinforcement learning. The agent:

1. **Observes** script structure, target metadata, and execution feedback
2. **Acts** by modifying scripts (timeouts, SSL settings, retries, payloads, etc.)
3. **Receives rewards** based on exploit success and execution quality
4. **Learns** to maximize exploit success through trial and error
5. **Persists** results back to RAG memory and sends feedback to LLM

---

## Architecture

### Components

- **`rl/script_env.py`**: Gymnasium environment wrapping script execution and modification
- **`rl/ppo_agent.py`**: PPO agent using stable-baselines3 for training and inference
- **`rl/rl_feedback.py`**: Integration layer between PPO, LLM, and RAG memory
- **`rl/train_ppo.py`**: Standalone training/inference CLI for batch operations
- **`main.py`**: Integrated pipeline with `--rl-mode` flags

### State Space (Observation)

The agent observes a 9-dimensional feature vector:
- Timeout value
- SSL verification enabled (0/1)
- Retry count
- Payload length
- Has error handling (0/1)
- Last execution success (0/1)
- Last execution time
- Modification count
- Target port

### Action Space

8 discrete actions:
0. Increase timeout
1. Decrease timeout
2. Toggle SSL verification
3. Add retry logic
4. Change payload encoding
5. Adjust delay
6. Modify connection parameters
7. Done (terminate episode)

### Reward Function

- **Success**: +100 (with speed bonus)
- **Partial evidence**: +30
- **Failure**: -10
- **Repeated error**: -20
- **Timeout/crash**: -15

---

## Installation

Install additional RL dependencies:

```bash
cd auvap
pip install -r requirements.txt
```

This adds:
- `gymnasium>=0.29.0`
- `stable-baselines3>=2.2.0`
- `torch>=2.0.0`
- `tensorboard>=2.14.0`

---

## Remote VM Execution

**PPO training now executes exploit scripts on a remote VM instead of your Mac.**

### Quick Setup

1. **Configure VM connection** (copy and edit):

```bash
cp rl/vm_config.env.example rl/vm_config.env
nano rl/vm_config.env
```

2. **Set environment variables**:

```bash
# Required
export RL_VM_HOST="192.168.1.100"        # Your VM's IP
export RL_VM_USER="kali"                 # SSH username

# Authentication: use key (recommended) OR password
export RL_VM_KEY_PATH="~/.ssh/kali_key"  # SSH key path
# OR
export RL_VM_PASSWORD="yourpassword"     # Password

# Optional
export RL_VM_PORT="22"                   # SSH port (default: 22)
export RL_VM_PYTHON="python3"            # Python on VM
export RL_VM_WORKSPACE="/tmp/auvap_rl"   # Temp dir on VM
```

3. **Load and verify**:

```bash
source rl/vm_config.env
ssh $RL_VM_USER@$RL_VM_HOST "echo 'VM connection OK'"
```

### How It Works

1. **Mac side**: PPO agent runs on your Mac (training/inference)
2. **VM side**: Exploit scripts execute on VM via SSH
3. **Transfer**: Scripts uploaded via SFTP, executed, results retrieved
4. **Isolation**: VM workspace (`/tmp/auvap_rl`) isolated from host

**Benefits:**
- Mac never executes potentially dangerous exploit code
- VM can be snapshotted/reset between runs
- VM has VPN-only network access
- Training data collected from real execution environment

### VM Requirements

**Using Metasploitable2 (Recommended for Training):**

Metasploitable2 is ideal for PPO training because it's intentionally vulnerable and provides realistic exploit targets. It comes pre-configured with SSH and Python.

**Default credentials:**
- Username: `msfadmin`
- Password: `msfadmin`
- Python: Python 2.5 (built-in)

**Quick setup:**

```bash
# Auto-configure for Metasploitable2
./rl/setup_metasploitable2.sh <metasploitable2_ip>

# Example
./rl/setup_metasploitable2.sh 192.168.1.100
```

**⚠️ CRITICAL SECURITY WARNING:**
Metasploitable2 is EXTREMELY vulnerable by design. ONLY use it in:
- Isolated lab networks (host-only or internal network)
- Never exposed to the internet
- Never on production networks
- Snapshotted/reset regularly

**Alternative VMs:**

For other Linux VMs (Kali, Ubuntu, etc.):

```bash
# On VM
sudo apt update
sudo apt install -y python3 openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# Allow SSH through firewall (if enabled)
sudo ufw allow 22/tcp
```

### SSH Setup

**For Metasploitable2 (Password Authentication):**

Metasploitable2 uses password authentication by default. Just set the environment variables:

```bash
export RL_VM_HOST="192.168.1.100"      # Your Metasploitable2 IP
export RL_VM_USER="msfadmin"
export RL_VM_PASSWORD="msfadmin"
```

**For Other VMs (SSH Key - More Secure):**

```bash
# On Mac - generate key if you don't have one
ssh-keygen -t rsa -b 4096 -f ~/.ssh/vm_key

# Copy public key to VM
ssh-copy-id -i ~/.ssh/vm_key.pub user@192.168.1.100

# Test connection
ssh -i ~/.ssh/vm_key user@192.168.1.100 "echo 'Success'"

# Set in environment
export RL_VM_KEY_PATH="~/.ssh/vm_key"
```

### Execution Flow

```
Mac (PPO Training)
    ↓
    1. Agent modifies script
    ↓
    2. Upload script to VM via SFTP
    ↓
VM (Execution)
    ↓
    3. Execute script against target
    ↓
    4. Save results as JSON
    ↓
    5. Return results to Mac
    ↓
Mac (PPO Training)
    ↓
    6. Calculate reward
    7. Update policy
    8. Store in RAG
```

### Troubleshooting

**Connection refused:**
```bash
# Check VM is running and reachable
ping $RL_VM_HOST

# For Metasploitable2, test SSH manually
ssh msfadmin@$RL_VM_HOST  # password: msfadmin

# Check if SSH port is open
nc -zv $RL_VM_HOST 22
```

**Permission denied (Metasploitable2):**
```bash
# Verify credentials are correct
echo "User: $RL_VM_USER, Pass: $RL_VM_PASSWORD"

# Should be: msfadmin / msfadmin
export RL_VM_USER="msfadmin"
export RL_VM_PASSWORD="msfadmin"

# Test manual login
sshpass -p msfadmin ssh msfadmin@$RL_VM_HOST "echo Success"
```

**Permission denied (SSH key):**
```bash
# Verify key permissions
chmod 600 ~/.ssh/vm_key

# Test manual SSH
ssh -i ~/.ssh/vm_key -v $RL_VM_USER@$RL_VM_HOST
```

**Workspace errors:**
```bash
# Ensure workspace directory exists and is writable
ssh $RL_VM_USER@$RL_VM_HOST "mkdir -p /tmp/auvap_rl && ls -la /tmp/auvap_rl"
```

**Python not found on VM:**
```bash
# Check Python availability
ssh $RL_VM_USER@$RL_VM_HOST "which python"

# Metasploitable2 uses Python 2.5 by default
export RL_VM_PYTHON="python"  # NOT python3

# Verify version
ssh $RL_VM_USER@$RL_VM_HOST "python -V"

# For other VMs with Python 3
export RL_VM_PYTHON="python3"
```

---

## Usage

### 1. Training Mode

Train PPO agent on classified vulnerabilities with generated scripts:

```bash
# Set VM connection (required for remote execution)
source rl/vm_config.env

# Train with remote VM execution
python main.py \
  --nessus scans/target.nessus \
  --config config/context_rules.json \
  --rl-mode train \
  --rl-timesteps 10000 \
  --rl-checkpoint-dir ./rl/checkpoints \
  --verbose
```

**What happens:**
- Pipeline generates initial scripts via LLM (on Mac)
- Scripts uploaded and executed on VM via SSH
- For each vulnerability, PPO agent trains for N timesteps (Mac)
- Agent learns to modify scripts and maximize success
- Checkpoints saved every 1000 steps (Mac)
- Final results stored in RAG memory (Mac)

### 2. Inference Mode

Apply trained agent to improve scripts before execution:

```bash
# Set VM connection
source rl/vm_config.env

# Run inference with trained agent
python main.py \
  --nessus scans/target.nessus \
  --config config/context_rules.json \
  --rl-mode inference \
  --rl-checkpoint-dir ./rl/checkpoints \
  --verbose
```

**What happens:**
- Pipeline loads latest PPO checkpoint (Mac)
- Agent modifies each script to improve success probability (Mac)
- Improved scripts executed on VM via SSH
- Results stored in RAG for future learning (Mac)

### 3. Standalone Training

Train on pre-generated vulnerability dataset:

```bash
# Set VM connection
source rl/vm_config.env

# Standalone training
python rl/train_ppo.py \
  --mode train \
  --vulnerabilities reports/Meta_hvp1r9_run_scripts.json \
  --rag-dir ./rag_memory \
  --checkpoint-dir ./rl/checkpoints \
  --timesteps 10000 \
  --verbose
```

### 4. Standalone Inference

Run inference without full pipeline:

```bash
# Set VM connection
source rl/vm_config.env

# Standalone inference
python rl/train_ppo.py \
  --mode inference \
  --vulnerabilities reports/Meta_hvp1r9_run_scripts.json \
  --rag-dir ./rag_memory \
  --checkpoint-dir ./rl/checkpoints \
  --output ./rl/inference_results.json \
  --verbose
```

---

## VPN-Only Execution on VM

Since scripts now execute on the remote VM, configure VPN on the VM itself:

### Option 1: VM-Level VPN (Recommended)

Route all VM traffic through VPN:

```bash
# On VM - install OpenVPN
sudo apt install -y openvpn

# Copy your VPN config
scp your-vpn.ovpn kali@192.168.1.100:/etc/openvpn/client.conf

# Start VPN
sudo systemctl start openvpn@client
sudo systemctl enable openvpn@client

# Verify VPN connection
ip addr show tun0
```

### Option 2: Firewall Rules on VM

Block non-VPN traffic:

```bash
# On VM - allow only VPN interface
sudo iptables -A OUTPUT -o tun0 -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -j REJECT

# Make persistent
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

### Option 3: Network Namespace on VM

Isolate exploit execution in VPN namespace:

```bash
# On VM - create VPN namespace
sudo ip netns add vpn_only
sudo ip netns exec vpn_only openvpn --config /etc/openvpn/client.conf --daemon

# Execute Python in namespace
sudo ip netns exec vpn_only python3 /tmp/auvap_rl/exploit_*.py
```

Update `rl/remote_executor.py` to use namespace:

```python
command = f"sudo ip netns exec vpn_only timeout {timeout}s {self.python_path} {remote_script_path}"
```

---

## Monitoring

### Tensorboard

Monitor training progress:

```bash
tensorboard --logdir ./rl/tensorboard
```

Navigate to `http://localhost:6006` to view:
- Episode rewards over time
- Policy loss and value function loss
- Entropy (exploration)
- Learning rate schedule

### Checkpoints

Checkpoints saved to `./rl/checkpoints/` with naming:
- `ppo_exploit_agent_1000_steps.zip`
- `ppo_exploit_agent_2000_steps.zip`
- `ppo_exploit_agent_final.zip`

Load latest checkpoint:

```python
from rl.ppo_agent import PPOScriptAgent

agent = PPOScriptAgent(checkpoint_dir="./rl/checkpoints")
latest = agent.get_latest_checkpoint()
agent.load_model(str(latest))
```

---

## RAG & LLM Feedback

### RAG Integration

After each RL-improved execution:
1. Results stored in `rag_memory/` via `RAGMemorySystem.store_execution_feedback()`
2. Successful modifications tagged with techniques (retry, SSL, timeout, etc.)
3. Future queries retrieve similar past attempts for guidance

#### Backend selection

- **Vector store (Chromadb + sentence-transformers)**: Automatically used when both packages are installed (`pip install chromadb sentence-transformers onnxruntime`). Provides semantic similarity search and LLM-generated lessons.
- **Lightweight JSON fallback**: Enabled automatically when vector deps are missing. Entries are written to `rag_memory/simple_memory.json`, still tracking success/failure counts and key evidence for Gemini prompts. Upgrade to the vector backend later without losing history—the JSON file is preserved alongside future Chroma collections.

### LLM Feedback

Agent sends structured feedback to LLM after training:

```json
{
  "agent_assessment": "RL agent successfully reduced timeout and disabled SSL verification",
  "recommended_improvements": [
    "Consider adding retry logic earlier in the script",
    "Use exponential backoff for connection attempts"
  ],
  "patterns_to_remember": [
    "vsftpd 2.3.4 responds faster without SSL verification",
    "Port 21 exploits benefit from 5-10s timeout range"
  ]
}
```

This feedback is persisted in RAG `lessons_learned` collection.

---

## Example Workflow with Metasploitable2

```bash
# 1. Setup Metasploitable2 remote execution
./rl/setup_metasploitable2.sh 192.168.1.100

# 2. Load VM configuration
source rl/vm_config.env

# 3. Test VM connectivity
python rl/test_vm_connection.py

# 4. Run initial scan and generate scripts
./run_auvap.sh Meta_hvp1r9.nessus

# 5. Train PPO agent (scripts execute on Metasploitable2)
python main.py \
  --nessus Meta_hvp1r9.nessus \
  --config config/context_rules.json \
  --rl-mode train \
  --rl-timesteps 20000 \
  --verbose

# 6. Monitor training progress (in separate terminal)
tensorboard --logdir ./rl/tensorboard

# 7. Run inference with trained agent
python main.py \
  --nessus Meta_hvp1r9.nessus \
  --config config/context_rules.json \
  --rl-mode inference \
  --verbose

# 8. Check successful exploits
cat rl/inference_results.json | jq '.results[] | select(.success==true)'
```

---

## Configuration

### Hyperparameters

Modify in `rl/ppo_agent.py`:

```python
PPOScriptAgent(
    learning_rate=3e-4,      # Learning rate
    n_steps=2048,            # Steps per rollout
    batch_size=64,           # Minibatch size
    n_epochs=10,             # Optimization epochs per rollout
    gamma=0.99,              # Discount factor
    ent_coef=0.01,           # Entropy coefficient (exploration)
    device="auto",           # "cuda", "cpu", or "auto"
)
```

### Environment Settings

Modify in `rl/script_env.py`:

```python
ExploitScriptEnv(
    vuln=vuln_dict,
    initial_script=script_text,
    max_modifications=10,     # Max actions per episode
    timeout_range=(5, 120),   # Timeout bounds for modifications
)
```

---

## Troubleshooting

### Import Errors

If you see "Import gymnasium could not be resolved":

```bash
pip install --upgrade gymnasium stable-baselines3 torch
```

### CUDA Issues

For GPU training on Linux:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu118
```

For CPU-only (macOS/Windows):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

### No Checkpoints Found

If inference fails with "No checkpoints found":

```bash
# Train first
python main.py --nessus scan.nessus --config config.json --rl-mode train

# Then run inference
python main.py --nessus scan.nessus --config config.json --rl-mode inference
```

---

## Advanced: Custom Actions

Add new modification actions by editing `rl/script_env.py`:

```python
# In ExploitScriptEnv.__init__
self.action_space = spaces.Discrete(9)  # Add action 8

# In ExploitScriptEnv._apply_action
elif action == 8:
    self.current_script = self._custom_modification(self.current_script)
    return "custom_modification"

# Add method
def _custom_modification(self, script: str) -> str:
    """Your custom script modification logic."""
    return script.replace("foo", "bar")
```

---

## Performance Benchmarks

Typical training on Metasploitable2 dataset (5 vulnerabilities, 10k timesteps each):

- **CPU (M1 Mac)**: ~15 minutes
- **CPU (Intel i7)**: ~25 minutes
- **GPU (RTX 3080)**: ~8 minutes

Inference per vulnerability: <5 seconds

---

## References

- [Stable-Baselines3 PPO](https://stable-baselines3.readthedocs.io/en/master/modules/ppo.html)
- [Gymnasium Environments](https://gymnasium.farama.org/)
- [PPO Paper (Schulman et al., 2017)](https://arxiv.org/abs/1707.06347)
