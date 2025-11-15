# Metasploitable2 PPO Training Quick Start

This guide assumes you have Metasploitable2 VM running on your network.

## Prerequisites

- Metasploitable2 VM running
- VM accessible from Mac (same network or host-only adapter)
- AUVAP dependencies installed (`pip install -r requirements.txt`)

## 1. Find Your Metasploitable2 IP

**If using VMware/VirtualBox with DHCP:**

```bash
# On Metasploitable2 VM console
ifconfig
# Look for inet addr under eth0
```

**Or scan your network from Mac:**

```bash
nmap -sn 192.168.1.0/24 | grep -B 2 "Cadmus"
# Metasploitable2 MAC address vendor is often Cadmus
```

## 2. Auto-Configure Connection

```bash
cd "/Users/boat/AUVAP real/auvap"

# Run setup script with Metasploitable2 IP
./rl/setup_metasploitable2.sh 192.168.1.100
```

This will:
- Test connectivity to VM
- Verify SSH access (msfadmin:msfadmin)
- Create `rl/vm_config.env` with correct settings
- Check Python availability

## 3. Load Configuration

```bash
source rl/vm_config.env
```

## 4. Test Remote Execution

```bash
python rl/test_vm_connection.py
```

Expected output:
```
✓ SSH connection successful
✓ Command execution successful
✓ Python available on VM: Python 2.5.x
✓ Workspace directory ready: /tmp/auvap_rl
✓ Script executed successfully on VM
```

## 5. Train PPO Agent

```bash
# Train on your existing Metasploitable2 scan
python main.py \
  --nessus Meta_hvp1r9.nessus \
  --config config/context_rules.json \
  --rl-mode train \
  --rl-timesteps 10000 \
  --verbose
```

**What happens:**
- Mac: PPO agent loads vulnerabilities and initial scripts
- VM: Each script executed on Metasploitable2
- Mac: Agent learns from success/failure rewards
- Mac: Checkpoints saved to `rl/checkpoints/`
- Mac: Results stored in RAG memory

## 6. Monitor Training

Open new terminal:

```bash
cd "/Users/boat/AUVAP real/auvap"
tensorboard --logdir ./rl/tensorboard
```

Visit `http://localhost:6006` to see:
- Episode rewards over time
- Success rate trends
- Policy loss curves

## 7. Run Inference

After training completes:

```bash
source rl/vm_config.env

python main.py \
  --nessus Meta_hvp1r9.nessus \
  --config config/context_rules.json \
  --rl-mode inference \
  --verbose
```

## Expected Training Results

With Metasploitable2's known vulnerabilities, you should see:

**Initial (untrained) success rate:** ~10-20%  
**After 10k timesteps:** ~40-60%  
**After 50k timesteps:** ~70-85%

Agent learns to:
- Adjust timeouts for slow services (distcc, vsftpd)
- Disable SSL verification for older services
- Add retry logic for unreliable exploits
- Optimize payload encoding

## Troubleshooting

### "Connection refused"

```bash
# Check VM is powered on
ping 192.168.1.100

# Verify SSH is running on VM
# (Login to VM console and run):
sudo /etc/init.d/ssh start
```

### "Permission denied"

```bash
# Verify credentials
export RL_VM_USER="msfadmin"
export RL_VM_PASSWORD="msfadmin"

# Test manual SSH
sshpass -p msfadmin ssh msfadmin@192.168.1.100 "echo OK"
```

### "Python version mismatch"

Metasploitable2 has Python 2.5, which may not support all features. Our wrapper scripts handle compatibility, but if issues occur:

```bash
# Update to use Python 2 explicitly
export RL_VM_PYTHON="python2"
```

### "No checkpoints found"

If inference fails:

```bash
# Check checkpoints exist
ls -la rl/checkpoints/

# If empty, train first
python main.py --nessus Meta_hvp1r9.nessus --config config/context_rules.json --rl-mode train
```

## Network Isolation Warning

⚠️ **CRITICAL:** Metasploitable2 is INTENTIONALLY VULNERABLE

**Safe configurations:**
- Host-only adapter (VM isolated from internet)
- Internal network (VM can't reach internet)
- Behind firewall with strict egress filtering

**NEVER:**
- Give Metasploitable2 internet access
- Use bridged networking on untrusted networks
- Expose it to your organization's production network

## Next Steps

After successful training:

1. **Analyze learned policies:**
   ```bash
   # View checkpoint details
   python -c "from rl.ppo_agent import PPOScriptAgent; \
              agent = PPOScriptAgent(); \
              print(agent.get_latest_checkpoint())"
   ```

2. **Export successful scripts:**
   ```bash
   # Extract scripts with >80% success rate
   python -c "import json; \
              data = json.load(open('rl/inference_results.json')); \
              [print(r['final_script']) for r in data['results'] if r.get('success')]"
   ```

3. **Seed RAG with successes:**
   ```bash
   # Check what the agent learned
   cat rag_memory/*/metadata.json | jq '.success'
   ```

4. **Use on new scans:**
   ```bash
   # Apply learned optimizations to new targets
   python main.py --nessus new_scan.nessus --config config.json --rl-mode inference
   ```

## Performance Benchmarks

Typical training times on M1 Mac with Metasploitable2:

- **5 vulnerabilities, 10k steps:** ~8 minutes
- **10 vulnerabilities, 20k steps:** ~25 minutes
- **RAG lookups per exploit:** <1 second
- **Remote execution overhead:** ~200ms per script

## Questions?

See `rl/README.md` for complete documentation or run:

```bash
python main.py --help
python rl/train_ppo.py --help
```
