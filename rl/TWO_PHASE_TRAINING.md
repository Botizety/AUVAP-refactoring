# Two-Phase Training System for AUVAP

## Overview

The AUVAP PPO training system now uses a **Two-Phase Approach** to intelligently improve exploit scripts:

- **Phase A**: LLM regenerates broken scripts based on error messages until they work
- **Phase B**: PPO optimizes working scripts for better exploit success rates

This approach solves the original problem where PPO tried to fix compilation errors with runtime parameter tweaks.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    INITIAL LLM-GENERATED SCRIPT              │
│                  (may have bugs/incompatibilities)           │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE A: LLM-BASED REGENERATION                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. Execute script on target VM                       │   │
│  │ 2. Capture detailed error (type, message, traceback) │   │
│  │ 3. Analyze error and identify root cause             │   │
│  │ 4. Request LLM to regenerate with specific fix       │   │
│  │ 5. Repeat until script works (max 5 attempts)        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Criteria for "working":                                    │
│  - No SyntaxError/NameError/ImportError                     │
│  - Script executes without crashing                         │
│  - May collect evidence (even if exploit fails)             │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE B: PPO FINE-TUNING (only if Phase A succeeds)        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. Start with working script from Phase A            │   │
│  │ 2. PPO learns to optimize parameters:                │   │
│  │    - Adjust timeouts                                 │   │
│  │    - Toggle SSL verification                         │   │
│  │    - Modify payloads                                 │   │
│  │    - Tune connection parameters                      │   │
│  │ 3. Reward shaping for partial progress:              │   │
│  │    +10: Script compiles                              │   │
│  │    +15: Connected to target                          │   │
│  │    +25: Protocol negotiated                          │   │
│  │    +100: Full exploit success                        │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              OPTIMIZED EXPLOIT SCRIPT                        │
│          (higher success rate, faster execution)             │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Fixes Implemented

### 1. **Critical Bug Fixes**

#### Remote Executor (rl/remote_executor.py)
- ✅ **Fixed SSL constant compatibility**: Properly removes `ssl.OP_NO_*` lines instead of replacing with `0`
- ✅ **Added fsync() to result file writing**: Ensures result files are written to disk before timeout
- ✅ **Enhanced error handling**: Always writes result file, even on catastrophic failure
- ✅ **Added error_type field**: Enables better error categorization

#### Script Environment (rl/script_env.py)
- ✅ **Expanded observation space**: Added 6 new features for error tracking
  - `syntax_error`, `attribute_error`, `ssl_error`, `timeout_error`, `script_lines`, `consecutive_failures`
- ✅ **Reward shaping**: Detailed rewards for partial progress (+10 compile, +15 connect, +25 protocol, +30 evidence)
- ✅ **Early termination**: Episodes end immediately on success (no wasted computation)
- ✅ **Memory leak fix**: Keeps only last 50 execution results

#### PPO Agent (rl/ppo_agent.py)
- ✅ **Optimized hyperparameters**:
  - `learning_rate`: 3e-4 → **1e-4** (better for sparse rewards)
  - `n_steps`: 2048 → **128** (matches episode length)
  - `batch_size`: 64 → **32** (more frequent updates)
  - `ent_coef`: 0.01 → **0.05** (more exploration)
- ✅ **Improved logging**: Logs instant rewards and handles no-episode-complete case

---

### 2. **Phase A: LLM Regeneration** (NEW)

**File**: `rl/phase_a_llm_regeneration.py`

**Key Features**:
- Executes scripts and captures detailed errors
- Categorizes errors (SSL compatibility, syntax, timeout, etc.)
- Builds targeted regeneration prompts with specific fix requests
- Iterates until script works or max attempts (default: 5)
- Stores successful patterns in RAG memory

**Error Categories Handled**:
1. SSL compatibility (AttributeError for `OP_NO_*` constants)
2. Syntax errors (Python 3.4+ compatibility)
3. Undefined variables (missing imports)
4. Timeouts (connection issues)
5. SSL handshake failures

---

### 3. **Phase B: PPO Fine-Tuning** (IMPROVED)

**Uses**: `rl/script_env.py`, `rl/ppo_agent.py`

**Improvements**:
- Only runs on working scripts (Phase A output)
- Observation space includes error tracking (15 features)
- Reward shaping provides learning signal even on failures
- Hyperparameters tuned for exploit script optimization

---

### 4. **Two-Phase Orchestrator** (NEW)

**File**: `rl/two_phase_trainer.py`

**Key Features**:
- Runs Phase A first, then Phase B only if A succeeds
- Skips Phase B if script already achieves full success in Phase A
- Stores results from both phases in RAG memory
- Comprehensive logging and progress tracking
- Saves detailed results JSON with both phase outcomes

---

## Usage

### Running Two-Phase Training

```bash
# Basic usage
python -m rl.two_phase_trainer \
  --vulnerabilities reports/classification_report.json \
  --output reports/two_phase_results.json

# With custom settings
python -m rl.two_phase_trainer \
  --vulnerabilities reports/classification_report.json \
  --phase-a-attempts 7 \
  --phase-b-timesteps 3000 \
  --verbose
```

### Environment Variables (for Remote VM)

```bash
# Required for remote execution on Metasploitable 2
export RL_VM_HOST=192.168.126.128
export RL_VM_USER=msfadmin
export RL_VM_PASSWORD=msfadmin
export RL_VM_PORT=22
export RL_VM_PYTHON=python3
```

### Command-Line Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--vulnerabilities` | *required* | Path to JSON with LLM-generated scripts |
| `--context-rules` | `config/context_rules.yaml` | Context rules for LLM prompts |
| `--rag-dir` | `./rag_memory` | RAG persistence directory |
| `--checkpoint-dir` | `./rl/checkpoints_two_phase` | PPO model checkpoints |
| `--output` | `./reports/two_phase_results.json` | Results output path |
| `--phase-a-attempts` | `5` | Max LLM regeneration attempts |
| `--phase-b-timesteps` | `2000` | PPO training timesteps |
| `--device` | `auto` | Training device (auto/cpu/cuda) |
| `--verbose` | `False` | Enable debug logging |

---

## Output Format

The `two_phase_results.json` file contains:

```json
{
  "total_vulnerabilities": 9,
  "phase_a_success_count": 7,
  "phase_b_run_count": 5,
  "final_success_count": 6,
  "success_rate": 0.67,
  "results": [
    {
      "vuln_id": "VULN-001",
      "phase_a_result": {
        "success": true,
        "attempts": 3,
        "final_script": "...",
        "execution_results": [...],
        "improvement_log": ["Attempt 1: SSL compatibility", ...]
      },
      "phase_b_result": {
        "success": true,
        "final_script": "...",
        "best_reward": 120.0,
        "modification_count": 12
      },
      "final_script": "...",
      "final_success": true,
      "phase_completed": "both"
    }
  ]
}
```

---

## Training Workflow

### For Each Vulnerability:

1. **Load initial LLM-generated script** from classification report
2. **Phase A: LLM Regeneration**
   - Execute script on Metasploitable 2 VM
   - If errors → analyze → regenerate → repeat (max 5 times)
   - Store working script in RAG
3. **Phase B: PPO Fine-Tuning** (if Phase A succeeded)
   - Create RL environment with working script
   - Train PPO for 2000 timesteps
   - Optimize for success rate and speed
   - Store optimized script in RAG
4. **Save results** with both phase outcomes

---

## Monitoring Progress

### Logs

```bash
# Real-time monitoring
tail -f logs/auvap_*.log

# Check Phase A progress
grep "PHASE A" logs/auvap_*.log

# Check Phase B progress
grep "PHASE B" logs/auvap_*.log
```

### TensorBoard

```bash
# Launch TensorBoard to view PPO training curves
tensorboard --logdir=rl/tensorboard
```

**Metrics to watch**:
- `rollout/ep_rew_mean`: Average episode reward (should increase)
- `train/entropy_loss`: Exploration level (should gradually decrease)
- `train/policy_loss`: Policy gradient magnitude
- `train/value_loss`: Value function accuracy

---

## Expected Results

### Before Two-Phase Training:
- ❌ 0/9 scripts work (100% crash rate)
- ❌ All rewards negative (-4 to -15)
- ❌ No learning signal for PPO

### After Two-Phase Training:
- ✅ Phase A: Fix 70-90% of scripts (compilation → execution)
- ✅ Phase B: Improve success rate by 20-40% for working scripts
- ✅ Positive rewards: +10 to +120 based on progress
- ✅ Scripts optimized for speed and reliability

---

## Troubleshooting

### Phase A Issues

**Problem**: Scripts still failing after 5 LLM attempts
**Solution**:
- Check LLM API key and rate limits
- Increase `--phase-a-attempts` to 7-10
- Review error logs for patterns LLM isn't fixing

**Problem**: LLM returns identical script
**Solution**:
- Error analysis may not be specific enough
- Check `phase_a_llm_regeneration.py` prompt templates
- Ensure error messages are detailed

### Phase B Issues

**Problem**: PPO rewards stay at 0
**Solution**:
- Phase A didn't produce working scripts
- Check remote VM connection
- Verify script execution on VM manually

**Problem**: Training too slow
**Solution**:
- Reduce `--phase-b-timesteps` from 2000 to 1000
- Use GPU with `--device cuda`
- Decrease `n_steps` in ppo_agent.py

---

## Technical Details

### Observation Space (15 features)

| Index | Feature | Range | Description |
|-------|---------|-------|-------------|
| 0 | timeout_val | 0-300 | Timeout value in script |
| 1 | ssl_verify | 0-1 | SSL verification enabled |
| 2 | retry_count | 0-10 | Number of retry loops |
| 3 | payload_length | 0-10000 | Payload size |
| 4 | has_error_handling | 0-1 | Try-except present |
| 5 | last_success | 0-1 | Last execution succeeded |
| 6 | last_exec_time | 0-300 | Last execution time (s) |
| 7 | modification_count | 0-50 | Modifications made |
| 8 | target_port | 0-65535 | Target port |
| 9 | syntax_error | 0-1 | Last error was SyntaxError |
| 10 | attribute_error | 0-1 | Last error was AttributeError |
| 11 | ssl_error | 0-1 | Last error was SSLError |
| 12 | timeout_error | 0-1 | Last error was timeout |
| 13 | script_lines | 0-1000 | Lines of code |
| 14 | consecutive_failures | 0-50 | Consecutive failures |

### Action Space (8 actions)

| Action | Description | Implementation |
|--------|-------------|----------------|
| 0 | Increase timeout | Regex: `timeout=X` → `timeout=X+10` |
| 1 | Decrease timeout | Regex: `timeout=X` → `timeout=X-10` |
| 2 | Toggle SSL verify | Swap `verify=True` ↔ `verify=False` |
| 3 | Add retry logic | **DISABLED** (causes indentation errors) |
| 4 | Change payload encoding | Toggle URL encoding/base64 |
| 5 | Adjust delay | Reduce `time.sleep(X)` by 50% |
| 6 | Modify connection params | **DISABLED** (causes syntax errors) |
| 7 | Done | Terminate episode |

---

## Future Enhancements

### Planned Improvements:
1. **Expand action space**: Add "regenerate with LLM" action in Phase B
2. **Curriculum learning**: Start with easy vulnerabilities, progress to hard
3. **Multi-objective optimization**: Balance success rate vs execution speed
4. **Active learning**: Use PPO uncertainty to decide when to call LLM
5. **Transfer learning**: Share PPO policy across similar vulnerabilities

---

## References

- Original issue analysis: See code review report
- PPO paper: https://arxiv.org/abs/1707.06347
- Stable Baselines3 docs: https://stable-baselines3.readthedocs.io/

---

## Support

For issues or questions:
1. Check logs in `logs/auvap_*.log`
2. Review TensorBoard metrics
3. Examine `two_phase_results.json` for detailed outcomes
4. Enable `--verbose` for debug logging
