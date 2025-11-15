# AUVAP – Automated Vulnerability Assessment & Penetration Testing

AUVAP is a production-oriented framework that turns Nessus scan output into an autonomous exploitation pipeline powered by Retrieval-Augmented Generation (RAG). Two coordinated LLM agents classify/prioritize vulnerabilities and synthesize exploit scripts, while a persistent memory captures execution outcomes so future runs learn from past successes and failures.

```
Nessus Scan → Parser → LLM #1 Classifier → RAG Memory Lookup
						↘ Config Rules ↗            ↘ Context
										LLM #2 Script Generator → Validator → Executor → Feedback → RAG
																													 ↘ Report Generator ↘ CLI
```

## Why AUVAP?
- **Single-pass classification:** LLM #1 sees every finding at once, enabling consistent prioritization and context-aware filtering (e.g., drop local-only issues automatically).
- **RAG-based learning:** Every exploit attempt is embedded, stored, and re-used. Success indicators, script excerpts, and LLM-derived lessons influence subsequent generations.
- **Safety-first execution:** Scripts must pass structural/safety validation, run in isolated temp directories, and respect strict timeout/IP constraints.
- **Actionable reporting:** JSON/HTML/Markdown reports capture executive summaries, service/severity breakdowns, execution evidence, and memory growth.

## Installation
Requirements: macOS/Linux, Python 3.9+, and access to OpenRouter.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Optional (for HTML/Markdown reports):

```bash
python3 -m pip install jinja2
```

Copy `.env.example` → `.env` and set `OPENROUTER_API_KEY`, `RAG_PERSIST_DIR`, and desired `LOG_LEVEL` (or pass the API key via CLI).
Optionally set `OPENROUTER_MODEL` to try a different OpenRouter model without editing code.
If you want to bypass OpenRouter entirely, set `LLM_PROVIDER=gemini` along with `GEMINI_API_KEY` (from Google AI Studio) and, optionally, `GEMINI_MODEL` (defaults to `gemini-2.0-flash`). The Gemini client will transparently try `-latest` variants, fall back through `gemini-2.0-flash-lite`, `gemini-2.0-flash-exp`, `gemini-2.5-flash-lite`, `gemini-2.5-flash`, and `gemini-2.5-pro`, and finally call the `ListModels` API to auto-discover any accessible model that supports `generateContent`.

## Configuration: `config/context_rules.json`
The configuration constrains scope, filters noise, and drives prioritization.

- **exploitation_constraints:** Communicate what the remote agent *can* and *cannot* do.
- **ignore_rules / force_include:** Fine-grained filtering by port/service/CVE/plugin.
- **priority_rules:** Map business context to vulnerability scoring.
- **safety_constraints:** IP ranges, dangerous command bans, per-run exploit limits.

Example files live under `examples/example_config.json`, while the live file under `config/` matches the format for immediate customization.

## Example Inputs
- `examples/example_scan.nessus` – demonstrates multi-host Nessus XML with a mix of SSH, HTTP, SMB, and local-only findings.
- `examples/example_config.json` – ready-to-use context rules describing a lab network.

## Usage
```bash
python main.py \
	--nessus examples/example_scan.nessus \
	--config config/context_rules.json \
	--api-key "$OPENROUTER_API_KEY" \
	--rag-dir ./rag_memory \
	--format json \
	--output reports/latest.json \
	--verbose \
	--dry-run
```

Key flags:
- `--dry-run` skips execution/feedback while still producing scripts and reports.
- `--format` accepts `json`, `html`, or `markdown` (HTML/MD require Jinja2).
- `--rag-dir` controls persistence; copy the directory between runs to preserve learning.
- `--model` overrides the OpenRouter model for the run (defaults to `OPENROUTER_MODEL` env var or the built-in choice).
- `--provider` switches between `openrouter` and `gemini`; when `gemini` is selected you can also pass `--gemini-api-key` / `--gemini-model`.

### Shortcut Runner
For demos you can avoid the long CLI string by using the helper script (make sure `.env` is populated and the script is executable):

```bash
chmod +x run_auvap.sh                           # one-time
./run_auvap.sh Meta_hvp1r9.nessus --dry-run      # defaults config, RAG dir, format, output, verbose
```

The wrapper automatically:
- loads `OPENROUTER_API_KEY` from `.env`;
- injects `--config config/context_rules.json`, `--rag-dir ./rag_memory`, `--format json`, and writes to `reports/<scan>_run.json` unless you override the flags yourself;
- enables `--verbose` by default (set `AUVAP_AUTO_VERBOSE=false` in `.env` to disable).

Override defaults globally via optional `.env` keys:

```
AUVAP_DEFAULT_CONFIG="config/context_rules.json"
AUVAP_DEFAULT_RAG_DIR="./rag_memory"
AUVAP_DEFAULT_FORMAT="json"
AUVAP_DEFAULT_OUTPUT_DIR="reports"
AUVAP_AUTO_VERBOSE=true
```

Any CLI flag you pass (e.g., `--format html` or `--output custom.json`) wins over the defaults, so you can keep the short command while still tweaking behavior as needed.

## Workflow Phases
1. **Ingestion:** Parse Nessus XML, extract hosts, services, CVEs, plugin output, etc.
2. **Classification (LLM #1):** One-shot prompt performs filtering, attack-vector labeling, remote-only enforcement, and priority scoring with sequential IDs.
3. **RAG Retrieval:** `RAGMemorySystem` searches for similar successes/failures/lessons using MiniLM embeddings stored in ChromaDB.
4. **Script Generation (LLM #2):** Prompts highlight RAG findings, safety constraints, and target metadata; output includes exploit type, code, techniques applied/avoided, and success indicators.
5. **Validation/Execution:** Scripts must declare `exploit(target_ip, target_port)` and return `{success, message, evidence}`; forbidden commands/timeouts are enforced before isolated execution.
6. **Feedback & Learning:** Execution results plus script excerpts hash-identified and stored as successes or failures; optional lessons extracted through OpenRouter.
7. **Reporting:** `report_generator.py` aggregates statistics and writes JSON/HTML/MD artifacts summarizing the run and RAG growth.

## How RAG Learning Improves Results
| Run | Stored Experiences | Notable Improvement |
| --- | ------------------ | ------------------- |
| 1   | 0                  | Generic scripts only |
| 5   | 20+ (mixed)        | Avoids techniques that failed earlier |
| 25  | 100+               | Service/version-specific exploit patterns reused |
| 100 | 400+               | >80% success rate on recurring misconfigurations |

Each feedback entry stores: vuln metadata, script hash/excerpt, techniques used, success flag, execution timing, and evidence/error. Query text mirrors embedding text so similar services/versions overlap semantically.

## Safety & Scope Controls
- Validation rejects scripts lacking timeouts, return structures, or containing forbidden commands (e.g., `rm -rf`, filesystem formatters, or suspicious `os.system` calls).
- Executor confines runs to a temporary directory, passes only the sanctioned host/port, enforces timeouts, and captures stdout/stderr for auditing.
- Configuration IP ranges and command blacklists ensure only authorized infrastructure is touched.

## Troubleshooting
| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `pytest: command not found` | Virtualenv deps not installed | `python3 -m pip install -r requirements.txt` |
| `OpenRouter API key must be provided` | Missing flag/env var | Pass `--api-key` or export `OPENROUTER_API_KEY` |
| `RuntimeError: Jinja2 is required...` | HTML/MD report without optional dep | `python3 -m pip install jinja2` or choose `--format json` |
| `chromadb is required` | Missing vector DB package | Ensure `chromadb` is installed via requirements |
| Script validation failure | Generated code missing required structure | Inspect `script_generation` metadata and tweak context rules/RAG settings |

## Development & Testing
Project layout:
```
auvap/
	config/          # Context loader + user rules
	execution/       # Validator and executor
	llm/             # OpenRouter client + LLM agents
	parsers/         # Nessus parser
	rag/             # Chroma-backed memory system
	reporting/       # Report generator + templates
	tests/           # Pytest suites
```

Run unit tests (requires dependencies):
```bash
pytest tests/test_validator.py tests/test_executor.py tests/test_rag_memory.py
```

Recommended future additions:
- `tests/test_nessus_parser.py` for XML parsing edge cases.
- `tests/test_integration.py` with mocked LLM clients to exercise the full pipeline deterministically.

## Contributing
1. Fork / create branch.
2. Add or update unit tests.
3. Run `pytest` and, optionally, `python main.py --dry-run ...` against sample artifacts.
4. Open a PR summarizing context rule changes or new exploit techniques captured in RAG.

## Legal & Ethical Notice
AUVAP is designed for authorized penetration testing in lab or contracted environments. Running the framework against systems without explicit permission is prohibited. Always ensure scope alignment, credential handling, and data retention comply with organizational and legal requirements.
