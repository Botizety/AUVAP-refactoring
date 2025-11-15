#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ROOT_DIR/.env"
  set +a
fi

# Check for appropriate API key based on provider
if [ "${LLM_PROVIDER:-openrouter}" = "gemini" ]; then
  : "${GEMINI_API_KEY:?GEMINI_API_KEY must be set in .env when using Gemini provider}"
else
  : "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set in .env when using OpenRouter provider}"
fi

find_python() {
  local candidates=(
    "$ROOT_DIR/venv/bin/python"
    "$ROOT_DIR/.venv/bin/python"
    "$ROOT_DIR/../.venv/bin/python"
  )
  for candidate in "${candidates[@]}"; do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return
    fi
  done
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return
  fi
  echo "python"  # Last resort; will likely fail later.
}

PYTHON_BIN="$(find_python)"

DEFAULT_CONFIG="${AUVAP_DEFAULT_CONFIG:-config/context_rules.json}"
DEFAULT_RAG_DIR="${AUVAP_DEFAULT_RAG_DIR:-./rag_memory}"
DEFAULT_FORMAT="${AUVAP_DEFAULT_FORMAT:-json}"
DEFAULT_OUTPUT_DIR="${AUVAP_DEFAULT_OUTPUT_DIR:-reports}"
AUTO_VERBOSE="${AUVAP_AUTO_VERBOSE:-true}"

declare -a PASSTHROUGH_ARGS=()
HELP_MODE=false
USER_NESSUS=false
USER_CONFIG=false
USER_RAG=false
USER_FORMAT=false
USER_OUTPUT=false
USER_VERBOSE=false

NESSUS_VALUE=""
CONFIG_VALUE="$DEFAULT_CONFIG"
RAG_VALUE="$DEFAULT_RAG_DIR"
FORMAT_VALUE="$DEFAULT_FORMAT"
OUTPUT_VALUE=""
POSITIONAL_NESSUS=""

to_lower() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

resolve_path() {
  case "$1" in
    /*) echo "$1" ;;
    *) echo "$ROOT_DIR/$1" ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h)
      HELP_MODE=true
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
    --nessus)
      USER_NESSUS=true
      NESSUS_VALUE="$2"
      shift 2
      ;;
    --nessus=*)
      USER_NESSUS=true
      NESSUS_VALUE="${1#*=}"
      shift
      ;;
    --config)
      USER_CONFIG=true
      CONFIG_VALUE="$2"
      shift 2
      ;;
    --config=*)
      USER_CONFIG=true
      CONFIG_VALUE="${1#*=}"
      shift
      ;;
    --rag-dir)
      USER_RAG=true
      RAG_VALUE="$2"
      shift 2
      ;;
    --rag-dir=*)
      USER_RAG=true
      RAG_VALUE="${1#*=}"
      shift
      ;;
    --format)
      USER_FORMAT=true
      FORMAT_VALUE="$2"
      shift 2
      ;;
    --format=*)
      USER_FORMAT=true
      FORMAT_VALUE="${1#*=}"
      shift
      ;;
    --output)
      USER_OUTPUT=true
      OUTPUT_VALUE="$2"
      shift 2
      ;;
    --output=*)
      USER_OUTPUT=true
      OUTPUT_VALUE="${1#*=}"
      shift
      ;;
    --verbose)
      USER_VERBOSE=true
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
    --verbose=*)
      USER_VERBOSE=true
      PASSTHROUGH_ARGS+=("--verbose")
      shift
      ;;
    --*)
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
    *)
      if [ -z "$POSITIONAL_NESSUS" ]; then
        POSITIONAL_NESSUS="$1"
      else
        PASSTHROUGH_ARGS+=("$1")
      fi
      shift
      ;;
  esac
done

if [ "$HELP_MODE" = true ]; then
  exec "$PYTHON_BIN" "$ROOT_DIR/main.py" "${PASSTHROUGH_ARGS[@]}"
fi

NESSUS_SOURCE="${NESSUS_VALUE:-$POSITIONAL_NESSUS}"
if [ -z "$NESSUS_SOURCE" ]; then
  echo "Usage: $(basename "$0") <nessus_file> [additional CLI args]" >&2
  exit 1
fi

if [ ${#PASSTHROUGH_ARGS[@]} -eq 0 ]; then
  PASSTHROUGH_ARGS=("--nessus" "$NESSUS_SOURCE")
else
  PASSTHROUGH_ARGS=("--nessus" "$NESSUS_SOURCE" "${PASSTHROUGH_ARGS[@]}")
fi

if [ "$USER_CONFIG" = false ]; then
  PASSTHROUGH_ARGS+=("--config" "$CONFIG_VALUE")
fi

if [ "$USER_RAG" = false ]; then
  PASSTHROUGH_ARGS+=("--rag-dir" "$RAG_VALUE")
fi

if [ "$USER_FORMAT" = false ]; then
  PASSTHROUGH_ARGS+=("--format" "$FORMAT_VALUE")
fi

OUTPUT_TARGET=""
if [ "$USER_OUTPUT" = false ]; then
  BASENAME="$(basename "$NESSUS_SOURCE")"
  BASENAME="${BASENAME%.nessus}"
  BASENAME=${BASENAME:-auvap}
  OUTPUT_VALUE="$DEFAULT_OUTPUT_DIR/${BASENAME}_run.${FORMAT_VALUE}"
  OUTPUT_TARGET="$(resolve_path "$OUTPUT_VALUE")"
  PASSTHROUGH_ARGS+=("--output" "$OUTPUT_TARGET")
else
  OUTPUT_TARGET="$(resolve_path "$OUTPUT_VALUE")"
  PASSTHROUGH_ARGS+=("--output" "$OUTPUT_TARGET")
fi

if [ "$(to_lower "$AUTO_VERBOSE")" != "false" ] && [ "$USER_VERBOSE" = false ]; then
  PASSTHROUGH_ARGS+=("--verbose")
fi

OUTPUT_DIRNAME="$(dirname "$OUTPUT_TARGET")"
if [ -n "$OUTPUT_DIRNAME" ] && [ ! -d "$OUTPUT_DIRNAME" ]; then
  mkdir -p "$OUTPUT_DIRNAME"
fi

exec "$PYTHON_BIN" "$ROOT_DIR/main.py" "${PASSTHROUGH_ARGS[@]}"
