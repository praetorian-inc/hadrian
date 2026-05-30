#!/usr/bin/env bash
# Provider-agnostic LLM helpers for the live-test scripts. SOURCE THIS FILE — do not execute directly.

# detect_planner_provider — echoes the first available LLM provider
# (openai | anthropic | ollama) or empty string if none is reachable.
# Priority: OPENAI_API_KEY → ANTHROPIC_API_KEY → ollama (reachable AND model
# present) → "".
detect_planner_provider() {
    if [ -n "${OPENAI_API_KEY:-}" ]; then
        echo "openai"
    elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        echo "anthropic"
    elif _ollama_has_model; then
        echo "ollama"
    else
        echo ""
    fi
}

# _ollama_has_model — returns 0 iff ollama is reachable AND the model hadrian
# will use (OLLAMA_MODEL, else llama3.2:latest) is present in /api/tags.
#
# Reachability alone is insufficient: a running ollama daemon with the model
# NOT pulled would let detect_planner_provider report "ollama", but the
# crapi-planner run uses --planner (not --planner-only), so hadrian silently
# falls back to brute-force and the row reports PASS without exercising the
# planner. Requiring the model present makes "ollama" mean "usable".
# Couples to hadrian's default model string; override with OLLAMA_MODEL.
_ollama_has_model() {
    local host="${OLLAMA_HOST:-http://localhost:11434}"
    local want="${OLLAMA_MODEL:-llama3.2:latest}"
    local tags
    tags=$(curl -sf --max-time 2 "${host}/api/tags" 2>/dev/null) || return 1
    printf '%s' "$tags" | python3 -c '
import json, sys
want = sys.argv[1]
try:
    models = json.load(sys.stdin).get("models", [])
except (ValueError, TypeError):
    sys.exit(1)
base = want.split(":")[0]
names = {m.get("name", "") for m in models}
sys.exit(0 if (want in names or any(n.split(":")[0] == base for n in names)) else 1)
' "$want"
}
