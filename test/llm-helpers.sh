#!/usr/bin/env bash
# =============================================================================
# llm-helpers.sh
#
# Provider-agnostic LLM helpers for the live-test scripts. SOURCE THIS FILE —
# do not execute it directly.
#
# Defines:
#   detect_planner_provider — echoes the first available LLM provider
#     (openai | anthropic | ollama) or empty string if none is reachable.
#     Priority: OPENAI_API_KEY → ANTHROPIC_API_KEY → ollama probe → "".
# =============================================================================

# detect_planner_provider — echoes the first available LLM provider
# (openai | anthropic | ollama) or empty string if none is reachable.
# Priority: OPENAI_API_KEY → ANTHROPIC_API_KEY → ollama probe → "".
detect_planner_provider() {
    if [ -n "${OPENAI_API_KEY:-}" ]; then
        echo "openai"
    elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        echo "anthropic"
    elif curl -sf -o /dev/null --max-time 2 "${OLLAMA_HOST:-http://localhost:11434}/api/tags"; then
        echo "ollama"
    else
        echo ""
    fi
}
