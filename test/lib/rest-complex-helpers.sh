#!/usr/bin/env bash
# =============================================================================
# rest-complex-helpers.sh
#
# Shared helpers for the vulnerable-rest-complex target. Sourced (not executed)
# by the scripts that drive that target.
#
# Sourced by:
#   - test/test-llm-planner.sh
#   - test/test-llm-triage.sh
#
# Requires the sourcing script to have set REST_COMPLEX_URL before calling.
# =============================================================================

# rest_complex_login <username> <password>
# Logs in via POST /api/auth/login and prints the bearer token (empty on failure).
rest_complex_login() {
    local username="$1" password="$2"
    printf '{"username":"%s","password":"%s"}' "$username" "$password" | \
        curl -sf -X POST "${REST_COMPLEX_URL}/api/auth/login" \
            -H "Content-Type: application/json" \
            --data-binary @- 2>/dev/null | \
        python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo ""
}
