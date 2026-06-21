#!/usr/bin/env bash
# Unit test for targets_contains. Sources the helper directly; no framework.
# Run with: ./test/test_targets_contains.sh
#
# targets_contains does an EXACT comma-delimited membership test on $TARGETS.
# The whole point is that "crapi" must NOT match "crapi-planner" (the substring
# bug the helper replaced), and vice-versa. Covers:
#   T1: member in the middle                 → match
#   T2: member at the start                  → match
#   T3: member at the end                    → match
#   T4: single-element list                  → match
#   T5: "crapi" must NOT match "crapi-planner" substring → no match
#   T6: "crapi-planner" present              → match (exact)
#   T7: absent member                        → no match
#   T8: empty/unset TARGETS                   → no match
set -u  # NOT -e: we want to catch failed assertions and keep going.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=target-helpers.sh
. "${SCRIPT_DIR}/target-helpers.sh"

pass=0; fail=0

# assert_match <label> <targets_csv> <name>   — expects targets_contains to return 0
assert_match() {
    # shellcheck disable=SC2034  # read by targets_contains (sourced) via the global $TARGETS
    TARGETS="$2"
    if targets_contains "$3"; then
        echo "  PASS: $1"; pass=$((pass + 1))
    else
        echo "  FAIL: $1 — expected match for '$3' in TARGETS='$2'"; fail=$((fail + 1))
    fi
}

# assert_no_match <label> <targets_csv> <name> — expects targets_contains to return non-zero
assert_no_match() {
    # shellcheck disable=SC2034  # read by targets_contains (sourced) via the global $TARGETS
    TARGETS="$2"
    if targets_contains "$3"; then
        echo "  FAIL: $1 — expected NO match for '$3' in TARGETS='$2'"; fail=$((fail + 1))
    else
        echo "  PASS: $1"; pass=$((pass + 1))
    fi
}

echo "T1: member in the middle"
assert_match    "T1 dvga in vulnerable-api,dvga,grpc" "vulnerable-api,dvga,grpc" "dvga"
echo "T2: member at the start"
assert_match    "T2 vulnerable-api at start" "vulnerable-api,dvga,grpc" "vulnerable-api"
echo "T3: member at the end"
assert_match    "T3 grpc at end" "vulnerable-api,dvga,grpc" "grpc"
echo "T4: single-element list"
assert_match    "T4 single crapi" "crapi" "crapi"
echo "T5: crapi must NOT match crapi-planner substring"
assert_no_match "T5 crapi does not match crapi-planner-only list" "crapi-planner" "crapi"
echo "T6: crapi-planner present → exact match"
assert_match    "T6 crapi-planner exact" "crapi,crapi-planner" "crapi-planner"
echo "T7: absent member"
assert_no_match "T7 grpc absent" "vulnerable-api,dvga" "grpc"
echo "T8: empty/unset TARGETS"
assert_no_match "T8 empty TARGETS" "" "crapi"

echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit $(( fail > 0 ? 1 : 0 ))
