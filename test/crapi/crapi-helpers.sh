#!/usr/bin/env bash
# =============================================================================
# crapi-helpers.sh
#
# Shared crAPI helpers for the live-test scripts. SOURCE THIS FILE — do not
# execute it directly. It defines:
#
#   - Canonical user identities (CRAPI_*_EMAIL, CRAPI_PASSWORD, etc.) used by
#     setup-live-targets.sh, run-live-tests.sh, and test-llm-planner.sh so
#     every test against crAPI uses the same accounts. All values are
#     overridable via environment variables.
#
#   - crapi_signup, crapi_login, crapi_mechanic_signup: thin wrappers around
#     the corresponding HTTP endpoints. Idempotent — duplicate signup against
#     a dirty DB is silently ignored.
#
#   - crapi_setup_users: signs up the full canonical roster (admin, two
#     users, mechanic). Safe to call multiple times.
#
#   - crapi_patch_openapi_spec: copies the OpenAPI spec to a destination
#     directory, substituting localhost:<default> with localhost:<port>.
#     Echoes the resulting path. Used by every script that points hadrian at
#     the spec when CRAPI_PORT differs from the spec's hardcoded default.
#
# Sourcing this file does NOT make any network calls. The functions only
# touch the network when invoked.
# =============================================================================

# Default port the spec hardcodes. Used when patching to a different port.
: "${CRAPI_OPENAPI_SPEC_DEFAULT_PORT:=8888}"

# Canonical user identities. Each script that talks to crAPI uses these so
# the DB ends up with the same users regardless of entry point.
: "${CRAPI_PASSWORD:=HadrianTest123!}"
: "${CRAPI_ADMIN_EMAIL:=hadrian-admin@test.com}"
: "${CRAPI_ADMIN_NUMBER:=1111111111}"
: "${CRAPI_USER_EMAIL:=hadrian-user1@test.com}"
: "${CRAPI_USER_NUMBER:=2222222222}"
: "${CRAPI_USER2_EMAIL:=hadrian-user2@test.com}"
: "${CRAPI_USER2_NUMBER:=3333333333}"
: "${CRAPI_MECHANIC_EMAIL:=hadrian-mechanic@test.com}"
: "${CRAPI_MECHANIC_NUMBER:=4444444444}"
: "${CRAPI_MECHANIC_CODE:=TRAC_MECH1}"

# _crapi_json <key=value>... — emits a JSON object with each key set to
# the corresponding value, using python3's json.dumps to handle
# escaping. We use python3 here because every other crAPI helper
# already requires it (login parses the token), and printf-built JSON
# silently breaks if a value contains '"' or '\' — overrides like
# CRAPI_PASSWORD='ab"cd' or names with backslashes would produce
# malformed bodies that the API rejects, surfacing only as silent
# retry exhaustion.
_crapi_json() {
    python3 -c '
import json, sys
out = {}
for arg in sys.argv[1:]:
    k, _, v = arg.partition("=")
    out[k] = v
sys.stdout.write(json.dumps(out))
' "$@"
}

# crapi_signup <base_url> <email> <name> <number> <password>
# Returns 0 always; signup against an already-registered email is treated
# as success.
crapi_signup() {
    local base_url="$1" email="$2" name="$3" number="$4" password="$5"
    _crapi_json "email=$email" "name=$name" "number=$number" "password=$password" | \
        curl -sf -X POST "${base_url}/identity/api/auth/signup" \
            -H "Content-Type: application/json" \
            --data-binary @- 2>/dev/null || true
}

# crapi_login <base_url> <email> <password>
# Echoes the bearer token, or empty string on failure.
crapi_login() {
    local base_url="$1" email="$2" password="$3"
    _crapi_json "email=$email" "password=$password" | \
        curl -sf -X POST "${base_url}/identity/api/auth/login" \
            -H "Content-Type: application/json" \
            --data-binary @- 2>/dev/null | \
        python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo ""
}

# crapi_mechanic_signup <base_url> <email> <name> <number> <password> <code>
crapi_mechanic_signup() {
    local base_url="$1" email="$2" name="$3" number="$4" password="$5" code="$6"
    _crapi_json "email=$email" "name=$name" "number=$number" "password=$password" "mechanic_code=$code" | \
        curl -sf -X POST "${base_url}/workshop/api/mechanic/signup" \
            -H "Content-Type: application/json" \
            --data-binary @- 2>/dev/null || true
}

# _crapi_provision_user <base_url> <kind: regular|mechanic> <email> <name> <number> <password> [code]
# Signs up a single user, then verifies the result by attempting a
# login. Retries the signup up to CRAPI_PROVISION_RETRIES (default 5)
# times with linear backoff if verification fails — crAPI's identity
# and workshop services intermittently 4xx during the first few seconds
# after boot, and `crapi_signup` swallows that silently because it can
# also legitimately mean "user already exists." The login probe
# disambiguates: a non-empty token proves the row actually landed.
# Idempotent: a pre-existing user takes the fast path because login
# succeeds on the first try.
_crapi_provision_user() {
    local base_url="$1" kind="$2" email="$3" name="$4" number="$5" password="$6" code="${7:-}"
    local attempts="${CRAPI_PROVISION_RETRIES:-5}"
    local i=0
    while [ "$i" -lt "$attempts" ]; do
        i=$((i + 1))
        if [ "$kind" = "mechanic" ]; then
            crapi_mechanic_signup "$base_url" "$email" "$name" "$number" "$password" "$code" >/dev/null
        else
            crapi_signup "$base_url" "$email" "$name" "$number" "$password" >/dev/null
        fi
        local token
        token=$(crapi_login "$base_url" "$email" "$password")
        if [ -n "$token" ]; then
            return 0
        fi
        sleep $((i * 2))
    done
    echo "ERROR: could not provision crAPI user $email after $attempts attempts" >&2
    return 1
}

# crapi_setup_users <base_url>
# Signs up the canonical roster, verifying each user by login before
# moving on. Idempotent. Returns non-zero if any user could not be
# provisioned after retries.
crapi_setup_users() {
    local base_url="$1"
    _crapi_provision_user "$base_url" regular  "$CRAPI_ADMIN_EMAIL"    "Hadrian Admin"    "$CRAPI_ADMIN_NUMBER"    "$CRAPI_PASSWORD" || return 1
    _crapi_provision_user "$base_url" regular  "$CRAPI_USER_EMAIL"     "Hadrian User1"    "$CRAPI_USER_NUMBER"     "$CRAPI_PASSWORD" || return 1
    _crapi_provision_user "$base_url" regular  "$CRAPI_USER2_EMAIL"    "Hadrian User2"    "$CRAPI_USER2_NUMBER"    "$CRAPI_PASSWORD" || return 1
    _crapi_provision_user "$base_url" mechanic "$CRAPI_MECHANIC_EMAIL" "Hadrian Mechanic" "$CRAPI_MECHANIC_NUMBER" "$CRAPI_PASSWORD" "$CRAPI_MECHANIC_CODE" || return 1
}

# crapi_patch_openapi_spec <src_spec_path> <target_port> <dest_dir>
# Copies the spec to <dest_dir>/crapi-openapi-spec.json, substituting the
# default port with <target_port>. If <target_port> equals the default,
# echoes <src_spec_path> unchanged (no copy). Echoes the spec path on
# stdout. Returns non-zero on failure.
crapi_patch_openapi_spec() {
    local src="$1" target_port="$2" dest_dir="$3"
    if [ ! -f "$src" ]; then
        echo "crapi_patch_openapi_spec: source spec not found: $src" >&2
        return 1
    fi
    if [ "$target_port" = "$CRAPI_OPENAPI_SPEC_DEFAULT_PORT" ]; then
        echo "$src"
        return 0
    fi
    mkdir -p "$dest_dir"
    local dst="${dest_dir}/crapi-openapi-spec.json"
    sed "s|http://localhost:${CRAPI_OPENAPI_SPEC_DEFAULT_PORT}|http://localhost:${target_port}|g" \
        "$src" > "$dst"
    # Validate the substitution actually landed. If the source spec no
    # longer contains localhost:<default> (e.g. upstream changed the
    # spec format or hostname), sed silently produces a copy with no
    # change and downstream callers point hadrian at the wrong port. Be
    # loud — same defense pattern as patch_crapi_compose_port.
    if ! grep -q "localhost:${target_port}" "$dst"; then
        echo "crapi_patch_openapi_spec: substitution did not land in $dst (source missing localhost:${CRAPI_OPENAPI_SPEC_DEFAULT_PORT}?)" >&2
        rm -f "$dst"
        return 1
    fi
    echo "$dst"
}

# crapi_resolve_spec <src_spec> <port> <cache_dir>
#
# Resolves the OpenAPI spec path for hadrian. Preference order:
#   1. If $CRAPI_SPEC_FILE (from .live-test-config) exists AND its baked-in
#      port matches <port>, echo it unchanged.
#   2. Otherwise, patch <src_spec> into <cache_dir> via
#      crapi_patch_openapi_spec and echo the new path.
#
# Echoes the resolved path on stdout. Logs to stderr.
# Returns non-zero if the resolved path is empty or does not exist.
crapi_resolve_spec() {
    local src_spec="$1" port="$2" cache_dir="$3"
    local resolved=""

    # Anchor the port match on a non-digit / end-of-line boundary so
    # CRAPI_PORT=889 doesn't accept a stale spec pinned to localhost:8895
    # (substring match).
    if [ -n "${CRAPI_SPEC_FILE:-}" ] && [ -f "${CRAPI_SPEC_FILE}" ] \
            && grep -qE "localhost:${port}([^0-9]|\$)" "$CRAPI_SPEC_FILE"; then
        resolved="$CRAPI_SPEC_FILE"
    else
        if [ -n "${CRAPI_SPEC_FILE:-}" ] && [ -f "${CRAPI_SPEC_FILE}" ]; then
            echo "[INFO] Cached spec at ${CRAPI_SPEC_FILE} does not match CRAPI_PORT=${port}; re-patching." >&2
        fi
        mkdir -p "$cache_dir"
        resolved=$(crapi_patch_openapi_spec "$src_spec" "$port" "$cache_dir")
    fi

    if [ -z "$resolved" ] || [ ! -f "$resolved" ]; then
        echo "crapi_resolve_spec: could not resolve spec (empty path or missing file)" >&2
        return 1
    fi
    echo "$resolved"
}
