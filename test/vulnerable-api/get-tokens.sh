#!/bin/bash
# Script to obtain JWT tokens for bearer auth testing with Hadrian
# Usage: source get-tokens.sh
#
# This script:
# 1. Starts the vulnerable API in the background
# 2. Obtains JWT tokens for all users
# 3. Exports them as environment variables
# 4. Stops the API (you'll restart it for testing)

set -e

API_URL="${API_URL:-http://localhost:8889}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Hadrian Token Generator ==="
echo ""

# Check if API is running
if curl -s "$API_URL/health" > /dev/null 2>&1; then
    echo "API is already running at $API_URL"
else
    echo "Starting vulnerable API..."
    cd "$SCRIPT_DIR"

    # Build if needed
    if [ ! -f vulnerable-api ]; then
        echo "Building API..."
        GOWORK=off go build -o vulnerable-api .
    fi

    # Start API
    AUTH_METHOD=bearer ./vulnerable-api &
    API_PID=$!
    echo "Started API with PID $API_PID"

    # Wait for API to be ready
    for i in {1..10}; do
        if curl -s "$API_URL/health" > /dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
fi

echo ""
echo "Obtaining tokens..."
echo ""

# Get admin token
ADMIN_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}')
export ADMIN_TOKEN=$(echo "$ADMIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Get user1 token
USER1_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"user1","password":"user1pass"}')
export USER1_TOKEN=$(echo "$USER1_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Get user2 token
USER2_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"user2","password":"user2pass"}')
export USER2_TOKEN=$(echo "$USER2_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Kill the API if we started it
if [ -n "$API_PID" ]; then
    kill $API_PID 2>/dev/null || true
    echo "Stopped temporary API instance"
fi

echo ""
echo "=== Tokens Obtained ==="
echo ""
echo "ADMIN_TOKEN=${ADMIN_TOKEN:0:50}..."
echo "USER1_TOKEN=${USER1_TOKEN:0:50}..."
echo "USER2_TOKEN=${USER2_TOKEN:0:50}..."
echo ""
echo "Environment variables exported. You can now run Hadrian:"
echo ""
echo "  # Start the API"
echo "  AUTH_METHOD=bearer ./vulnerable-api &"
echo ""
echo "  # Run Hadrian"
echo "  hadrian test \\"
echo "    --api openapi.yaml \\"
echo "    --roles roles.yaml \\"
echo "    --auth auth-bearer.yaml \\"
echo "    --verbose"
echo ""
