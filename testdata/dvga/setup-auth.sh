#!/bin/bash
# DVGA Authentication Setup Script
# Retrieves tokens from DVGA for Hadrian GraphQL security testing
#
# Default DVGA user: admin:changeme
# Additional users can be created via the DVGA web UI

set -e

# Configuration
DVGA_ENDPOINT="${DVGA_ENDPOINT:-http://172.17.0.1:5013/graphql}"
OUTPUT_FILE="${OUTPUT_FILE:-testdata/dvga/auth-tokens.yaml}"
ENV_FILE="${ENV_FILE:-testdata/dvga/.env}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}   DVGA Authentication Setup${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo ""
echo -e "Target: ${CYAN}$DVGA_ENDPOINT${NC}"
echo ""

# Check if DVGA is reachable
echo -e "${YELLOW}[1/5] Checking DVGA connection...${NC}"
if ! curl -s -X POST "$DVGA_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __typename }"}' | grep -q "Query"; then
    echo -e "${RED}Error: Cannot connect to DVGA at $DVGA_ENDPOINT${NC}"
    echo ""
    echo "Make sure DVGA is running:"
    echo "  docker run -d -p 5013:5013 --name dvga dolevf/dvga:latest"
    exit 1
fi
echo -e "  ${GREEN}✓ DVGA is reachable${NC}"
echo ""

# Function to login and get token
get_token() {
    local username="$1"
    local password="$2"
    
    local login_result=$(curl -s -X POST "$DVGA_ENDPOINT" \
        -H "Content-Type: application/json" \
        --data-raw "{\"query\":\"mutation { login(username: \\\"$username\\\", password: \\\"$password\\\") { accessToken } }\"}")

    local access_token=$(echo "$login_result" | grep -o '"accessToken":"ey[^"]*"' | cut -d'"' -f4)

    if [ -n "$access_token" ]; then
        echo "$access_token"
    fi
}

# List existing users
echo -e "${YELLOW}[2/5] Discovering DVGA users...${NC}"
USERS=$(curl -s -X POST "$DVGA_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ users { username } }"}' | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
echo "  Found users: $USERS"
echo ""

# Get admin token (default: admin:changeme)
echo -e "${YELLOW}[3/5] Authenticating...${NC}"

# Try common passwords for admin
ADMIN_TOKEN=""
for pass in "changeme" "admin" "password" "admin123"; do
    ADMIN_TOKEN=$(get_token "admin" "$pass")
    if [ -n "$ADMIN_TOKEN" ]; then
        echo -e "  ${GREEN}✓ admin token acquired${NC}"
        break
    fi
done

if [ -z "$ADMIN_TOKEN" ]; then
    echo -e "  ${RED}✗ Failed to get admin token${NC}"
    echo "  Try resetting DVGA: docker restart dvga"
fi

# Try to get operator token
OPERATOR_TOKEN=""
for pass in "changeme" "operator" "password"; do
    OPERATOR_TOKEN=$(get_token "operator" "$pass")
    if [ -n "$OPERATOR_TOKEN" ]; then
        echo -e "  ${GREEN}✓ operator token acquired${NC}"
        break
    fi
done

if [ -z "$OPERATOR_TOKEN" ]; then
    echo -e "  ${YELLOW}⚠ operator token unavailable (using admin)${NC}"
    OPERATOR_TOKEN="$ADMIN_TOKEN"
fi

echo ""

# Generate auth config file
echo -e "${YELLOW}[4/5] Generating configuration files...${NC}"

cat > "$OUTPUT_FILE" << YAML
# DVGA Authentication Configuration
# Generated: $(date -Iseconds)
# Target: $DVGA_ENDPOINT

method: bearer
location: header
key_name: Authorization

roles:
  admin:
    # High-privilege admin user
    token: "$ADMIN_TOKEN"
    
  operator:
    # Mid-privilege operator user
    token: "$OPERATOR_TOKEN"
    
  attacker:
    # Attacker role for BOLA/BFLA tests (uses operator)
    token: "$OPERATOR_TOKEN"
    
  victim:
    # Victim role for BOLA/BFLA tests (uses admin data)
    token: "$ADMIN_TOKEN"
YAML

echo -e "  ${GREEN}✓ $OUTPUT_FILE${NC}"

# Save environment file
cat > "$ENV_FILE" << ENVFILE
# DVGA Test Environment
# Generated: $(date -Iseconds)
DVGA_ENDPOINT=$DVGA_ENDPOINT
DVGA_ADMIN_TOKEN=$ADMIN_TOKEN
DVGA_OPERATOR_TOKEN=$OPERATOR_TOKEN
ENVFILE

echo -e "  ${GREEN}✓ $ENV_FILE${NC}"
echo ""

# Create test data for BOLA testing
echo -e "${YELLOW}[5/5] Creating test data...${NC}"

if [ -n "$ADMIN_TOKEN" ]; then
    # Create admin's private paste
    RESULT=$(curl -s -X POST "$DVGA_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -d '{"query": "mutation { createPaste(title: \"Admin Confidential\", content: \"Secret admin data - DO NOT ACCESS\", public: false) { paste { id } } }"}')
    
    PASTE_ID=$(echo "$RESULT" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "$PASTE_ID" ]; then
        echo -e "  ${GREEN}✓ Created admin paste (ID: $PASTE_ID)${NC}"
        echo "DVGA_ADMIN_PASTE_ID=$PASTE_ID" >> "$ENV_FILE"
    fi
    
    # Create victim's private paste
    RESULT=$(curl -s -X POST "$DVGA_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -d '{"query": "mutation { createPaste(title: \"Victim PII\", content: \"SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111\", public: false) { paste { id } } }"}')
    
    PASTE_ID=$(echo "$RESULT" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "$PASTE_ID" ]; then
        echo -e "  ${GREEN}✓ Created victim paste (ID: $PASTE_ID)${NC}"
        echo "DVGA_VICTIM_PASTE_ID=$PASTE_ID" >> "$ENV_FILE"
    fi
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}   Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Quick Start:${NC}"
echo ""
echo "  # Load environment variables"
echo "  source testdata/dvga/.env"
echo ""
echo "  # Run GraphQL security tests"
echo "  ./hadrian test graphql \\"
echo "    --target http://172.17.0.1:5013 \\"
echo "    --templates templates/graphql \\"
echo "    --auth testdata/dvga/auth-tokens.yaml \\"
echo "    --roles testdata/dvga/dvga-roles.yaml \\"
echo "    --verbose"
echo ""
echo "  # Or run integration tests"
echo "  export DVGA_ADMIN_TOKEN=\"\$DVGA_ADMIN_TOKEN\""
echo "  GOWORK=off go test -tags=integration ./pkg/plugins/graphql/... -v"
echo ""
