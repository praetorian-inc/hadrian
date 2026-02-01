#!/bin/bash
# Setup script to create test videos for crAPI users
# Required for BFLA and BOPLA mass assignment tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRAPI_HOST="${CRAPI_HOST:-http://192.168.65.254:8888}"

# Source environment variables
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
else
    echo "ERROR: .env file not found at $SCRIPT_DIR/.env"
    echo "Please create it with CRAPI_USER_TOKEN and CRAPI_USER2_TOKEN"
    exit 1
fi

# Create a temporary test video file
TMP_VIDEO="/tmp/hadrian_test_video.mp4"
echo "test video content for hadrian security testing" > "$TMP_VIDEO"

upload_video() {
    local token="$1"
    local user_name="$2"
    local video_name="$3"

    if [ -z "$token" ]; then
        echo "SKIP: No token for $user_name"
        return 0
    fi

    echo "Uploading video for $user_name..."

    response=$(curl -s -X POST "$CRAPI_HOST/identity/api/v2/user/videos" \
        -H "Authorization: Bearer $token" \
        -F "file=@$TMP_VIDEO" \
        -F "videoName=$video_name")

    if echo "$response" | grep -q "error\|Error\|ERROR"; then
        echo "  WARN: $response"
    else
        echo "  OK: Video uploaded"
    fi
}

verify_video() {
    local token="$1"
    local user_name="$2"

    if [ -z "$token" ]; then
        return 0
    fi

    video_id=$(curl -s -H "Authorization: Bearer $token" \
        "$CRAPI_HOST/identity/api/v2/user/dashboard" | \
        grep -o '"video_id":[0-9]*' | cut -d: -f2)

    if [ -n "$video_id" ] && [ "$video_id" != "0" ]; then
        echo "  $user_name: video_id=$video_id ✓"
    else
        echo "  $user_name: No video found ✗"
    fi
}

echo "=== Uploading Test Videos ==="
echo "Host: $CRAPI_HOST"
echo ""

upload_video "$CRAPI_USER_TOKEN" "user" "user_test_video"
upload_video "$CRAPI_USER2_TOKEN" "user2" "user2_test_video"
upload_video "$CRAPI_MECHANIC_TOKEN" "mechanic" "mechanic_test_video"

echo ""
echo "=== Verifying Videos ==="

verify_video "$CRAPI_USER_TOKEN" "user"
verify_video "$CRAPI_USER2_TOKEN" "user2"
verify_video "$CRAPI_MECHANIC_TOKEN" "mechanic"

# Cleanup
rm -f "$TMP_VIDEO"

echo ""
echo "Done. You can now run Hadrian tests."
