#!/usr/bin/env bash
# Run ws-audio-test against a running Janus instance.
#
# Usage:
#   ./test_ws_audio.sh [command]
#
# Commands: signaling | plain-rtp | ws-stream | ws-e2e | all (default: ws-e2e)
#
# Environment (export or prefix the command — a semicolon does NOT pass vars to the script):
#   JANUS_HTTP=https://host/janus ./test_ws_audio.sh
#   export JANUS_HTTP=https://host/janus && ./test_ws_audio.sh
#
#   JANUS_HTTP   Janus HTTP API (default: http://127.0.0.1:8088/janus)
#   TOKEN        HMAC token if token_auth_secret is set
#   ROOM         AudioBridge room id (default: ws-audio-test)
#   LOCAL_IP     IP Janus uses to reach plain-RTP client (default: 127.0.0.1)
#   EXPECT_RX    Minimum inbound RTP packets on WS leg for ws-e2e (default: 50)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="${SCRIPT_DIR}/ws-audio-test"

JANUS_HTTP="${JANUS_HTTP:-http://127.0.0.1:8088/janus}"
TOKEN="${TOKEN:-}"
ROOM="${ROOM:-ws-audio-test}"
LOCAL_IP="${LOCAL_IP:-127.0.0.1}"
EXPECT_RX="${EXPECT_RX:-50}"
CMD="${1:-ws-e2e}"

export JANUS_HTTP TOKEN ROOM LOCAL_IP EXPECT_RX

cd "${TEST_DIR}"
make build

run_cmd() {
	case "$1" in
		signaling)
			./bin/ws-audio-test signaling --media websocket
			;;
		plain-rtp)
			./bin/ws-audio-test plain-rtp --tone --expect-rx "${EXPECT_RX}"
			;;
		ws-stream)
			./bin/ws-audio-test ws-stream --tone --expect-rx "${EXPECT_RX}"
			;;
		ws-e2e)
			./bin/ws-audio-test ws-e2e --expect-rx "${EXPECT_RX}"
			;;
		all)
			run_cmd signaling
			run_cmd plain-rtp
			run_cmd ws-stream
			run_cmd ws-e2e
			;;
		*)
			echo "Unknown command: $1 (use signaling|plain-rtp|ws-stream|ws-e2e|all)" >&2
			exit 2
			;;
	esac
}

run_cmd "${CMD}"
