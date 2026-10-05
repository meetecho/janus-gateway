# ws-audio-test

CLI to validate Janus AudioBridge **plain RTP** and core **RTP-over-WebSocket** (`rtpws`).

## Prerequisites

- Janus built with `--enable-websockets` (libwebsockets)
- AudioBridge plugin enabled
- Core media listener enabled in `janus.jcfg`:

```jcfg
rtpws: {
    enable_rtp_ws = true
    port = 8190
    path = "/rtp-ws"
    # public_url = "wss://media.example.com"   # optional; returned in join response
    # secure = true
    # cert_pem = "/path/to/cert.pem"
    # cert_key = "/path/to/key.pem"
}
```

- Room allows WS participants (`allow_ws_participants = true`, or let the CLI create the room with that flag)
- HMAC token if `token_auth_secret` is configured (`export TOKEN=...`)

Join with `"codec": "opus"` (default), `"pcma"`, `"pcmu"`, `"l16"` (L16/16000), or `"l16-48"` (L16/48000); the WebSocket `call_info` frame reports the negotiated payload type, sample rate, and `framing`.

## Build

```bash
cd test/ws-audio-test
go build -o bin/ws-audio-test .
```

## Commands

| Command | What it tests |
|---------|----------------|
| `signaling` | Room create + join; prints `websocket_media.url` or `rtp` details |
| `plain-rtp` | UDP RTP **in** (tone → Janus) and **out** (mix → client) with counters |
| `ws-stream` | Join with `media=websocket`, then WS binary RTP **in** and **out** |
| `ws-e2e` | Plain-RTP feeder + WS participant; verifies **outbound** mix over WS |

### Quick run

```bash
export JANUS_HTTP=http://127.0.0.1:8088/janus
export TOKEN=your-hmac-token   # if token auth is enabled
export ROOM=ws-audio-test

# Signaling only (Opus WS leg)
go run . signaling --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" --media websocket

# G.711 A-law over WebSocket
go run . ws-stream --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" --codec pcma --tone --expect-rx 50

# WS bidirectional (auto-join, default Opus)
go run . ws-stream --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" --tone --expect-rx 50

# Full outbound mix test: plain-RTP talks, WS leg receives mix
go run . ws-e2e --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" --local-ip 127.0.0.1 --expect-rx 50
```

`ws-stream` also accepts `--ws-url` directly if you already have a `websocket_media.url` from a prior join. Use `--codec` when auto-joining via `--janus-http` (also available as `CODEC` env var).

### Codecs

| `--codec` | RTP PT | Sample rate | Notes |
|-----------|--------|-------------|-------|
| `opus` (default) | 100 | 48 kHz (room rate) | Tone uses placeholder payload bytes (connectivity test) |
| `pcma` | 8 | 8 kHz | G.711 A-law encoded 440 Hz tone |
| `pcmu` | 0 | 8 kHz | G.711 μ-law encoded 440 Hz tone |
| `l16` | dynamic | 16 kHz | 16-bit big-endian linear PCM; room `sampling_rate` must be 16000 |
| `l16-48` | dynamic | 48 kHz | 16-bit big-endian linear PCM; room `sampling_rate` must be 48000 |

After connecting to the WebSocket media URL, read the JSON `call_info` text frame and match its `payload_type`, `sample_rate`, and `codec` when sending binary RTP.

### Framing (`--framing`)

By default the WS wire carries **full RTP packets** (`--framing rtp`). Pass `--framing payload` to
join with `"ws_framing": "payload"`: the wire then carries **raw codec payloads** with no RTP header.
The gateway strips the RTP header outbound and synthesizes one inbound. This is meant for external
AI/STT/TTS clients that don't want to parse or emit RTP. Combine with `--codec l16`/`l16-48` for
plain linear PCM that most providers accept directly.

```bash
# Raw G.711 payloads over WS (no RTP header on the wire)
go run . ws-stream --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" \
  --codec pcmu --framing payload --tone --expect-rx 50

# Raw L16/16000 PCM payloads (ideal for STT/TTS)
go run . ws-stream --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" \
  --codec l16 --framing payload --tone --expect-rx 50
```

### Bidirectional checks

All streaming modes track `tx` / `rx` packet counts and bytes. Use `--expect-rx N` to fail if Janus did not deliver at least `N` inbound RTP packets (outbound leg).

```bash
# Plain RTP both ways
go run . plain-rtp \
  --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" --local-ip 127.0.0.1 \
  --tone --expect-rx 50

# WS media both ways (auto-join)
go run . ws-stream \
  --janus-http "$JANUS_HTTP" --token "$TOKEN" --room "$ROOM" \
  --tone --expect-rx 50

# Or connect to an existing media URL
go run . ws-stream \
  --ws-url 'ws://127.0.0.1:8190/rtp-ws?sid=...' \
  --tone --expect-rx 50
```

## Protocol

1. **Signaling**: normal Janus API — `join` with `"media": "websocket"` (optionally `"ws_framing": "payload"`); AudioBridge returns `websocket_media.url`.
2. **Media**: connect to that URL; server sends JSON `call_info` (text frame) including `framing`.
3. Client and server exchange **binary** WebSocket frames: full RTP packets (12+ bytes) in `rtp` framing, or raw codec payloads in `payload` framing.
