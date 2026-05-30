# WebRTC-to-SIP Gateway Setup Guide

## Janus Gateway + SIP.js — Complete Integration Reference

This guide covers setting up an open-source WebRTC-to-SIP gateway using **Janus Gateway** (server-side) and **SIP.js** (browser-side), including architecture decisions, installation, configuration, and working examples.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [When to Use What](#when-to-use-what)
3. [Part 1: Janus Gateway Setup](#part-1-janus-gateway-setup)
4. [Part 2: SIP.js Setup](#part-2-sipjs-setup)
5. [Part 3: Integration Scenarios](#part-3-integration-scenarios)
6. [Network & Ports Reference](#network--ports-reference)
7. [Troubleshooting](#troubleshooting)
8. [Part 4: Fraud Prevention (CRITICAL)](#part-4-fraud-prevention-critical)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         ARCHITECTURE OPTION A                                 │
│                    Janus as WebRTC-to-SIP Gateway                             │
│                                                                              │
│  ┌───────────┐   WebSocket (8188)   ┌──────────────┐   SIP UDP/TCP   ┌─────────────┐
│  │  Browser  │ ◄─────────────────► │    Janus     │ ◄────────────► │  SIP Server  │
│  │ (janus.js)│   + WebRTC/DTLS      │   Gateway    │   + RTP         │  (Asterisk/  │
│  └───────────┘                      │ (Sofia-SIP)  │                 │  FreeSWITCH) │
│                                     └──────────────┘                 └─────────────┘
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                         ARCHITECTURE OPTION B                                 │
│                   SIP.js Direct to SIP Server                                 │
│                                                                              │
│  ┌───────────┐   SIP over WSS       ┌─────────────┐                         │
│  │  Browser  │ ◄─────────────────► │  SIP Server  │                         │
│  │ (SIP.js)  │   + WebRTC/DTLS      │  (with WSS   │                         │
│  └───────────┘                      │   module)    │                         │
│                                     └─────────────┘                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Key difference:**
- **Option A (Janus):** Browser never speaks SIP. Janus handles all SIP signaling internally via Sofia-SIP. Browser communicates with Janus using a JSON-based API over WebSocket.
- **Option B (SIP.js):** Browser speaks SIP directly over WebSocket (RFC 7118). No gateway needed, but the SIP server must support WebSocket transport.

---

## When to Use What

| Scenario | Recommended Approach |
|----------|---------------------|
| SIP server has NO WebSocket support | **Janus + janus.js** (Option A) |
| SIP server supports WebSocket (Asterisk w/ `res_pjsip_transport_websocket`, FreeSWITCH, Kamailio) | **SIP.js directly** (Option B) |
| Need advanced WebRTC features (simulcast, recording, video rooms) AND SIP | **Janus** as gateway |
| Simple click-to-call from browser to SIP phone | Either works; SIP.js is simpler if WSS is available |
| Legacy PBX/PSTN integration | **Janus** (no WSS requirement on PBX) |
| Multiple concurrent calls from one browser tab | **SIP.js SessionManager** or **Janus with helper sessions** |

---

## Part 1: Janus Gateway Setup

### Prerequisites

Janus runs on **Linux** (recommended) or **macOS**. Windows is only supported via WSL.

### 1.1 Install Dependencies (Ubuntu/Debian)

```bash
# Core dependencies
sudo apt install -y \
  libmicrohttpd-dev libjansson-dev libssl-dev libsofia-sip-ua-dev \
  libglib2.0-dev libopus-dev libogg-dev libcurl4-openssl-dev \
  liblua5.3-dev libconfig-dev pkg-config libtool automake

# Build libnice from source (recommended over distro package)
git clone https://gitlab.freedesktop.org/libnice/libnice
cd libnice
meson --prefix=/usr build && ninja -C build && sudo ninja -C build install
cd ..

# Build libsrtp 2.x
wget https://github.com/cisco/libsrtp/archive/v2.2.0.tar.gz
tar xfv v2.2.0.tar.gz
cd libsrtp-2.2.0
./configure --prefix=/usr --enable-openssl
make shared_library && sudo make install
cd ..

# Build libwebsockets (for WebSocket transport)
git clone https://libwebsockets.org/repo/libwebsockets
cd libwebsockets
mkdir build && cd build
cmake -DLWS_MAX_SMP=1 -DLWS_WITHOUT_EXTENSIONS=0 -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_C_FLAGS="-fpic" ..
make && sudo make install
cd ../..
```

For **Fedora/CentOS:**
```bash
yum install libmicrohttpd-devel jansson-devel openssl-devel libsrtp-devel \
  sofia-sip-devel glib2-devel opus-devel libogg-devel libcurl-devel \
  pkgconfig libconfig-devel libtool autoconf automake
```

### 1.2 Build Janus

```bash
cd janus-gateway
sh autogen.sh
./configure --prefix=/opt/janus
make
sudo make install
sudo make configs    # Install default config files (run ONCE only)
```

To see all build options:
```bash
./configure --help
```

Disable features you don't need:
```bash
./configure --prefix=/opt/janus --disable-rabbitmq --disable-mqtt --disable-nanomsg
```

### 1.3 Configure Janus Core

Edit `/opt/janus/etc/janus/janus.jcfg`:

```
general: {
    debug_level = 4                    # 0-7, higher = more verbose
    admin_secret = "janusoverlord"     # Admin API secret
    # api_secret = "janusrocks"        # Uncomment to require API secret
    # session_timeout = 60             # Session timeout in seconds
}

certificates: {
    # Leave commented for auto-generated self-signed cert (fine for WebRTC DTLS)
    # cert_pem = "/path/to/cert.pem"
    # cert_key = "/path/to/key.pem"
}

media: {
    rtp_port_range = "20000-40000"     # UDP ports for RTP media
    # no_media_timer = 1               # Seconds before "no media" event
}

nat: {
    # STUN server (needed if Janus is behind NAT)
    # stun_server = "stun.l.google.com"
    # stun_port = 19302

    # For cloud deployments (AWS EC2, etc.) with 1:1 NAT:
    # nat_1_1_mapping = "YOUR_PUBLIC_IP"

    # ICE settings
    ice_ignore_list = "vmnet"
    # ice_enforce_list = "eth0"        # Limit to specific interfaces
}
```

### 1.4 Configure WebSocket Transport

Edit `/opt/janus/etc/janus/janus.transport.websockets.jcfg`:

```
general: {
    ws = true                          # Enable WebSocket
    ws_port = 8188                     # WebSocket port
    # wss = true                       # Enable secure WebSocket
    # wss_port = 8989                  # Secure WebSocket port
}

# For secure WebSocket (required for production):
certificates: {
    # cert_pem = "/etc/letsencrypt/live/yourdomain/fullchain.pem"
    # cert_key = "/etc/letsencrypt/live/yourdomain/privkey.pem"
}
```

### 1.5 Configure HTTP Transport

Edit `/opt/janus/etc/janus/janus.transport.http.jcfg`:

```
general: {
    base_path = "/janus"
    http = true
    port = 8088
    # https = true
    # secure_port = 8089
}
```

### 1.6 Configure SIP Plugin

Edit `/opt/janus/etc/janus/janus.plugin.sip.jcfg`:

```
general: {
    # local_ip = "192.168.1.100"       # Bind SIP stack to this IP
    # local_media_ip = "192.168.1.100" # Bind media to this IP
    # sdp_ip = "YOUR_PUBLIC_IP"        # Advertise this IP in SDP (for NAT)

    keepalive_interval = 120           # SIP OPTIONS keep-alive (seconds)
    behind_nat = false                 # Set true if behind NAT
    register_ttl = 3600                # Registration expiry (seconds)
    rtp_port_range = "20000-40000"     # RTP port range for SIP media
}
```

### 1.7 Start Janus

```bash
# Foreground (for testing)
/opt/janus/bin/janus

# With specific options
/opt/janus/bin/janus --debug-level=5 --rtp-port-range=20000-40000

# As daemon
/opt/janus/bin/janus --daemon --pid-file=/var/run/janus.pid

# Verify it's running
curl http://localhost:8088/janus/info
```

### 1.8 Test with Built-in Web Demos

Serve the `html/` folder with any web server:

```bash
# Using Python
cd html
python3 -m http.server 8000

# Or using PHP
php -S 0.0.0.0:8000
```

Open `http://localhost:8000/demos/sip.html` in Chrome/Firefox.

The demo will:
1. Connect to Janus via WebSocket on port 8188
2. Let you register with a SIP server (enter registrar, username, password)
3. Make/receive calls to/from SIP endpoints
4. Support audio, video, and DTMF

Edit `html/demos/settings.js` to change the Janus server address:
```javascript
// For WebSocket (recommended):
var server = "ws://" + window.location.hostname + ":8188";

// For HTTP long-polling:
var server = "http://" + window.location.hostname + ":8088/janus";
```

---

## Part 2: SIP.js Setup

### 2.1 Install from npm (for your own project)

```bash
npm install sip.js
```

### 2.2 Build from Source

```bash
cd SIP.js-0.21.2
npm install
npm run build          # Compile TypeScript to lib/
npm run build-demo     # Build browser demos with webpack
```

### 2.3 Run the Demo

After building:
```bash
# Open in browser
# SIP.js-0.21.2/demo/index.html
```

Or serve with a web server:
```bash
cd SIP.js-0.21.2
python3 -m http.server 8080
# Open http://localhost:8080/demo/index.html
```

> **Safari note:** Requires either `Develop → WebRTC → Allow Media Capture on Insecure Sites` or serving from HTTPS.

### 2.4 SimpleUser — Quick Start

The simplest way to make a SIP call from a browser:

```typescript
import { Web } from "sip.js";

// Get the audio element from your HTML
const audioElement = document.getElementById("remoteAudio") as HTMLAudioElement;

// Configure
const options: Web.SimpleUserOptions = {
  aor: "sip:alice@your-sip-domain.com",       // Your SIP address
  media: {
    constraints: { audio: true, video: false },
    remote: { audio: audioElement }
  },
  userAgentOptions: {
    authorizationUsername: "alice",             // SIP auth username
    authorizationPassword: "secret123",        // SIP auth password
    displayName: "Alice"
  }
};

// Connect to SIP server via WebSocket
const server = "wss://your-sip-server.com:8089/ws";
const phone = new Web.SimpleUser(server, options);

// Register and make a call
await phone.connect();
await phone.register();
await phone.call("sip:bob@your-sip-domain.com");

// Later...
await phone.hangup();
await phone.disconnect();
```

### 2.5 Full API — Advanced Usage

For more control (multiple calls, custom behavior):

```typescript
import { Inviter, Registerer, SessionState, UserAgent } from "sip.js";

const userAgent = new UserAgent({
  uri: UserAgent.makeURI("sip:alice@example.com"),
  transportOptions: {
    server: "wss://sip-server.example.com"
  },
  authorizationUsername: "alice",
  authorizationPassword: "password123"
});

// Start the user agent
await userAgent.start();

// Register
const registerer = new Registerer(userAgent);
await registerer.register();

// Make a call
const target = UserAgent.makeURI("sip:bob@example.com");
const inviter = new Inviter(userAgent, target, {
  sessionDescriptionHandlerOptions: {
    constraints: { audio: true, video: false }
  }
});

inviter.stateChange.addListener((state) => {
  switch (state) {
    case SessionState.Establishing:
      console.log("Ringing...");
      break;
    case SessionState.Established:
      console.log("Call connected!");
      break;
    case SessionState.Terminated:
      console.log("Call ended.");
      break;
  }
});

await inviter.invite();
```

### 2.6 SIP.js API Layers

| Layer | Class | Use Case |
|-------|-------|----------|
| Simple | `SimpleUser` | Single call, basic phone functionality |
| Manager | `SessionManager` | Multiple concurrent calls |
| API | `UserAgent`, `Inviter`, `Invitation`, `Registerer` | Full SIP control |
| Core | `UserAgentCore`, `Transaction`, `Dialog` | Protocol-level access |

---

## Part 3: Integration Scenarios

### Scenario A: Janus Gateway with janus.js (Browser → Janus → SIP PBX)

This is the standard Janus SIP demo approach. The browser uses Janus's own JavaScript library.

**When to use:** Your SIP server (Asterisk, FreeSWITCH, Kamailio) does NOT have WebSocket support, or you need Janus's other features (recording, video rooms, etc.).

```html
<!-- Include Janus JS library -->
<script src="janus.js"></script>
<script>
// 1. Initialize Janus
Janus.init({ debug: "all", callback: function() {

  // 2. Create session
  var janus = new Janus({
    server: "ws://your-janus-server:8188",
    success: function() {

      // 3. Attach to SIP plugin
      janus.attach({
        plugin: "janus.plugin.sip",
        success: function(pluginHandle) {
          var sipcall = pluginHandle;

          // 4. Register with SIP server
          sipcall.send({
            message: {
              request: "register",
              proxy: "sip:your-sip-server:5060",
              username: "sip:alice@your-sip-server",
              authuser: "alice",
              secret: "password123",
              display_name: "Alice"
            }
          });
        },
        onmessage: function(msg, jsep) {
          // Handle registration success, incoming calls, etc.
          if (msg.result && msg.result.event === "registered") {
            console.log("Registered!");
          }
          if (msg.result && msg.result.event === "incomingcall") {
            // Accept the call
            sipcall.createAnswer({
              jsep: jsep,
              media: { audio: true, video: false },
              success: function(jsep) {
                sipcall.send({ message: { request: "accept" }, jsep: jsep });
              }
            });
          }
        },
        onremotetrack: function(track, mid, on) {
          // Attach remote audio/video track
          if (track.kind === "audio") {
            var audioEl = document.getElementById("remoteAudio");
            var stream = new MediaStream([track]);
            audioEl.srcObject = stream;
          }
        }
      });
    }
  });
}});

// 5. Make a call
function makeCall(uri) {
  sipcall.createOffer({
    media: { audio: true, video: false },
    success: function(jsep) {
      sipcall.send({
        message: { request: "call", uri: uri },
        jsep: jsep
      });
    }
  });
}
</script>
```

### Scenario B: SIP.js Direct to WebSocket-enabled SIP Server

**When to use:** Your SIP server already supports WebSocket transport.

**Asterisk setup** (pjsip.conf):
```ini
[transport-wss]
type=transport
protocol=wss
bind=0.0.0.0:8089
cert_file=/etc/asterisk/keys/asterisk.pem
priv_key_file=/etc/asterisk/keys/asterisk.key

[webrtc_endpoint]
type=endpoint
transport=transport-wss
context=default
disallow=all
allow=opus
allow=ulaw
webrtc=yes
dtls_auto_generate_cert=yes
```

**Browser code:**
```typescript
import { Web } from "sip.js";

const phone = new Web.SimpleUser("wss://asterisk-server:8089/ws", {
  aor: "sip:1001@asterisk-server",
  media: {
    constraints: { audio: true, video: false },
    remote: { audio: document.getElementById("remoteAudio") as HTMLAudioElement }
  },
  userAgentOptions: {
    authorizationUsername: "1001",
    authorizationPassword: "1001password"
  }
});

await phone.connect();
await phone.register();
// Now ready to make/receive calls
await phone.call("sip:1002@asterisk-server");
```

### Scenario C: Hybrid — SIP.js for Signaling, Janus for Media Features

In advanced setups, you might use Janus for its media processing capabilities (recording, transcoding, mixing) while having SIP.js handle the SIP signaling layer. This requires custom integration and is not a standard configuration.

---

## Network & Ports Reference

### Janus Gateway Ports

| Port | Protocol | Service | Config File |
|------|----------|---------|-------------|
| 8088 | TCP/HTTP | Janus REST API | `janus.transport.http.jcfg` |
| 8089 | TCP/HTTPS | Janus REST API (secure) | `janus.transport.http.jcfg` |
| 8188 | TCP/WS | Janus WebSocket API | `janus.transport.websockets.jcfg` |
| 8989 | TCP/WSS | Janus WebSocket API (secure) | `janus.transport.websockets.jcfg` |
| 7088 | TCP/HTTP | Admin API | `janus.transport.http.jcfg` |
| 7188 | TCP/WS | Admin WebSocket API | `janus.transport.websockets.jcfg` |
| 20000-40000 | UDP | RTP/RTCP (WebRTC + SIP media) | `janus.jcfg` + `janus.plugin.sip.jcfg` |
| 5060 | UDP/TCP | SIP signaling (Sofia-SIP outbound) | Managed by Sofia-SIP |

### SIP.js (Browser-side)

| Port | Protocol | Service |
|------|----------|---------|
| 443/8089 | TCP/WSS | SIP over WebSocket (outbound to SIP server) |
| Ephemeral | UDP | WebRTC media (ICE/DTLS/SRTP) |

### Firewall Rules (Janus Server)

```bash
# Janus API (choose one or both)
sudo ufw allow 8188/tcp    # WebSocket
sudo ufw allow 8088/tcp    # HTTP

# For HTTPS/WSS
sudo ufw allow 8989/tcp    # Secure WebSocket
sudo ufw allow 8089/tcp    # HTTPS

# RTP media (MUST be open for audio/video)
sudo ufw allow 20000:40000/udp

# If Janus needs to reach external SIP server
# (outbound, usually allowed by default)
```

---

## Troubleshooting

### Janus Issues

| Problem | Solution |
|---------|----------|
| "No WebRTC support" in browser | Use HTTPS or localhost. WebRTC requires secure context. |
| ICE failed / no media | Check firewall allows UDP 20000-40000. Set `nat_1_1_mapping` for cloud. |
| SIP registration fails | Verify SIP server address, credentials. Check `behind_nat` setting. |
| WebSocket connection refused | Ensure `ws = true` in websockets config. Check port 8188 is open. |
| "Could not find Sofia-SIP" during build | Install `libsofia-sip-ua-dev` (Debian) or `sofia-sip-devel` (Fedora). |
| OSSL errors on startup | Rebuild libsrtp with `--enable-openssl`. |

### SIP.js Issues

| Problem | Solution |
|---------|----------|
| WebSocket connection fails | Verify WSS URL and port. Check SIP server has WS transport enabled. |
| 401 Unauthorized | Check `authorizationUsername` and `authorizationPassword`. |
| No audio | Ensure `remote.audio` element is in DOM. Check browser permissions. |
| "Location" header missing | SIP server may not support WebSocket. Use Janus instead. |
| OSSL/SRTP errors | Ensure SIP server has DTLS/SRTP configured for WebRTC endpoints. |

### NAT/Cloud Deployment Tips

1. **AWS EC2 / Cloud VMs:** Set `nat_1_1_mapping` to your public IP in `janus.jcfg`
2. **Docker:** Use `--network=host` or map all required ports including UDP range
3. **Behind reverse proxy (nginx):**
   ```nginx
   location /janus-ws {
       proxy_pass http://127.0.0.1:8188;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
       proxy_read_timeout 86400;
   }
   ```
4. **TURN server** (for restrictive NATs): Configure ICE servers in `settings.js` (Janus demos) or `SimpleUserOptions` (SIP.js)

### Quick Verification Checklist

```bash
# 1. Janus is running
curl http://localhost:8088/janus/info | python3 -m json.tool

# 2. WebSocket is accessible
wscat -c ws://localhost:8188

# 3. SIP plugin is loaded (check Janus startup logs for)
# [janus.plugin.sip] loaded

# 4. RTP ports are open
sudo ss -ulnp | grep -E "2[0-9]{4}"

# 5. SIP server is reachable from Janus host
nc -zvu your-sip-server 5060
```

---

## Quick Start Summary

### Fastest Path: Janus + Built-in SIP Demo

```bash
# On a Linux server:
# 1. Install deps + build Janus (see Section 1.1-1.2)
# 2. Start Janus
/opt/janus/bin/janus

# 3. Serve the demos
cd /path/to/janus-gateway/html
python3 -m http.server 8000

# 4. Open browser → http://your-server:8000/demos/sip.html
# 5. Enter your SIP registrar, username, password → Register → Call
```

### Fastest Path: SIP.js Standalone

```bash
# 1. In your project
npm install sip.js

# 2. Or build from source
cd SIP.js-0.21.2
npm install
npm run build-demo

# 3. Open demo/index.html in browser
# 4. Connects to sipjs.onsip.com demo server by default
```

---

## Part 4: Fraud Prevention (CRITICAL)

When you allow users to dial international numbers, fraudsters **will** attempt to route calls to high-cost premium-rate numbers (International Revenue Share Fraud — IRSF). A single night of abuse can generate thousands of dollars in charges. These backend guardrails are non-negotiable for any production deployment.

### Architecture: Never Trust the Client

```
┌───────────┐         ┌──────────────────┐         ┌──────────────┐         ┌────────────┐
│  Browser  │ ──①──► │  Your Backend    │ ──③──► │    Janus     │ ──④──► │ SIP Trunk  │
│  (App)    │ ◄──②── │  (Node/Python)   │         │   Gateway    │         │  Provider  │
└───────────┘         └──────────────────┘         └──────────────┘         └────────────┘
                              │
                         ┌────┴────┐
                         │  Redis  │
                         │ (wallet │
                         │ + rate  │
                         │  limit) │
                         └─────────┘

① App requests call token (with destination number)
② Backend validates user, checks balance, returns short-lived token
③ Backend initiates call via Janus API (or SIP INVITE) only if authorized
④ Janus/SIP trunk places the actual call
```

**Golden rule:** The browser/mobile app should NEVER have direct access to your SIP trunk credentials or the ability to dial arbitrary numbers without server-side authorization.

---

### 4.1 Strict Token Authentication

The client app must request a short-lived authorization token from your backend before any call can be placed. The backend is the only component with SIP trunk credentials.

**Node.js Backend (Express + JWT):**

```typescript
// backend/src/call-auth.ts
import express from "express";
import jwt from "jsonwebtoken";
import { Redis } from "ioredis";

const app = express();
const redis = new Redis();
const JWT_SECRET = process.env.JWT_SECRET!;
const TOKEN_TTL_SECONDS = 30; // Token expires in 30s — just enough to initiate one call

app.use(express.json());

// Middleware: verify user session (your existing auth)
app.use(authenticateUser);

app.post("/api/call/authorize", async (req, res) => {
  const { userId } = req.user;          // From your auth middleware
  const { destination } = req.body;     // e.g., "+44207123456"

  // ── Step 1: Validate destination ──
  if (!isDestinationAllowed(destination)) {
    return res.status(403).json({ error: "Destination not permitted" });
  }

  // ── Step 2: Check user balance ──
  const balanceCents = await redis.get(`wallet:${userId}`);
  if (!balanceCents || parseInt(balanceCents) <= 0) {
    return res.status(402).json({ error: "Insufficient balance" });
  }

  // ── Step 3: Rate limit (max 3 concurrent calls per user) ──
  const activeCalls = await redis.get(`active_calls:${userId}`);
  if (activeCalls && parseInt(activeCalls) >= 3) {
    return res.status(429).json({ error: "Too many active calls" });
  }

  // ── Step 4: Calculate max call duration ──
  const ratePerMinuteCents = getRate(destination); // e.g., 2 cents/min for US
  const maxDurationSeconds = Math.floor(
    (parseInt(balanceCents) / ratePerMinuteCents) * 60
  );

  // ── Step 5: Issue short-lived token ──
  const callToken = jwt.sign(
    {
      userId,
      destination,
      maxDurationSeconds,
      ratePerMinuteCents,
    },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL_SECONDS }
  );

  // Mark token as unused (one-time use)
  await redis.set(`call_token:${callToken}`, "unused", "EX", TOKEN_TTL_SECONDS);

  return res.json({
    token: callToken,
    maxDurationSeconds,
    estimatedCostPerMinute: ratePerMinuteCents / 100,
  });
});
```

**Consuming the token (call initiation endpoint):**

```typescript
// backend/src/call-initiate.ts
app.post("/api/call/initiate", async (req, res) => {
  const { token } = req.body;

  // ── Verify and consume token (one-time use) ──
  let payload: any;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  const tokenKey = `call_token:${token}`;
  const tokenState = await redis.getdel(tokenKey); // Atomic get-and-delete
  if (tokenState !== "unused") {
    return res.status(401).json({ error: "Token already consumed" });
  }

  const { userId, destination, maxDurationSeconds, ratePerMinuteCents } = payload;

  // ── Initiate call via Janus Admin API or direct SIP ──
  const callId = await initiateJanusCall(userId, destination);

  // ── Track active call with server-side kill timer ──
  await redis.incr(`active_calls:${userId}`);
  await redis.set(`call:${callId}`, JSON.stringify({
    userId, destination, startTime: Date.now(), ratePerMinuteCents
  }), "EX", maxDurationSeconds + 60);

  // ── Set hard kill timer ──
  scheduleCallTermination(callId, userId, maxDurationSeconds);

  return res.json({ callId, maxDurationSeconds });
});
```

---

### 4.2 Destination Whitelisting

Block all international destinations by default. Only allow specific country codes your business requires.

**Implementation:**

```typescript
// backend/src/destination-whitelist.ts

// WHITELIST: Only these country codes are allowed
const ALLOWED_COUNTRY_CODES: string[] = [
  "+1",    // US/Canada
  "+44",   // UK
  "+61",   // Australia
  "+49",   // Germany
  "+33",   // France
  // Add only what you need
];

// BLACKLIST: Known premium-rate prefixes (always block even if country is allowed)
const BLOCKED_PREFIXES: string[] = [
  "+1900",     // US premium
  "+1976",     // US premium
  "+44870",    // UK premium
  "+44871",    // UK premium
  "+44872",    // UK premium
  "+44900",    // UK premium
  "+44908",    // UK premium
  "+44909",    // UK premium
  "+44098",    // UK premium
  "+882",      // International networks (satellite, premium)
  "+883",      // International networks
  "+979",      // International premium rate
];

// HIGH-RISK countries (block entirely — common IRSF targets)
const BLOCKED_COUNTRIES: string[] = [
  "+220",  // Gambia
  "+221",  // Senegal
  "+222",  // Mauritania
  "+223",  // Mali
  "+224",  // Guinea
  "+225",  // Ivory Coast
  "+226",  // Burkina Faso
  "+227",  // Niger
  "+228",  // Togo
  "+229",  // Benin
  "+230",  // Mauritius
  "+231",  // Liberia
  "+232",  // Sierra Leone
  "+233",  // Ghana
  "+234",  // Nigeria
  "+235",  // Chad
  "+236",  // Central African Republic
  "+237",  // Cameroon
  "+238",  // Cape Verde
  "+239",  // São Tomé
  "+240",  // Equatorial Guinea
  "+241",  // Gabon
  "+242",  // Congo
  "+243",  // DR Congo
  "+244",  // Angola
  "+245",  // Guinea-Bissau
  "+246",  // Diego Garcia
  "+247",  // Ascension Island
  "+248",  // Seychelles
  "+249",  // Sudan
  "+250",  // Rwanda
  "+251",  // Ethiopia
  "+252",  // Somalia
  "+253",  // Djibouti
  "+254",  // Kenya
  "+255",  // Tanzania
  "+256",  // Uganda
  "+257",  // Burundi
  "+258",  // Mozambique
  "+260",  // Zambia
  "+261",  // Madagascar
  "+262",  // Réunion
  "+263",  // Zimbabwe
  "+264",  // Namibia
  "+265",  // Malawi
  "+266",  // Lesotho
  "+267",  // Botswana
  "+268",  // Eswatini
  "+269",  // Comoros
  "+290",  // Saint Helena
  "+291",  // Eritrea
  "+297",  // Aruba
  "+298",  // Faroe Islands
  "+299",  // Greenland
  "+350",  // Gibraltar
  "+500",  // Falkland Islands
  "+501",  // Belize
  "+504",  // Honduras
  "+505",  // Nicaragua
  "+592",  // Guyana
  "+593",  // Ecuador
  "+595",  // Paraguay
  "+597",  // Suriname
  "+670",  // East Timor
  "+672",  // Norfolk Island
  "+673",  // Brunei
  "+674",  // Nauru
  "+675",  // Papua New Guinea
  "+676",  // Tonga
  "+677",  // Solomon Islands
  "+678",  // Vanuatu
  "+679",  // Fiji
  "+680",  // Palau
  "+681",  // Wallis and Futuna
  "+682",  // Cook Islands
  "+683",  // Niue
  "+685",  // Samoa
  "+686",  // Kiribati
  "+687",  // New Caledonia
  "+688",  // Tuvalu
  "+689",  // French Polynesia
  "+690",  // Tokelau
  "+691",  // Micronesia
  "+692",  // Marshall Islands
  "+850",  // North Korea
  "+960",  // Maldives
  "+967",  // Yemen
];

export function isDestinationAllowed(number: string): boolean {
  // Normalize: strip spaces, dashes
  const normalized = number.replace(/[\s\-\(\)]/g, "");

  // Must start with +
  if (!normalized.startsWith("+")) {
    return false;
  }

  // Check blocked prefixes first (premium-rate numbers)
  for (const prefix of BLOCKED_PREFIXES) {
    if (normalized.startsWith(prefix)) {
      return false;
    }
  }

  // Check blocked countries
  for (const country of BLOCKED_COUNTRIES) {
    if (normalized.startsWith(country)) {
      return false;
    }
  }

  // Check against whitelist
  const isWhitelisted = ALLOWED_COUNTRY_CODES.some(
    (code) => normalized.startsWith(code)
  );

  if (!isWhitelisted) {
    return false;
  }

  // Basic format validation (E.164: max 15 digits)
  const digits = normalized.slice(1); // Remove +
  if (!/^\d{7,14}$/.test(digits)) {
    return false;
  }

  return true;
}
```

**Also configure at the carrier level:** Log into your SIP trunk provider (Twilio, Telnyx, VoIP.ms, etc.) and disable all international destinations in their control panel. Only enable the specific countries you need. This is your last line of defense if your code has a bug.

---

### 4.3 Pre-paid Wallet System with Server-Side Call Timer

Use Redis to track user balances and enforce hard time limits on calls.

**Wallet management:**

```typescript
// backend/src/wallet.ts
import { Redis } from "ioredis";

const redis = new Redis();

export async function getBalance(userId: string): Promise<number> {
  const balance = await redis.get(`wallet:${userId}`);
  return balance ? parseInt(balance) : 0; // Balance in cents
}

export async function deductBalance(userId: string, amountCents: number): Promise<boolean> {
  // Atomic decrement — prevents race conditions
  const newBalance = await redis.decrby(`wallet:${userId}`, amountCents);
  if (newBalance < 0) {
    // Rollback — insufficient funds
    await redis.incrby(`wallet:${userId}`, amountCents);
    return false;
  }
  return true;
}

export async function addBalance(userId: string, amountCents: number): Promise<void> {
  await redis.incrby(`wallet:${userId}`, amountCents);
}
```

**Rate lookup:**

```typescript
// backend/src/rates.ts

// Rates in cents per minute
const RATES: Record<string, number> = {
  "+1":   1,    // US/Canada — $0.01/min
  "+44":  2,    // UK — $0.02/min
  "+61":  3,    // Australia — $0.03/min
  "+49":  2,    // Germany — $0.02/min
  "+33":  2,    // France — $0.02/min
};

export function getRate(destination: string): number {
  const normalized = destination.replace(/[\s\-\(\)]/g, "");

  // Match longest prefix first (more specific rates)
  const sortedPrefixes = Object.keys(RATES).sort((a, b) => b.length - a.length);

  for (const prefix of sortedPrefixes) {
    if (normalized.startsWith(prefix)) {
      return RATES[prefix];
    }
  }

  // Default: high rate for unknown destinations (extra safety)
  return 50; // $0.50/min — discourages calling unlisted destinations
}
```

**Server-side call timer (force-kill when balance runs out):**

```typescript
// backend/src/call-timer.ts
import { Redis } from "ioredis";

const redis = new Redis();
const activeTimers = new Map<string, NodeJS.Timeout>();

export function scheduleCallTermination(
  callId: string,
  userId: string,
  maxDurationSeconds: number
): void {
  // Hard kill timer — non-negotiable server-side enforcement
  const timer = setTimeout(async () => {
    console.log(`[TIMER] Force-terminating call ${callId} (max duration reached)`);
    await terminateCall(callId, userId, "max_duration_reached");
  }, maxDurationSeconds * 1000);

  activeTimers.set(callId, timer);

  // Also set a warning at 80% duration
  const warningAt = Math.floor(maxDurationSeconds * 0.8);
  setTimeout(() => {
    notifyUser(userId, {
      type: "balance_warning",
      message: `Call will end in ${maxDurationSeconds - warningAt} seconds`,
      remainingSeconds: maxDurationSeconds - warningAt,
    });
  }, warningAt * 1000);
}

export async function terminateCall(
  callId: string,
  userId: string,
  reason: string
): Promise<void> {
  // Clear the timer
  const timer = activeTimers.get(callId);
  if (timer) {
    clearTimeout(timer);
    activeTimers.delete(callId);
  }

  // ── Option A: Terminate via Janus Admin API ──
  await fetch(`http://localhost:7088/admin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      janus: "message_plugin",
      plugin: "janus.plugin.sip",
      transaction: `hangup-${callId}`,
      admin_secret: "janusoverlord",
      request: { request: "hangup" },
    }),
  });

  // ── Deduct actual cost from wallet ──
  const callData = await redis.get(`call:${callId}`);
  if (callData) {
    const { userId: uid, startTime, ratePerMinuteCents } = JSON.parse(callData);
    const durationMinutes = (Date.now() - startTime) / 60000;
    const costCents = Math.ceil(durationMinutes * ratePerMinuteCents);
    await redis.decrby(`wallet:${uid}`, costCents);
    await redis.del(`call:${callId}`);
  }

  // Decrement active call counter
  await redis.decr(`active_calls:${userId}`);

  console.log(`[CALL] Terminated ${callId} for user ${userId}: ${reason}`);
}

// Call this when a call ends naturally (BYE received)
export async function onCallEnded(callId: string, userId: string): Promise<void> {
  await terminateCall(callId, userId, "normal_hangup");
}
```

---

### 4.4 Additional Fraud Prevention Measures

**Rate limiting at the API level:**

```typescript
// backend/src/rate-limit.ts
import rateLimit from "express-rate-limit";

// Max 10 call attempts per minute per user
export const callRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.user.userId,
  message: { error: "Too many call attempts. Try again later." },
});

// Max 3 failed auth attempts per 15 minutes per IP
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: "Too many failed attempts." },
});
```

**Anomaly detection (simple heuristics):**

```typescript
// backend/src/anomaly-detection.ts

export async function checkForAnomalies(
  userId: string,
  destination: string
): Promise<{ allowed: boolean; reason?: string }> {
  const redis = new Redis();

  // 1. Check if user has called this destination before
  const callHistory = await redis.lrange(`history:${userId}`, 0, -1);
  const uniqueDestinations = new Set(callHistory.map((c) => JSON.parse(c).destination));

  // Flag: user calling 5+ unique international numbers in 1 hour
  if (uniqueDestinations.size >= 5) {
    const recentCalls = callHistory
      .map((c) => JSON.parse(c))
      .filter((c) => Date.now() - c.timestamp < 3600000);
    const recentUnique = new Set(recentCalls.map((c) => c.destination));
    if (recentUnique.size >= 5) {
      return { allowed: false, reason: "Unusual calling pattern detected" };
    }
  }

  // 2. Check call duration patterns (many short calls = fraud indicator)
  const recentCalls = callHistory
    .map((c) => JSON.parse(c))
    .filter((c) => Date.now() - c.timestamp < 3600000);
  const shortCalls = recentCalls.filter((c) => c.duration < 30); // < 30 seconds
  if (shortCalls.length >= 10) {
    return { allowed: false, reason: "Too many short-duration calls" };
  }

  // 3. Time-of-day check (calls at 3am local time = suspicious)
  const hour = new Date().getHours();
  if (hour >= 1 && hour <= 5) {
    const nightCalls = recentCalls.filter((c) => {
      const h = new Date(c.timestamp).getHours();
      return h >= 1 && h <= 5;
    });
    if (nightCalls.length >= 3) {
      return { allowed: false, reason: "Unusual activity hours" };
    }
  }

  return { allowed: true };
}
```

**Daily spending cap:**

```typescript
// Enforce a maximum daily spend regardless of wallet balance
const DAILY_SPEND_CAP_CENTS = 2000; // $20/day max

async function checkDailyCap(userId: string, callCostEstimate: number): Promise<boolean> {
  const today = new Date().toISOString().split("T")[0]; // "2026-05-30"
  const key = `daily_spend:${userId}:${today}`;

  const spent = parseInt((await redis.get(key)) || "0");
  if (spent + callCostEstimate > DAILY_SPEND_CAP_CENTS) {
    return false; // Would exceed daily cap
  }

  // Increment (with 48h expiry so keys auto-clean)
  await redis.incrby(key, callCostEstimate);
  await redis.expire(key, 172800);
  return true;
}
```

---

### 4.5 Fraud Prevention Checklist

| Layer | Control | Priority |
|-------|---------|----------|
| **Carrier** | Block all countries by default in trunk provider panel | 🔴 Critical |
| **Carrier** | Set daily/monthly spend alerts and hard caps | 🔴 Critical |
| **Backend** | Token-based call authorization (short-lived, one-time use) | 🔴 Critical |
| **Backend** | Destination whitelist + premium-number blacklist | 🔴 Critical |
| **Backend** | Pre-paid wallet with server-side kill timer | 🔴 Critical |
| **Backend** | Rate limiting (calls per minute per user) | 🟡 High |
| **Backend** | Daily spending cap per user | 🟡 High |
| **Backend** | Anomaly detection (many short calls, unusual hours) | 🟡 High |
| **Backend** | Concurrent call limit per user | 🟡 High |
| **App** | Never expose SIP credentials to client | 🔴 Critical |
| **App** | Show real-time balance and call cost to user | 🟢 Good practice |
| **Monitoring** | Alert on spike in international call volume | 🟡 High |
| **Monitoring** | Alert on new destinations never called before | 🟢 Good practice |

---

### 4.6 Janus-Specific Security Configuration

In `janus.jcfg`, enable API authentication so random clients can't attach to the SIP plugin:

```
general: {
    # Require this secret in all API requests
    api_secret = "your-strong-random-secret-here"

    # Or use token-based auth (tokens managed via Admin API)
    # token_auth = true
}
```

In your backend, include the secret when talking to Janus:

```typescript
const janus = new Janus({
  server: "ws://localhost:8188",
  apisecret: "your-strong-random-secret-here",
  // ...
});
```

This ensures only your backend (not random browsers) can create sessions and place calls through Janus.

---

## References

- [Janus Gateway Documentation](https://janus.conf.meetecho.com/docs/)
- [Janus SIP Plugin Docs](https://janus.conf.meetecho.com/docs/sip)
- [Janus GitHub](https://github.com/meetecho/janus-gateway)
- [SIP.js Documentation](https://sipjs.com)
- [SIP.js GitHub](https://github.com/onsip/SIP.js)
- [RFC 7118 — SIP over WebSocket](https://tools.ietf.org/html/rfc7118)
- [WebRTC.org](https://webrtc.org/)
- [IRSF Fraud Prevention (CFCA)](https://cfca.org/fraud-loss-survey/)
- [Twilio Fraud Prevention Guide](https://www.twilio.com/docs/voice/fraud)
