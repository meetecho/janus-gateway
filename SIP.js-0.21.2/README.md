![SIP.js Logo](https://sipjs.com/shared/img/logo.png "SIP.js")

![Build Status](https://github.com/onsip/SIP.js/actions/workflows/node.js.yml/badge.svg)
[![npm version](https://badge.fury.io/js/sip.js.svg)](https://badge.fury.io/js/sip.js)

# SIP Library for JavaScript

- Create real-time peer-to-peer audio and video sessions via [WebRTC](https://webrtc.org/)
- Utilize SIP in your web application via [SIP over WebSocket](https://tools.ietf.org/html/rfc7118) 
- Send instant messages and view presence
- Support early media, hold and transfers
- Send DTMF RFC 2833 or SIP INFO
- Share your screen or desktop
- Written in TypeScript
- Runs in all major web browsers
- Compatible with standards compliant servers including [Asterisk](https://www.asterisk.org/) and [FreeSWITCH](https://freeswitch.com/)

## Demo

Want see it in action? The project website, [sipjs.com](https://sipjs.com), has a [live demo](https://sipjs.com).

Looking for code to get started with? This repository includes [demonstrations](./demo/README.md) which run in a web browser.

## Usage

To place a SIP call, either utilize the [`SimpleUser` class](docs/simple-user.md)...

```ts
import { Web } from "sip.js";

// Helper function to get an HTML audio element
function getAudioElement(id: string): HTMLAudioElement {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLAudioElement)) {
    throw new Error(`Element "${id}" not found or not an audio element.`);
  }
  return el;
}

// Options for SimpleUser
const options: Web.SimpleUserOptions = {
  aor: "sip:alice@example.com", // caller
  media: {
    constraints: { audio: true, video: false }, // audio only call
    remote: { audio: getAudioElement("remoteAudio") } // play remote audio
  }
};

// WebSocket server to connect with
const server = "wss://sip.example.com";

// Construct a SimpleUser instance
const simpleUser = new Web.SimpleUser(server, options);

// Connect to server and place call
simpleUser.connect()
  .then(() => simpleUser.call("sip:bob@example.com"))
  .catch((error: Error) => {
    // Call failed
  });
```

Or, alternatively, use the full [API framework](docs/api.md)...

```ts
import { Inviter, SessionState, UserAgent } from "sip.js";

// Create user agent instance (caller)
const userAgent = new UserAgent({
  uri: UserAgent.makeURI("sip:alice@example.com"),
  transportOptions: {
    server: "wss://sip.example.com"
  },
});

// Connect the user agent
userAgent.start().then(() => {

  // Set target destination (callee)
  const target = UserAgent.makeURI("sip:bob@example.com");
  if (!target) {
    throw new Error("Failed to create target URI.");
  }

  // Create a user agent client to establish a session
  const inviter = new Inviter(userAgent, target, {
    sessionDescriptionHandlerOptions: {
      constraints: { audio: true, video: false }
    }
  });

  // Handle outgoing session state changes
  inviter.stateChange.addListener((newState) => {
    switch (newState) {
      case SessionState.Establishing:
        // Session is establishing
        break;
      case SessionState.Established:
        // Session has been established
        break;
      case SessionState.Terminated:
        // Session has terminated
        break;
      default:
        break;
    }
  });

  // Send initial INVITE request
  inviter.invite()
    .then(() => {
      // INVITE sent
    })
    .catch((error: Error) => {
      // INVITE did not send
    });

});
```
## Installation

Node module
```sh
npm install sip.js
```

 UMD bundle
- Download [sipjs.com/download](https://sipjs.com/download)
- CDN [jsDelivr.com](https://www.jsdelivr.com/package/npm/sip.js)

## Building, Development and Testing

Clone this repository, then...

```sh
npm install
npm run build-and-test
```

For more info please see the [Documentation](./docs/README.md).

## Support

* For migration guides and API reference please see the [Documentation](./docs/README.md).
* For bug reports and feature requests please open a [GitHub Issue](https://github.com/onsip/sip.js/issues).
* For questions or usage problems please use the [Google Group](https://groups.google.com/forum/#!forum/sip_js).
* For more information see the project website at [SIPjs.com](https://sipjs.com).
