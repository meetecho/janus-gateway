# API Framework

## Overview

This API is intended to provide a complete and suitable framework for most end user applications wishing initiate and carry various forms of real-time multimedia session data such as voice, video, or text messages. 

The API is implemented on top of the [Core Library](./core.md) which provides lower protocol level access.

A working knowledge of the SIP protocol is a prerequisite for working with this API. The SIP protocol is an internet standard the details of which are well beyond the scope of the documentation herein. However there are many resources available. See: https://tools.ietf.org/html/rfc3261 for the primary specification.


## Reference Documentation

* [API Reference](./api/sip.js.md)

## Getting Started

- Create a user agent
- Setup handling of incoming calls
- Connect the user agent
- Register the user agent
- Place an outbound call
- Make a transfer call

```ts
import {
  Invitation,
  Inviter,
  InviterOptions,
  Referral,
  Registerer,
  RegistererOptions,
  Session,
  SessionState,
  UserAgent,
  UserAgentOptions,
  InvitationAcceptOptions
} from "sip.js";

/*
 * Create a user agent
 */
const uri = UserAgent.makeURI("sip:alice@example.com");
if (!uri) {
  throw new Error("Failed to create URI");
}
const userAgentOptions: UserAgentOptions = {
  uri,
  /* ... */
};
const userAgent = new UserAgent(userAgentOptions);

/*
 * Setup handling for incoming INVITE requests
 */
userAgent.delegate = {
  onInvite(invitation: Invitation): void {

    // An Invitation is a Session
    const incomingSession: Session = invitation;

    // Setup incoming session delegate
    incomingSession.delegate = {
      // Handle incoming REFER request.
      onRefer(referral: Referral): void {
        // ...
      }
    };

    // Handle incoming session state changes.
    incomingSession.stateChange.addListener((newState: SessionState) => {
      switch (newState) {
        case SessionState.Establishing:
          // Session is establishing.
          break;
        case SessionState.Established:
          // Session has been established.
          break;
        case SessionState.Terminated:
          // Session has terminated.
          break;
        default:
          break;
      }
    });

    // Handle incoming INVITE request.
    let constrainsDefault: MediaStreamConstraints = {
      audio: true,
      video: false,
    }

    const options: InvitationAcceptOptions = {
      sessionDescriptionHandlerOptions: {
        constraints: constrainsDefault,
      },
    }

    incomingSession.accept(options)
  }
};

/*
 * Create a Registerer to register user agent
 */
const registererOptions: RegistererOptions = { /* ... */ };
const registerer = new Registerer(userAgent, registererOptions);

/*
 * Start the user agent
 */
userAgent.start().then(() => {

  // Register the user agent
  registerer.register();

  // Send an outgoing INVITE request
  const target = UserAgent.makeURI("sip:bob@example.com");
  if (!target) {
    throw new Error("Failed to create target URI.");
  }

  // Create a new Inviter
  const inviterOptions: InviterOptions = { /* ... */ };
  const inviter = new Inviter(userAgent, target, inviterOptions);

  // An Inviter is a Session
  const outgoingSession: Session = inviter;

  // Setup outgoing session delegate
  outgoingSession.delegate = {
    // Handle incoming REFER request.
    onRefer(referral: Referral): void {
      // ...
    }
  };

  // Handle outgoing session state changes.
  outgoingSession.stateChange.addListener((newState: SessionState) => {
    switch (newState) {
      case SessionState.Establishing:
        // Session is establishing.
        break;
      case SessionState.Established:
        // Session has been established.
        break;
      case SessionState.Terminated:
        // Session has terminated.
        break;
      default:
        break;
    }
  });

  // Send the INVITE request
  inviter.invite()
    .then(() => {
      // INVITE sent
    })
    .catch((error: Error) => {
      // INVITE did not send
    });

  // Send an outgoing REFER request
  const transferTarget = UserAgent.makeURI("sip:transfer@example.com");

  if (!transferTarget) {
    throw new Error("Failed to create transfer target URI.");
  }

  outgoingSession.refer(transferTarget, {
    // Example of extra headers in REFER request
    requestOptions: {
      extraHeaders: [
        'X-Referred-By-Someone: Username'
      ]
    },
    requestDelegate: {
      onAccept(): void {
        // ...
      }
    }
  });
});
```

## Handling Changes in Network State

When connectivity to the network is lost, an application may wish to update state.
In particular, when network connectivity is lost registrations may no longer be valid.
Likewise, when network connectivity is re-established, an application may which to re-register.

The following example implementation mirrors the reconnection strategy implemented by [`SimpleUser`](./simple-user.md).

```ts
// Number of times to attempt reconnection before giving up
const reconnectionAttempts = 3;
// Number of seconds to wait between reconnection attempts
const reconnectionDelay = 4;

// Used to guard against overlapping reconnection attempts
let attemptingReconnection = false;
// If false, reconnection attempts will be discontinued or otherwise prevented
let shouldBeConnected = true;

// Function which recursively attempts reconnection
const attemptReconnection = (reconnectionAttempt = 1): void => {
  // If not intentionally connected, don't reconnect.
  if (!shouldBeConnected) {
    return;
  }

  // Reconnection attempt already in progress
  if (attemptingReconnection) {
    return;
  }

  // Reconnection maximum attempts reached
  if (reconnectionAttempt > reconnectionAttempts) {
    return;
  }

  // We're attempting a reconnection
  attemptingReconnection = true;

  setTimeout(() => {
    // If not intentionally connected, don't reconnect.
    if (!shouldBeConnected) {
      attemptingReconnection = false;
      return;
    }
    // Attempt reconnect
    userAgent.reconnect()
      .then(() => {
        // Reconnect attempt succeeded
        attemptingReconnection = false;
      })
      .catch((error: Error) => {
        // Reconnect attempt failed
        attemptingReconnection = false;
        attemptReconnection(++reconnectionAttempt);
      });
  }, reconnectionAttempt === 1 ? 0 : reconnectionDelay * 1000);
};

// Handle connection with server established
userAgent.delegate.onConnect = () => {
  // On connecting, register the user agent
  registerer.register()
    .catch((e: Error) => {
      // Register failed
    });
};

// Handle connection with server lost
userAgent.delegate.onDisconnect = (error?: Error) => {
  // On disconnect, cleanup invalid registrations
  registerer.unregister()
    .catch((e: Error) => {
      // Unregister failed
    });
  // Only attempt to reconnect if network/server dropped the connection (if there is an error)
  if (error) {
    attemptReconnection();
  }
};

// Monitor network connectivity and attempt reconnection when browser goes online
window.addEventListener("online", () => {
  attemptReconnection();
});
```