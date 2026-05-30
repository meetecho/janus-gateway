
# Migration from 0.15.x to 0.16.x

The 0.16.x release is not backwards compatible with 0.15.x.

Significant architectural changes were made to address long standing issues including some ambiguities and race conditions that were difficult to resolve in the prior architecture. Additionally, years of code contributions to different aspects of the code base had resulted in inconsistencies in the overall API interface. Improvements made to some aspects of the API where often not carried across the whole API. An attempt has been made to rectify these inconsistencies in the new API by taking the "best" approach and applying it across the board.

Architectural changes include:

1. Classes are constructed then methods on those classes are called to send requests.
2. Methods which send requests/responses now return a `Promise` (instead of `this`).
3. Events have been replaced with delegates and finite state machines.

Migrating to the new API entails updating code accordingly. 

## 1. `UserAgent` class replaces...

- `UA`

### Configuration Options

The following `UA.Options` have been modified for use as `UserAgentOptions`...
- `allowOutOfDialogRefers`
  - removed (it was redundant)
- `authenticationFactory`
  - removed (it was a noop)
- `authorizationUser`
  - renamed to `authorizationUsername`
- `autostart`
  - renamed to `autoStart` (case changed for consistency)
- `autostop`
  - renamed to `autoStop` (case changed for consistency)
- `dtmfType`
  - use `Session.info()` for "out-of-band" DTMF or `SessionDescriptionHandler` for "in-band" DTMF.
- `experimentalFeatures`
  - removed (it was a noop)
- `hostportParams`
  - removed (it was a noop)
- `log`
  - use `logBuiltinEnabled`, `logLevel` and `logConnector`
- `password`
  - renamed `authorizationPassword`
- `registerOptions`
  - pass `RegistererOptions` to `Registerer` instead (see below).
- `register`
  - use `Registerer.register()` instead (see below).
- `100rel`
  - renamed `sipExtension100rel`
- `replaces`
  - renamed `sipExtensionReplaces`
- `extraSupported`
  - renamed `sipExtensionExtraSupported`
- `uri`
  - must be a `URI` instance, use `UserAgent.makeURI()` to create (see below).

### Construction, Starting and Stopping

Previously...
```ts
  const uri = "sip:alice@example.com";
  const options = {
    uri: uri
    // Set various other options
  };

  const ua = new UA(options);

  ua.start();
  ua.stop();
```

Now...
```ts
  const uri = UserAgent.makeURI("sip:alice@example.com");
  if (!uri) {
    // Failed to create URI
  }
  const options: UserAgentOptions = {
    uri: uri,
    // Set various other options
  };

  const userAgent = new UserAgent(options);

  userAgent.start()
    .then(() => {
      console.log("Connected");

      userAgent.stop()
        .then(() => {
          console.log("Stopped");
        })
        .catch((error) => {
          console.error("Failed to stop");
        });
    })
    .catch((error) => {
      console.error("Failed to connect");
    });
```

## 2. `Registerer` class replaces...

- `UA.register()`
- `UA.unregister()`
- `UA.isregistered()`
- `UA.on("registered")`
- `UA.on("unregistered")`
- `UA.on("registrationFailed")`

Previously...
```ts
  const uri = "sip:alice@example.com";
  const options = {
    authenticationUsername: "username",
    password: "password",
    uri: uri
  };

  const ua = new UA(options);

  ua.on("registered", (response: any) => {
    console.log("Registered");
  });
  ua.on("registrationFailed", () => {
    console.log("Failed to register");
  });
  ua.on("unregistered", (response, cause) => {
    console.log("Unregistered");
  });

  ua.register();

  if (ua.isRegistered()) {
    // Currently registered
  }

  ua.unregister();
```

Now...
```ts
  const uri = UserAgent.makeURI("sip:alice@example.com");
  if (!uri) {
    throw new Error("Failed to create target URI.");
  }

  const options: UserAgentOptions = {
    authorizationUsername: "username",
    authorizationPassword: "password",
    uri: uri
  };

  const userAgent = new UserAgent(options);

  userAgent.start()
    .then(() => {
      console.log("Connected");

      const registerer = new Registerer(userAgent);

      // Setup registerer state change handler
      registerer.stateChange.addListener((newState) => {
        switch (newState) {
          case RegistererState.Registered:
            console.log("Registered");
            break;
          case RegistererState.Unregistered:
            console.log("Unregistered");
            break;
          case RegistererState.Terminated:
            console.log("Terminated");
            break;
        }
      });

      // Send REGISTER
      registerer.register()
        .then((request) => {
          console.log("Successfully sent REGISTER");
          console.log("Sent request = " + request);
        })
        .catch((error) => {
          console.error("Failed to send REGISTER");
        });

      if (registerer.state === RegistererState.Registered) {
        // Currently registered
      }

      // Send un-REGISTER
      registerer.unregister()
        .then((request) => {
          console.log("Successfully sent un-REGISTER");
          console.log("Sent request = " + request);
        })
        .catch((error) => {
          console.error("Failed to send un-REGISTER");
          console.log("Failed to send un-REGISTER");
        });

    })
    .catch((error) => {
      console.error("Failed to connect");
    });
```

## 3. `Inviter` class replaces...

- `UA.invite()`

Previously...
* Setup target and options
* Call `UA.invite()` to create `Session` and send INVITE
* Register event listener to `UA` capture sent INVITE request message
* Register event listeners on `Session` to capture response messages
* Register event listeners on `Session` to handle session state changes

```ts
// Target URI
const uri = new URI("sip", "alice", "example.com");

// Options
const options =  {
  sessionDescriptionHandlerOptions: {
    constraints: {
      audio: true,
      video: false
    }
  }
};

// Send initial INVITE and create a new Session instance
let session;
try {
  session = ua.invite(uri, options);
} catch (error) {
  console.log("Failed to create session");
  throw error;
}

// Add event listener to UA instance to capture sent INVITE
const inviteSentListener = (context) => {
  if (context === session) {
    console.log("Successfully sent INVITE");
    console.log("INVITE request = " + context.request);
    ua.off(inviteSentListener)
  }
};
ua.on("inviteSent", inviteSentListener);

// Add event listeners to Session instance to handle state changes and capture responses
session.on("progress", () => {
  console.log("Ringing");
});
session.on("accepted", (response) => {
  console.log("Answered");
  console.log("Positive response = " + response);
});
session.on("failed", () => {
  console.log("Perhaps failed to send INVITE?");
  console.log("Regardless something went wrong.");
});
session.on("rejected", (response) => {
  console.log("Negative response = " + response);
});
session.on("terminated", () => {
  console.log("Ended");
});
```

Now...
* Construct new `Inviter`
* Setup session state change handler
* Setup target and options (including delegate to capture response messages)
* Call `Inviter.invite()` to send INVITE which returns a `Promise` resolving the sent request

```ts
// Target URI
const uri = UserAgent.makeURI("sip:alice@example.com");
if (!uri) {
  throw new Error("Failed to create target URI.");
}

// Create new Session instance in "initial" state
const session = new Inviter(userAgent, uri);

// Setup session state change handler
session.stateChange.addListener((newState: SessionState) => {
  switch (newState) {
    case SessionState.Establishing:
      console.log("Ringing");
      break;
    case SessionState.Established:
      console.log("Answered");
      break;
    case SessionState.Terminated:
      console.log("Ended");
      break;
  }
});

// Options including delegate to capture response messages
const inviteOptions: InviterInviteOptions = {
  requestDelegate: {
    onAccept: (response) => {
      console.log("Positive response = " + response);
    },
    onReject: (response) => {
      console.log("Negative response = " + response);
    }
  },
  sessionDescriptionHandlerOptions: {
    constraints: {
      audio: true,
      video: false
    }
  }
};

// Send initial INVITE
session.invite(inviteOptions)
  .then((request: OutgoingInviteRequest) => {
    console.log("Successfully sent INVITE");
    console.log("INVITE request = " + request);
  })
  .catch((error: Error) => {
    console.log("Failed to send INVITE");
  });
```

## 4. `Messager` class replaces...

- `UA.message()`

Previously...

```ts
  // Send MESSAGE
  const clientContext = ua.message("sip:alice@example.com", "Hello");
```

Now...

```ts
  // Target URI
  const uri = UserAgent.makeURI("sip:alice@example.com");
  if (!uri) {
    throw new Error("Failed to create target URI.");
  }

  // Create Messager
  const messager = new Messager(userAgent, uri, "Hello");

  // Send MESSAGE
  messager.message()
    .then(() => {
      console.log("Successfully sent MESSAGE");
    })
    .catch((error: Error) => {
      console.log("Failed to send MESSAGE");
    });
```

## 5. `Publisher` class replaces...

- `UA.publish()`

Previously...

```ts
  // Send initial PUBLISH
  const context = ua.publish("sip:alice@example.com", "event-type", "The initial content.", undefined);

  // Send re-PUBLISH
  context.publish("The updated content.");

  // Send un-PUBLISH
  context.unpublish();
```

Now...

```ts
  // Target URI
  const uri = UserAgent.makeURI("sip:alice@example.com");
  if (!uri) {
    throw new Error("Failed to create target URI.");
  }

  const publisher = new Publisher(userAgent, uri, "event-type");

  // Send initial PUBLISH
  publisher.publish("The initial content.")
    .then(() => {
      console.log("Successfully sent PUBLISH");
    })
    .catch((error: Error) => {
      console.log("Failed to send PUBLISH");
    });

  // Send re-PUBLISH
  publisher.publish("The updated content.")
    .then(() => {
      console.log("Successfully sent re-PUBLISH");
    })
    .catch((error: Error) => {
      console.log("Failed to send re-PUBLISH");
    });

  // Send un-PUBLISH
  publisher.unpublish()
    .then(() => {
      console.log("Successfully sent un-PUBLISH");
    })
    .catch((error: Error) => {
      console.log("Failed to send un-PUBLISH");
    });
```

## 6. `Subscriber` class replaces...

- `UA.subscribe()`

Previously...

```ts
  // Send initial SUBSCRIBE
  const subscription = ua.subscribe("sip:alice@example.com", "event-type", undefined);

  subscription.on("notify", (notification) => {
    const body = notification.request.body;
    console.log("Subscription started and/or received notification: \n" + body);

    // Send un-SUBSCRIBE
    subscription.unsubscribe();
  });

  subscription.on("terminated", () => {
    console.log("Failed to subscribe or subscription ended");
  });

  // Send re-PUBLISH
  subscription.subscribe();
```

Now...

```ts
  // Target URI
  const uri = UserAgent.makeURI("sip:alice@example.com");
  if (!uri) {
    throw new Error("Failed to create target URI.");
  }

  // Delegate for handling notifications
  const delegate: SubscriptionDelegate = {
    onNotify: (notification) => {
      const body = notification.request.body;
      console.log("Received notification: \n" + body);

      // Send reply
      notification.accept();

      // Send un-SUBSCRIBE
      subscription.unsubscribe()
        .then(() => {
          console.log("Successfully sent un-SUBSCRIBE");
        })
        .catch((error: Error) => {
          console.log("Failed to send un-SUBSCRIBE");
        });
    }
  };

  // Create subscription
  const subscription = new Subscriber(userAgent, uri, "event-type", { delegate });

  // Setup subscription state change handler
  subscription.stateChange.addListener((newState) => {
    switch (newState) {
      case SubscriptionState.Subscribed:
        console.log("Subscription started");
        break;
      case SubscriptionState.Terminated:
        console.log("Subscription ended");
        break;
    }
  });

  // Send initial SUBSCRIBE
  subscription.subscribe()
    .then(() => {
      console.log("Successfully sent SUBSCRIBE");
    })
    .catch((error: Error) => {
      console.log("Failed to send SUBSCRIBE");
    });
```

## 7. Core library replaces...

- `UA.request()`

Previously...

```ts
  const context = ua.request(C.OPTIONS, "sip:alice@example.com");

  context.on("accepted", (response, cause) => { /* Positive response received */ });
  context.on("rejected", (response, cause) => { /* Negative response received */ });
```

Now...

```ts
  // Core
  const core = userAgent.userAgentCore;

  // From URI
  const fromURI = UserAgent.makeURI("sip:bob@example.com");
  if (!fromURI) {
    throw new Error("Failed to create from URI.");
  }

  // To URI
  const toURI = UserAgent.makeURI("sip:alice@example.com");
  if (!toURI) {
    throw new Error("Failed to create to URI.");
  }

  // Request URI
  const requestURI = toURI;

  // Create message
  const message = core.makeOutgoingRequestMessage("OPTIONS", requestURI, fromURI, toURI, {});

  // Send message
  const request = core.request(message, {
    onAccept: (response) => { /* Positive response received */ },
    onReject: (response) => { /* Negative response received */ },
  });
```


## 8. `UserAgentDelegate` interface replaces

- `UA.on("invite")`
- `UA.on("message")`
- `UA.on("notify")`
- `UA.on("outOfDialogReferRequested")`
- `UA.on("subscribe")`
- `UA.transport.on("connected")`
- `UA.transport.on("connecting")`
- `UA.transport.on("disconnected")`
- `UA.transport.on("disconnecting")`

NOTE: Handling incoming out of dialog REFER and SUBSCRIBE has not yet been implemented (0.16.0).

Previously...
```ts
const ua = new UA();

ua.on("invite", (session) => {
  console.log("INVITE received");
  session.accept();
});

ua.on("message", (message) => {
  console.log("MESSAGE received");
});

ua.on("notify", (notify) => {
  console.log("NOTIFY received");
});

ua.on("outOfDialogReferRequested", (refer) => {
  console.log("REFER received");
});

ua.on("subscribe", (subscribe) => {
  console.log("SUBSCRIBE received");
});

ua.transport.on("disconnected", () => {
  console.log("WebSocket disconnected");
});
```

Now...
```ts
const options = {
  delegate: {
    onConnect: () => {
      console.log("Network connectivity established");
    },
    onDisconnect: (error?: Error) => {
      console.log("Network connectivity lost");
      if (!error) {
        console.log("User agent stopped");
      }
    },
    onInvite: (invitation) => {
      console.log("INVITE received");
      invitation.accept();
    },
    onMessage: (message) => {
      console.log("MESSAGE received");
      message.accept();
    },
    onNotify: (notification) => {
      console.log("NOTIFY received");
      notification.accept();
    },
    onRefer: (referral) => {
      console.log("REFER received");
      referral.accept();
    },
    onSubscribe: (subscription) => {
      console.log("SUBSCRIBE received");
      referral.accept();
    }
  }
}

const userAgent = new UserAgent(options);
```

## 9. `UserAgent.reconnect()` method replaces...

- Transport configuration option `maxReconnectionAttempts`
- Transport configuration options `reconnectionTimeout`

Previously...

By default, the transport would internally reconnect to the WebSocket server in the event of unexpected disconnection. This would attempt to reconnect up to `configuration.maxReconnectionAttempts` times, with a gap of `configuration.reconnectionTimeout` seconds between each request.

Now...

- `SimpleUser` implements a similar internal reconnection strategy which may be configured via `SimpleUserOptions.reconnectionAttempts` and `SimpleUserOptions.reconnectionDelay`
- The API no longer provides an "internal" reconnection strategy, but coding an "external" reconnection strategy is straightforward

Here is how to implement the 0.15.x reconnection strategy using the 0.16.x API...

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

// Handle connection with server lost
userAgent.delegate.onDisconnect = (error?: Error) => {
  // On disconnect, cleanup invalid registrations
  registerer.unregister()
    .catch((e: Error) => {
      // Unregister failed
    });
  // Only attempt to reconnect if network/server dropped the connection
  if (error) {
    attemptReconnection();
  }
};
```