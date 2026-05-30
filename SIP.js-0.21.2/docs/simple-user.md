# SimpleUser

## Overview

The `SimpleUser` class provides an easy simplified interface for making audio and video calls in a web page.

While not intended for all use cases, `SimpleUser` is intended to be suitable for many single page web browser applications. For instance, the examples on the [Demo](../demo/README.md) page are implemented using the `SimpleUser` class exclusively. Furthermore, the [Demo](../demo/README.md) source code provides concrete examples of how to use all the features provided by `SimpleUser`.

If requirements are more advanced, working directly with the [SessionManager](./session-manager.md) which `SimpleUser` is built on top of provides more flexiblity and supports multiple concurrent calls.

If requirements are still more advanced, working directly with the [API](./api.md) which `SessionManager` is built on top of provides more flexiblity.

## Reference Documentation

* [SimpleUser Class Reference](./simple-user/sip.js.md)

## Getting Started

Create an HTML file and write a script to construct a `SimpleUser` instance.

For this example, we will assume the `SimpleUser` class is imported as a module. You could alternatively include SIP.js as a bundle. Compiling the TypeScript to JavaScript and adding it to the HTML page are not covered here, but there are many resources available covering how to add JavaScript to an HTML page (see the [Demo](../demo/README.md) source code for one way to do it).

### Making a Call

* construct `SimpleUser` instance
* connect instance to a server
* place a call
* hangup

### Receiving a Call

* construct `SimpleUser` instance
* provide instance with delegate to handle incoming calls
* connect instance to a server
* answer call
* hangup

#### HTML

```html
<audio id="remoteAudio" controls>
  <p>Your browser doesn't support HTML5 audio.</p>
</audio>
```

#### TypeScript

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

// Helper function to wait
async function wait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// Main function
async function main(): Promise<void> {

  // SIP over WebSocket Server URL
  // The URL of a SIP over WebSocket server which will complete the call.
  // FreeSwitch is an example of a server which supports SIP over WebSocket.
  // SIP over WebSocket is an internet standard the details of which are
  // outside the scope of this documentation, but there are many resources
  // available. See: https://tools.ietf.org/html/rfc7118 for the specification.
  const server = "wss://sip.example.com";

  // SIP Request URI
  // The SIP Request URI of the destination. It's "Who you wanna call?"
  // SIP is an internet standard the details of which are outside the
  // scope of this documentation, but there are many resources available.
  // See: https://tools.ietf.org/html/rfc3261 for the specification.
  const destination = "sip:bob@example.com";

  // SIP Address of Record (AOR)
  // This is the user's SIP address. It's "Where people can reach you."
  // SIP is an internet standard the details of which are outside the
  // scope of this documentation, but there are many resources available.
  // See: https://tools.ietf.org/html/rfc3261 for the specification.
  const aor = "sip:alice@example.com";

  // Configuration Options
  // These are configuration options for the `SimpleUser` instance.
  // Here we are setting the HTML audio element we want to use to
  // play the audio received from the remote end of the call.
  // An audio element is needed to play the audio received from the
  // remote end of the call. Once the call is established, a `MediaStream`
  // is attached to the provided audio element's `src` attribute.
  const options: Web.SimpleUserOptions = {
    aor,
    media: {
      remote: {
        audio: getAudioElement("remoteAudio")
      }
    }
  };

  // Construct a SimpleUser instance
  const simpleUser = new Web.SimpleUser(server, options);

  // Supply delegate to handle inbound calls (optional)
  simpleUser.delegate = {
    onCallReceived: async () => {
      await simpleUser.answer();
    }
  };

  // Connect to server
  await simpleUser.connect();

  // Register to receive inbound calls (optional)
  await simpleUser.register();

  // Place call to the destination
  await simpleUser.call(destination);

  // Wait some number of milliseconds
  await wait(5000);

  // Hangup call
  await simpleUser.hangup();
}

// Run it
main()
  .then(() => console.log(`Success`))
  .catch((error: Error) => console.error(`Failure`, error));
```
