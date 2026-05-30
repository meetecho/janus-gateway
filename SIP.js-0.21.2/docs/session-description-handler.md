# SessionDescriptionHandler - WebRTC

## Overview

The `SessionDescriptionHandler` class provides an implementation of which adhears to the `SessionDescriptionHandler` interface required by the [API](./api.md). The class is intended to be suitable for extending to provide custom behaviour if needed. It supports up to one audio track and/or one video track per session.

## Reference Documentation

- [SessionDescriptionHandler Class Reference](./session-description-handler/sip.js.md)

## How do I get the session description handler for an `Invitation` or an `Inviter`?

`Session` has a `sessionDescriptionHandler` property. `Invitation` and `Inviter` extend `Session`, so...

See [`Session.sessionDescriptionHandler` docs](./api/sip.js.session.sessiondescriptionhandler.md) for more info.

## When is a `Session`'s session description handler available?

If `Session` is an instance of `Inviter` and an offer was sent in the INVITE, `Session.sessionDescriptionHandler` will be defined when the session state changes to `SessionState.Establishing`. Otherwise it will be defined when the session state changes to `SessionState.Established`.

## How do I play the local and remote `MediaStream`?

The session description handler and media tracks are availble once the `Session` state transitions to `SessionState.Established`...

```ts
import { Session, SessionState, Web } from "sip.js";

// A Session state change handler which assigns media streams to HTML media elements.
function handleStateChanges(
  session: Session,
  localHTMLMediaElement: HTMLVideoElement | undefined,
  remoteHTMLMediaElement: HTMLAudioElement | HTMLVideoElement | undefined
): void {
  // Track session state changes and set media tracks to HTML elements when they become available.
  session.stateChange.addListener((state: SessionState) => {
    switch (state) {
      case SessionState.Initial:
        break;
      case SessionState.Establishing:
        break;
      case SessionState.Established:
        const sessionDescriptionHandler = session.sessionDescriptionHandler;
        if (!sessionDescriptionHandler || !(sessionDescriptionHandler instanceof Web.SessionDescriptionHandler)) {
          throw new Error("Invalid session description handler.");
        }
        if (localHTMLMediaElement) {
          assignStream(sessionDescriptionHandler.localMediaStream, localHTMLMediaElement);
        }
        if (remoteHTMLMediaElement) {
          assignStream(sessionDescriptionHandler.remoteMediaStream, remoteHTMLMediaElement);
        }
        break;
      case SessionState.Terminating:
        break;
      case SessionState.Terminated:
        break;
      default:
        throw new Error("Unknown session state.");
    }
  });
}

// Assign a MediaStream to an HTMLMediaElement and update if tracks change.
function assignStream(stream: MediaStream, element: HTMLMediaElement): void {
  // Set element source.
  element.autoplay = true; // Safari does not allow calling .play() from a non user action
  element.srcObject = stream;

  // Load and start playback of media.
  element.play().catch((error: Error) => {
    console.error("Failed to play media");
    console.error(error);
  });

  // If a track is added, load and restart playback of media.
  stream.onaddtrack = (): void => {
    element.load(); // Safari does not work otheriwse
    element.play().catch((error: Error) => {
      console.error("Failed to play remote media on add track");
      console.error(error);
    });
  };

  // If a track is removed, load and restart playback of media.
  stream.onremovetrack = (): void => {
    element.load(); // Safari does not work otheriwse
    element.play().catch((error: Error) => {
      console.error("Failed to play remote media on remove track");
      console.error(error);
    });
  };
}
```

## How do I override how local media is obtained?

Providing for alternative media acquisition can be done by providing a `MediaStreamFactory`...

```ts
import { UserAgent, UserAgentOptions, Web } from "sip.js";

// Create media stream factory
const myMediaStreamFactory: Web.MediaStreamFactory = (
  constraints: MediaStreamConstraints,
  sessionDescriptionHandler: Web.SessionDescriptionHandler
): Promise<MediaStream> => {
  const mediaStream = new MediaStream(); // my custom media stream acquisition
  return Promise.resolve(mediaStream);
};

// Create session description handler factory
const mySessionDescriptionHandlerFactory: Web.SessionDescriptionHandlerFactory = Web.defaultSessionDescriptionHandlerFactory(
  myMediaStreamFactory
);

// Create user agent
const myUserAgent = new UserAgent({
  sessionDescriptionHandlerFactory: mySessionDescriptionHandlerFactory
});
```

## How do I detect if a track was added or removed?

The session description handler is availble once the `Session` state transitions to `SessionState.Established`, however there are cases where tracks are added or removed if the media changes - for example, on upgrade from audio only to a video session. Not also that when the `SessionDescriptionHandler` is constructed the media stream initially has no tracks, so the presence of tracks should not be assumed.

See [`SessionDescriptionHandler.remoteMediaStream` docs](./session-description-handler/sip.js.sessiondescriptionhandler.remotemediastream.md) for more info.

```ts
import { Web } from "sip.js";

function handleAddTrack(sessionDescriptionHandler: Web.SessionDescriptionHandler): void {
  sessionDescriptionHandler.remoteMediaStream.onaddtrack = (event) => {
    const track = event.track;
    console.log("A track was added");
  };
  sessionDescriptionHandler.remoteMediaStream.onremovetrack = (event) => {
    const track = event.track;
    console.log("A track was removed");
  };
}
```

## How do I put a session on "hold"?

```ts
import { Web } from "sip.js";

// The Session.sessionDescriptionHandlerOptionsReInvite property
// may be used to pass options to the SessionDescriptionHandler.
const sessionDescriptionHandlerOptions: Web.SessionDescriptionHandlerOptions = {
  hold: true; // set to false to "unhold" session
}
session.sessionDescriptionHandlerOptionsReInvite = sessionDescriptionHandlerOptions;

const options: SessionInviteOptions = {
  requestDelegate: {
    onAccept: (): void => {
      // session is on hold
    },
    onReject: (): void => {
      // re-invite request was rejected, call not on hold
    }
  }
};

// Send re-INVITE
session
  .invite(options)
  .catch((error: Error) => {
    if (error instanceof RequestPendingError) {
      // a hold request is already in progress
    }
  });
```

See [docs](./session-description-handler/sip.js.sessiondescriptionhandleroptions.md) for more info.

## How do I get a handle on the session description handler when it is created?

If you must have access as soon as it is created and before it is utilized, use the session delegate.

See [`SessionDelegate.onSessionDescriptionHandler()` docs](./api/sip.js.sessiondelegate.onsessiondescriptionhandler.md) for more info.

```ts
import { SessionDescriptionHandler } from "sip.js";

function handleSessionDescriptionHandlerCreated(session: Session): void {
  session.delegate = {
    onSessionDescriptionHandler: (sessionDescriptionHandler: SessionDescriptionHandler, provisional: boolean) => {
      console.log("A session description handler was created");
    }
  };
}
```

## How do I get a handle on the peer connection?

`SessionDescriptionHandler` has a `peerConnection` property.

See [docs](./session-description-handler/sip.js.sessiondescriptionhandler.md) for more info.

## How do I get a handle on the peer connection events?

`SessionDescriptionHandler` has a `peerConnectionDelegate` property.

See [docs](./session-description-handler/sip.js.sessiondescriptionhandler.md) for more info.

## How do I use more than one audio and one video track?

`SessionDescriptionHandler` only supports up to one audio and one video track.

A custom session description handler needs to be created to support more tracks.
