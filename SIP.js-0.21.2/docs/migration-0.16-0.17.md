# Migration from 0.16.x to 0.17.x

## SimpleUser class

The [SimpleUser](./simple-user.md) class is compatible with 0.16.x. No changes are required.

## API framework

The interface provided by default WebRTC [SessionDescriptionHandler](./session-description-handler) has been rewritten. While existing custom `SessionDescriptionHandler` implementations should still work without changes, sub-classes that extended the WebRTC `SessionDescriptionHandler` from 0.16.x may no longer work.

The React Native `SessionDescriptionHandler` has been removed. If you are using React Native, see [here](./react-native.md).

### WebRTC [SessionDescriptionHandler](./session-description-handler) Rewrite

Issues addressed:
- Support for providing alternative media acquisition
- Supports upgrading audio session to video session
- Options may be modified on a per call basis
- Methods are now available to be extended
- Many new methods have been added
- Data channel usage is now supported

Breaking changes:
- The `getMediaStream` method has been replaced by the `MediaStreamFactory` interface
- All the various "events" are no longer emitted

#### Events Removed

Replaced by [MediaStreamFactory](./session-description-handler/sip.js.mediastreamfactory.md) interface:
- "userMedia"
- "userMediaRequest"
- "userMediaFailed"

Providing for alternative media acquisition has been a common request. Now...

```ts
import { UserAgent, UserAgentOptions, Web } from "sip.js";

// Create media stream factory
const myMediaStreamFactory: Web.MediaStreamFactory = (
  constraints: MediaStreamConstraints,
  sessionDescriptionHandler: Web.SessionDescriptionHandler
): Promise<MediaStream> => {
  const mediaStream = new MediaStream(); // my custom media stream acquisition
  return Promise.resolve(mediaStream);
}

// Create session description handler factory
const mySessionDescriptionHandlerFactory: Web.SessionDescriptionHandlerFactory = 
  Web.defaultSessionDescriptionHandlerFactory(myMediaStreamFactory);

// Create user agent
const myUserAgent = new UserAgent({
  sessionDescriptionHandlerFactory: mySessionDescriptionHandlerFactory
});
```

Replaced by [SessionDescriptionHandler.remoteMediaStream](./session-description-handler/sip.js.sessiondescriptionhandler.remotemediastream.md) property:
- "addTrack"
- "addStream"

Getting a handle on remote tracks when they are added has historically been tricky. Now [SessionDescriptionHandler.remoteMediaStream](./session-description-handler/sip.js.sessiondescriptionhandler.remotemediastream.md) is always available and always has the current remote tracks (if any). Furthermore You can add event handlers for `addTrack` and `removeTrack` to the `MediaStream` and get updated when tracks are added or removed.

Replaced by [SessionDescriptionHandler.peerConnectionDelegate](./session-description-handler/sip.js.peerconnectiondelegate.md) property:
- "iceCandidate"
- "iceConnection"
- "iceConnectionClosed"
- "iceConnectionChecking"
- "iceConnectionCompleted"
- "iceConnectionConnected"
- "iceConnectionDisconnected"
- "iceConnectionFailed"
- "iceGathering"
- "iceGatheringComplete"

Should no longer be needed with new API, but extend `SessionDescriptionHandler` if need be:
- "confirmed"
- "getDescription"
- "setDescription"
- "setRemoteDescription"
- "peerConnection-createAnswerFailed"
- "peerConnection-createOfferFailed"
- "peerConnection-SetLocalDescriptionFailed"
- "peerConnection-setRemoteDescriptionFailed"

## Core library

The [Core](./core.md) library is compatible with 0.16.x. No changes are required.

