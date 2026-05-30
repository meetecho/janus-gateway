# React Native


### SimpleUser class

The [SimpleUser](./simple-user.md) class will not work with React Native (it depends on the DOM).

### API framework

In order to use the [API](./api.md) framework in React Native (for building Android and iOS apps):

- include the [react-native-webrtc](https://github.com/react-native-webrtc/react-native-webrtc) dependency into your React Native project
- call the exposed [registerGlobals()](https://github.com/react-native-webrtc/react-native-webrtc#registerglobals) function before creating a new `UserAgent` instance

By calling `registerGlobals()`, classes required by WebRTC such as `RTCPeerConnection` and `MediaStream` (among others) will be exposed in the global scope which is required by the default WebRTC [SessionDescriptionHandler](./session-description-handler).

For example...
```
import { registerGlobals } from 'react-native-webrtc';
import { UserAgent } from 'sip.js';

registerGlobals();

const ua = new UserAgent(/* configuration options here */);
```

### Core library

The [Core](./core.md) library works with React Native out of the box.
