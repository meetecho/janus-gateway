# Migration from Simple to SimpleUser

Migrating from `Simple` (documented [here](https://sipjs.com/guides/simple/))
to `SimpleUser` (documented [here](./simple-user))
is relatively simple.

Want to see working `SimpleUser` code examples? Run the [demo](../demo/README.md).

Herein are some before and after migration code snippets...

## HTML

```html
<html>
  <head>
    <link rel="stylesheet" href="my-styles.css">
  </head>
  <body>
    <video id="localVideo" muted="muted"></video>
    <video id="remoteVideo" muted="muted"></video>
  </body>
</html>
```

## Importing Simple/SimpleUser

Before...
```js
import { Simple } from "sip.js/lib/Web";
```
After...
```ts
import { SimpleUser, SimpleUserOptions } from "sip.js/lib/platform/web";
```

## Create an Simple/SimpleUser Instance

Before...
```js
var options = {
  media: {
    local: {
      video: document.getElementById('localVideo')
    },
    remote: {
      video: document.getElementById('remoteVideo'),
      // This is necessary to do an audio/video call as opposed to just a video call
      audio: document.getElementById('remoteVideo')
    }
  },
  ua: {
    wsServers: "wss://sip.example.com"
  }
};

var simple = new Simple(options);
```
After...
```ts
const server = "wss://sip.example.com";

const options: SimpleUserOptions = {
  media: {
    constraints: { 
      audio: true,
      video: true
    },
    local: {
      video: document.getElementById("localVideo") as HTMLVideoElement
    },
    remote: {
      video: document.getElementById("remoteVideo") as HTMLVideoElement,
    }
  },
  userAgentOptions: {}
};

const simpleUser = new SimpleUser(server, options);
```

## Starting and Ending a Call

Before...
```js
var endButton = document.getElementById('endCall');
endButton.addEventListener("click", function () {
  simple.hangup();
  alert("Call Ended");
}, false);

simple.call('welcome@onsip.com');
```
After...
```ts
const endButton = document.getElementById("endCall");
endButton.addEventListener("click", async () => {
  await simpleUser.hangup();
  alert("Call Ended");
}, false);

simpleUser.call("welcome@onsip.com");
```

## Answering a Call

Before...
```js
var options = {
  media: {
    local: {
      video: document.getElementById('localVideo')
    },
    remote: {
      video: document.getElementById('remoteVideo'),
      // This is necessary to do an audio/video call as opposed to just a video call
      audio: document.getElementById('remoteVideo')
    }
  },
  ua: {
    uri: 'test@example.com',
    authorizationUser: 'test',
    password: 'password',
    wsServers: "wss://sip.example.com"
  }
};

var simple = new Simple(options);

simple.on('ringing', function () {
  simple.answer();
});
```
After...
```ts
const server = "wss://sip.example.com";

const options: SimpleUserOptions = {
  media: {
    constraints: { 
      audio: true,
      video: true
    },
    local: {
      video: document.getElementById("localVideo") as HTMLVideoElement
    },
    remote: {
      video: document.getElementById("remoteVideo") as HTMLVideoElement,
    }
  },
  aor: "sip:test@example.com",
  userAgentOptions: {
    authorizationUsername: "test",
    authorizationPassword: "password"
  }
};

const simpleUser = new SimpleUser(server, options);

simpleUser.delegate = {
  onCallReceived: async () => {
    await simpleUser.answer();
  }
};
```
