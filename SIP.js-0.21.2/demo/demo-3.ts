/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-use-before-define */
import {
  SessionDescriptionHandlerOptions,
  SimpleUser,
  SimpleUserDelegate,
  SimpleUserOptions
} from "../lib/platform/web/index.js";
import { nameAlice, nameBob, uriAlice, uriBob, webSocketServerAlice, webSocketServerBob } from "./demo-users.js";
import { getButton, getDiv, getInput } from "./demo-utils.js";

// A class which extends SimpleUser to handle setup and use of a data channel
class SimpleUserWithDataChannel extends SimpleUser {
  private _dataChannel: RTCDataChannel | undefined;

  constructor(
    private messageInput: HTMLInputElement,
    private sendButton: HTMLButtonElement,
    private receiveDiv: HTMLDivElement,
    server: string,
    options: SimpleUserOptions = {}
  ) {
    super(server, options);
  }

  public get dataChannel(): RTCDataChannel | undefined {
    return this._dataChannel;
  }

  public set dataChannel(dataChannel: RTCDataChannel | undefined) {
    this._dataChannel = dataChannel;
    if (!dataChannel) {
      return;
    }
    dataChannel.onclose = (event) => {
      console.log(`[${this.id}] data channel onClose`);
      this.messageInput.disabled = true;
      this.receiveDiv.classList.add("disabled");
      this.sendButton.disabled = true;
    };
    dataChannel.onerror = (event) => {
      console.error(`[${this.id}] data channel onError`);
      console.error((event as RTCErrorEvent).error);
      alert(`[${this.id}] Data channel error.\n` + (event as RTCErrorEvent).error);
    };
    dataChannel.onmessage = (event) => {
      console.log(`[${this.id}] data channel onMessage`);
      const el = document.createElement("p");
      el.classList.add("message");
      const node = document.createTextNode(event.data);
      el.appendChild(node);
      this.receiveDiv.appendChild(el);
      this.receiveDiv.scrollTop = this.receiveDiv.scrollHeight;
    };
    dataChannel.onopen = (event) => {
      console.log(`[${this.id}] data channel onOpen`);
      this.messageInput.disabled = false;
      this.receiveDiv.classList.remove("disabled");
      this.sendButton.disabled = false;
    };
  }

  public send(): void {
    if (!this.dataChannel) {
      const error = "No data channel";
      console.error(`[${this.id}] failed to send message`);
      console.error(error);
      alert(`[${this.id}] Failed to send message.\n` + error);
      return;
    }
    const msg = this.messageInput.value;
    if (!msg) {
      console.log(`[${this.id}] no data to send`);
      return;
    }
    this.messageInput.value = "";
    switch (this.dataChannel.readyState) {
      case "connecting":
        console.error("Attempted to send message while data channel connecting.");
        break;
      case "open":
        try {
          this.dataChannel.send(msg);
        } catch (error) {
          console.error(`[${this.id}] failed to send message`);
          console.error(error);
          alert(`[${this.id}] Failed to send message.\n` + error);
        }
        break;
      case "closing":
        console.error("Attempted to send message while data channel closing.");
        break;
      case "closed":
        console.error("Attempted to send while data channel connection closed.");
        break;
    }
  }
}

const connectAlice = getButton("connectAlice");
const connectBob = getButton("connectBob");
const disconnectAlice = getButton("disconnectAlice");
const disconnectBob = getButton("disconnectBob");
const registerAlice = getButton("registerAlice");
const registerBob = getButton("registerBob");
const unregisterAlice = getButton("unregisterAlice");
const unregisterBob = getButton("unregisterBob");
const beginAlice = getButton("beginAlice");
const beginBob = getButton("beginBob");
const endAlice = getButton("endAlice");
const endBob = getButton("endBob");
const messageAlice = getInput("messageAlice");
const sendAlice = getButton("sendAlice");
const receiveAlice = getDiv("receiveAlice");
const messageBob = getInput("messageBob");
const sendBob = getButton("sendBob");
const receiveBob = getDiv("receiveBob");

// New SimpleUserWithDataChannel for Alice
const alice = buildUser(
  webSocketServerAlice,
  uriAlice,
  nameAlice,
  uriBob,
  nameBob,
  connectAlice,
  disconnectAlice,
  registerAlice,
  unregisterAlice,
  beginAlice,
  endAlice,
  messageAlice,
  sendAlice,
  receiveAlice
);

// New SimpleUserWithDataChannel for Bob
const bob = buildUser(
  webSocketServerBob,
  uriBob,
  nameBob,
  uriAlice,
  nameAlice,
  connectBob,
  disconnectBob,
  registerBob,
  unregisterBob,
  beginBob,
  endBob,
  messageBob,
  sendBob,
  receiveBob
);

if (!alice || !bob) {
  console.error("Something went wrong");
}

function buildUser(
  webSocketServer: string,
  aor: string,
  displayName: string,
  targetAOR: string,
  targetName: string,
  connectButton: HTMLButtonElement,
  disconnectButton: HTMLButtonElement,
  registerButton: HTMLButtonElement,
  unregisterButton: HTMLButtonElement,
  beginButton: HTMLButtonElement,
  endButton: HTMLButtonElement,
  messageInput: HTMLInputElement,
  sendButton: HTMLButtonElement,
  receiveDiv: HTMLDivElement
): SimpleUser {
  console.log(`Creating "${name}" <${aor}>...`);

  // SimpleUser options
  const options: SimpleUserOptions = {
    aor,
    media: {
      constraints: {
        // This demo is making "data only" calls
        audio: false,
        video: false
      }
    },
    userAgentOptions: {
      // logLevel: "debug",
      displayName
    }
  };

  // Create SimpleUser
  const user = new SimpleUserWithDataChannel(messageInput, sendButton, receiveDiv, webSocketServer, options);

  // SimpleUser delegate
  const delegate: SimpleUserDelegate = {
    onCallCreated: makeCallCreatedCallback(user, beginButton, endButton),
    onCallReceived: makeCallReceivedCallback(user),
    onCallHangup: makeCallHangupCallback(user, beginButton, endButton),
    onRegistered: makeRegisteredCallback(user, registerButton, unregisterButton),
    onUnregistered: makeUnregisteredCallback(user, registerButton, unregisterButton),
    onServerConnect: makeServerConnectCallback(user, connectButton, disconnectButton, registerButton, beginButton),
    onServerDisconnect: makeServerDisconnectCallback(user, connectButton, disconnectButton, registerButton, beginButton)
  };
  user.delegate = delegate;

  // Setup connect button click listeners
  connectButton.addEventListener(
    "click",
    makeConnectButtonClickListener(user, connectButton, disconnectButton, registerButton, beginButton)
  );

  // Setup disconnect button click listeners
  disconnectButton.addEventListener(
    "click",
    makeDisconnectButtonClickListener(user, connectButton, disconnectButton, registerButton, beginButton)
  );

  // Setup register button click listeners
  registerButton.addEventListener("click", makeRegisterButtonClickListener(user, registerButton));

  // Setup unregister button click listeners
  unregisterButton.addEventListener("click", makeUnregisterButtonClickListener(user, unregisterButton));

  // Setup begin button click listeners
  beginButton.addEventListener("click", makeBeginButtonClickListener(user, targetAOR, targetName));

  // Setup end button click listeners
  endButton.addEventListener("click", makeEndButtonClickListener(user));

  // Setup send button click listeners
  sendButton.addEventListener("click", () => user.send());

  // Enable connect button
  connectButton.disabled = false;

  return user;
}

// Helper function to create call received callback
function makeCallReceivedCallback(user: SimpleUserWithDataChannel): () => void {
  return () => {
    console.log(`[${user.id}] call received`);
    // An example of how to have the session description handler callback when a data channel is created upon answering.
    const sessionDescriptionHandlerOptions: SessionDescriptionHandlerOptions = {
      onDataChannel: (dataChannel: RTCDataChannel) => {
        console.log(`[${user.id}] data channel created`);
        user.dataChannel = dataChannel;
      }
    };
    user.answer({ sessionDescriptionHandlerOptions }).catch((error: Error) => {
      console.error(`[${user.id}] failed to answer call`);
      console.error(error);
      alert(`[${user.id}] Failed to answer call.\n` + error);
    });
  };
}

// Helper function to create call created callback
function makeCallCreatedCallback(
  user: SimpleUser,
  beginButton: HTMLButtonElement,
  endButton: HTMLButtonElement
): () => void {
  return () => {
    console.log(`[${user.id}] call created`);
    beginButton.disabled = true;
    endButton.disabled = false;
  };
}

// Helper function to create call hangup callback
function makeCallHangupCallback(
  user: SimpleUser,
  beginButton: HTMLButtonElement,
  endButton: HTMLButtonElement
): () => void {
  return () => {
    console.log(`[${user.id}] call hangup`);
    beginButton.disabled = !user.isConnected();
    endButton.disabled = true;
  };
}

// Helper function to create registered callback
function makeRegisteredCallback(
  user: SimpleUser,
  registerButton: HTMLButtonElement,
  unregisterButton: HTMLButtonElement
): () => void {
  return () => {
    console.log(`[${user.id}] registered`);
    registerButton.disabled = true;
    unregisterButton.disabled = false;
  };
}

// Helper function to create unregistered callback
function makeUnregisteredCallback(
  user: SimpleUser,
  registerButton: HTMLButtonElement,
  unregisterButton: HTMLButtonElement
): () => void {
  return () => {
    console.log(`[${user.id}] unregistered`);
    registerButton.disabled = !user.isConnected();
    unregisterButton.disabled = true;
  };
}

// Helper function to create network connect callback
function makeServerConnectCallback(
  user: SimpleUser,
  connectButton: HTMLButtonElement,
  disconnectButton: HTMLButtonElement,
  registerButton: HTMLButtonElement,
  beginButton: HTMLButtonElement
): () => void {
  return () => {
    console.log(`[${user.id}] connected`);
    connectButton.disabled = true;
    disconnectButton.disabled = false;
    registerButton.disabled = false;
    beginButton.disabled = false;
  };
}

// Helper function to create network disconnect callback
function makeServerDisconnectCallback(
  user: SimpleUser,
  connectButton: HTMLButtonElement,
  disconnectButton: HTMLButtonElement,
  registerButton: HTMLButtonElement,
  beginButton: HTMLButtonElement
): () => void {
  return (error?: Error) => {
    console.log(`[${user.id}] disconnected`);
    connectButton.disabled = false;
    disconnectButton.disabled = true;
    registerButton.disabled = true;
    beginButton.disabled = true;
    if (error) {
      alert(`[${user.id}] Server disconnected.\n` + error.message);
    }
  };
}

// Helper function to setup click handler for connect button
function makeConnectButtonClickListener(
  user: SimpleUser,
  connectButton: HTMLButtonElement,
  disconnectButton: HTMLButtonElement,
  registerButton: HTMLButtonElement,
  beginButton: HTMLButtonElement
): () => void {
  return () => {
    user
      .connect()
      .then(() => {
        connectButton.disabled = true;
        disconnectButton.disabled = false;
        registerButton.disabled = false;
        beginButton.disabled = false;
      })
      .catch((error: Error) => {
        console.error(`[${user.id}] failed to connect`);
        console.error(error);
        alert(`[${user.id}] Failed to connect.\n` + error);
      });
  };
}

// Helper function to setup click handler for disconnect button
function makeDisconnectButtonClickListener(
  user: SimpleUser,
  connectButton: HTMLButtonElement,
  disconnectButton: HTMLButtonElement,
  registerButton: HTMLButtonElement,
  beginButton: HTMLButtonElement
): () => void {
  return () => {
    user
      .disconnect()
      .then(() => {
        connectButton.disabled = false;
        disconnectButton.disabled = true;
        registerButton.disabled = true;
        beginButton.disabled = true;
      })
      .catch((error: Error) => {
        console.error(`[${user.id}] failed to disconnect`);
        console.error(error);
        alert(`[${user.id}] Failed to disconnect.\n` + error);
      });
  };
}

// Helper function to setup click handler for register button
function makeRegisterButtonClickListener(user: SimpleUser, registerButton: HTMLButtonElement): () => void {
  return () => {
    user
      .register({
        // An example of how to get access to a SIP response message for custom handling
        requestDelegate: {
          onReject: (response) => {
            console.warn(`[${user.id}] REGISTER rejected`);
            let message = `Registration of "${user.id}" rejected.\n`;
            message += `Reason: ${response.message.reasonPhrase}\n`;
            alert(message);
          }
        }
      })
      .then(() => {
        registerButton.disabled = true;
      })
      .catch((error: Error) => {
        console.error(`[${user.id}] failed to register`);
        console.error(error);
        alert(`[${user.id}] Failed to register.\n` + error);
      });
  };
}

// Helper function to setup click handler for unregister button
function makeUnregisterButtonClickListener(user: SimpleUser, unregisterButton: HTMLButtonElement): () => void {
  return () => {
    user
      .unregister()
      .then(() => {
        unregisterButton.disabled = true;
      })
      .catch((error: Error) => {
        console.error(`[${user.id}] failed to unregister`);
        console.error(error);
        alert(`[${user.id}] Failed to unregister.\n` + error);
      });
  };
}

// Helper function to setup click handler for begin button
function makeBeginButtonClickListener(
  user: SimpleUserWithDataChannel,
  target: string,
  targetDisplay: string
): () => void {
  return () => {
    // An example of how to have the session description handler create a data channel when generating an
    // initial offer and how to have the session description handler callback when a data channel is created.
    const sessionDescriptionHandlerOptions: SessionDescriptionHandlerOptions = {
      dataChannel: true,
      onDataChannel: (dataChannel: RTCDataChannel) => {
        console.log(`[${user.id}] data channel created`);
        user.dataChannel = dataChannel;
      }
    };
    user
      .call(
        target,
        { sessionDescriptionHandlerOptions },
        {
          // An example of how to get access to a SIP response message for custom handling
          requestDelegate: {
            onReject: (response) => {
              console.warn(`[${user.id}] INVITE rejected`);
              let message = `Session invitation to "${targetDisplay}" rejected.\n`;
              message += `Reason: ${response.message.reasonPhrase}\n`;
              message += `Perhaps "${targetDisplay}" is not connected or registered?\n`;
              alert(message);
            }
          }
        }
      )
      .catch((error: Error) => {
        console.error(`[${user.id}] failed to begin session`);
        console.error(error);
        alert(`[${user.id}] Failed to begin session.\n` + error);
      });
  };
}

// Helper function to setup click handler for begin button
function makeEndButtonClickListener(user: SimpleUser): () => void {
  return () => {
    user.hangup().catch((error: Error) => {
      console.error(`[${user.id}] failed to end session`);
      console.error(error);
      alert(`[${user.id}] Failed to end session.\n` + error);
    });
  };
}
