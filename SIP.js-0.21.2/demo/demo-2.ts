/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-use-before-define */
import { SimpleUser, SimpleUserDelegate, SimpleUserOptions } from "../lib/platform/web/index.js";
import { nameAlice, nameBob, uriAlice, uriBob, webSocketServerAlice, webSocketServerBob } from "./demo-users.js";
import { getButton, getInput, getVideo } from "./demo-utils.js";

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
const holdAlice = getInput("holdAlice");
const holdBob = getInput("holdBob");
const muteAlice = getInput("muteAlice");
const muteBob = getInput("muteBob");
const videoLocalAlice = getVideo("videoLocalAlice");
const videoLocalBob = getVideo("videoLocalBob");
const videoRemoteAlice = getVideo("videoRemoteAlice");
const videoRemoteBob = getVideo("videoRemoteBob");

// New SimpleUser for Alice
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
  holdAlice,
  muteAlice,
  videoLocalAlice,
  videoRemoteAlice
);

// New SimpleUser for Bob
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
  holdBob,
  muteBob,
  videoLocalBob,
  videoRemoteBob
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
  holdCheckbox: HTMLInputElement,
  muteCheckbox: HTMLInputElement,
  videoLocalElement: HTMLVideoElement,
  videoRemoteElement: HTMLVideoElement
): SimpleUser {
  console.log(`Creating "${name}" <${aor}>...`);

  // SimpleUser options
  const options: SimpleUserOptions = {
    aor,
    media: {
      constraints: {
        // This demo is making "video only" calls
        audio: false,
        video: true
      },
      local: {
        video: videoLocalElement
      },
      remote: {
        video: videoRemoteElement
      }
    },
    userAgentOptions: {
      // logLevel: "debug",
      displayName
    }
  };

  // Create SimpleUser
  const user = new SimpleUser(webSocketServer, options);

  // SimpleUser delegate
  const delegate: SimpleUserDelegate = {
    onCallAnswered: makeCallAnsweredCallback(user, holdCheckbox, muteCheckbox),
    onCallCreated: makeCallCreatedCallback(user, beginButton, endButton, holdCheckbox, muteCheckbox),
    onCallReceived: makeCallReceivedCallback(user),
    onCallHangup: makeCallHangupCallback(user, beginButton, endButton, holdCheckbox, muteCheckbox),
    onCallHold: makeCallHoldCallback(user, holdCheckbox),
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

  // Setup hold change listeners
  holdCheckbox.addEventListener("change", makeHoldCheckboxClickListener(user, holdCheckbox));

  // Setup mute change listeners
  muteCheckbox.addEventListener("change", makeMuteCheckboxClickListener(user, muteCheckbox));

  // Enable connect button
  connectButton.disabled = false;

  return user;
}

// Helper function to create call anaswered callback
function makeCallAnsweredCallback(
  user: SimpleUser,
  holdCheckbox: HTMLInputElement,
  muteCheckbox: HTMLInputElement
): () => void {
  return () => {
    console.log(`[${user.id}] call answered`);
    holdCheckboxDisabled(false, holdCheckbox);
    muteCheckboxDisabled(false, muteCheckbox);
  };
}

// Helper function to create call received callback
function makeCallReceivedCallback(user: SimpleUser): () => void {
  return () => {
    console.log(`[${user.id}] call received`);
    user.answer().catch((error: Error) => {
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
  endButton: HTMLButtonElement,
  holdCheckbox: HTMLInputElement,
  muteCheckbox: HTMLInputElement
): () => void {
  return () => {
    console.log(`[${user.id}] call created`);
    beginButton.disabled = true;
    endButton.disabled = false;
    holdCheckboxDisabled(true, holdCheckbox);
    muteCheckboxDisabled(true, muteCheckbox);
  };
}

// Helper function to create call hangup callback
function makeCallHangupCallback(
  user: SimpleUser,
  beginButton: HTMLButtonElement,
  endButton: HTMLButtonElement,
  holdCheckbox: HTMLInputElement,
  muteCheckbox: HTMLInputElement
): () => void {
  return () => {
    console.log(`[${user.id}] call hangup`);
    beginButton.disabled = !user.isConnected();
    endButton.disabled = true;
    holdCheckboxDisabled(true, holdCheckbox);
    muteCheckboxDisabled(true, muteCheckbox);
  };
}

// Helper function to create call anaswered callback
function makeCallHoldCallback(user: SimpleUser, holdCheckbox: HTMLInputElement): (held: boolean) => void {
  return (held: boolean) => {
    console.log(`[${user.id}] call hold ${held}`);
    holdCheckbox.checked = held;
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
function makeBeginButtonClickListener(user: SimpleUser, target: string, targetDisplay: string): () => void {
  return () => {
    user
      .call(target, undefined, {
        // An example of how to get access to a SIP response message for custom handling
        requestDelegate: {
          onReject: (response) => {
            console.warn(`[${user.id}] INVITE rejected`);
            let message = `Session invitation to "${targetDisplay}" rejected.\n`;
            message += `Reason: ${response.message.reasonPhrase}\n`;
            message += `Perhaps "${targetDisplay}" is not connected or registered?\n`;
            message += `Or perhaps "${targetDisplay}" did not grant access to video?\n`;
            alert(message);
          }
        },
        withoutSdp: false
      })
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

// Helper function to setup click handler for hold checkbox
function makeHoldCheckboxClickListener(user: SimpleUser, holdCheckbox: HTMLInputElement): () => void {
  return () => {
    if (holdCheckbox.checked) {
      // Checkbox is checked..
      user.hold().catch((error: Error) => {
        holdCheckbox.checked = false;
        console.error(`[${user.id}] failed to hold call`);
        console.error(error);
        alert("Failed to hold call.\n" + error);
      });
    } else {
      // Checkbox is not checked..
      user.unhold().catch((error: Error) => {
        holdCheckbox.checked = true;
        console.error(`[${user.id}] failed to unhold call`);
        console.error(error);
        alert("Failed to unhold call.\n" + error);
      });
    }
  };
}

// Hold helper function
const holdCheckboxDisabled = (disabled: boolean, holdCheckbox: HTMLInputElement): void => {
  holdCheckbox.checked = false;
  holdCheckbox.disabled = disabled;
};

// Helper function to setup click handler for mute checkbox
function makeMuteCheckboxClickListener(user: SimpleUser, muteCheckbox: HTMLInputElement): () => void {
  return () => {
    if (muteCheckbox.checked) {
      // Checkbox is checked..
      user.mute();
      if (user.isMuted() === false) {
        muteCheckbox.checked = false;
        console.error(`[${user.id}] failed to mute call`);
        alert("Failed to mute call.\n");
      }
    } else {
      // Checkbox is not checked..
      user.unmute();
      if (user.isMuted() === true) {
        muteCheckbox.checked = true;
        console.error(`[${user.id}] failed to unmute call`);
        alert("Failed to unmute call.\n");
      }
    }
  };
}

// Mute helper function
const muteCheckboxDisabled = (disabled: boolean, muteCheckbox: HTMLInputElement): void => {
  muteCheckbox.checked = false;
  muteCheckbox.disabled = disabled;
};
