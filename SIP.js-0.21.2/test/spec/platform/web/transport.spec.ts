/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-use-before-define */
import { Server, WebSocket } from "mock-socket";

import { StateTransitionError, TransportState } from "../../../../lib/api/index.js";
import { LoggerFactory } from "../../../../lib/core/index.js";
import { Transport } from "../../../../lib/platform/web/index.js";
import { EmitterSpy, makeEmitterSpy } from "../../../support/api/emitter-spy.js";
import { soon } from "../../../support/api/utils.js";

/**
 * Transport Unit Tests
 *
 * The approach here is to traverse all of the possible paths through
 * the finite state machine (FSM) which the transport implements.
 * We consider the FSM as a directed acyclic graph (even though it is cyclic)
 * by considering all paths through the FSM from "Disconnected" which arrive
 * back a "Disconnected" as comprising the entire acyclic graph.
 */
describe("Web Transport", () => {
  const connectionTimeout = 5; // seconds
  // The mock WebSocket implements a 4 ms delay implemented via setTimeout on connect
  // (so the callbacks can get setup before being called), close and send. So we need
  // to wait 5 ms before we can expect the onopen callback, for example, to be called.
  const serverDelay = 5; // milliseconds
  const server = "wss://localhost:8080";
  const log = new LoggerFactory();
  const logger = log.getLogger("sip.Transport");
  const sendMessage = "just some bits";
  const onConnectMock = jasmine.createSpy("onConnect");
  const onDisconnectMock = jasmine.createSpy("onDisconnect");
  const onMessageMock = jasmine.createSpy("onMessage");
  let mockServer: Server;
  let mockServerWebSocket: WebSocket | undefined;
  let mockServerReceivedMessage: string | undefined;
  let transport: Transport;
  let transportStateSpy: EmitterSpy<TransportState>;
  let connectPromise: Promise<void> | undefined;
  let disconnectPromise: Promise<void> | undefined;
  let sendPromise: Promise<void> | undefined;

  beforeEach(() => {
    jasmine.clock().install();
    initServer();
    transport = new Transport(logger, {
      connectionTimeout,
      server
    });
    transportStateSpy = makeEmitterSpy(transport.stateChange, logger);
    transport.onConnect = onConnectMock;
    transport.onDisconnect = onDisconnectMock;
    transport.onMessage = onMessageMock;
  });

  afterEach(() => {
    transport.dispose();
    mockServer.stop();
    jasmine.clock().uninstall();
  });

  describe("Construct Transport", () => {
    // Construct the transport.
    constructTransport();

    // The transport should now be in the Disconnected state, so traverse the FSM.
    traverseTransportStateMachine();
  });

  function initServer(): void {
    if (mockServer) {
      mockServer.close();
      mockServerWebSocket = undefined;
    }
    mockServer = new Server(server, { selectProtocol: (protocols: Array<string>): string => "sip" });
    mockServer.on("connection", (socket) => {
      logger.log("Mock WebSocket Server: incoming connection");
      mockServerWebSocket = socket as WebSocket; // TODO: Client and WebSocket do not have same signature - close() is an issue.

      socket.on("message", (receivedMessage) => {
        if (typeof receivedMessage !== "string") {
          throw new Error("Mock WebSocket  Server received message not of type string.");
        }
        logger.log(`Mock WebSocket Server: received message "${receivedMessage}"`);
        mockServerReceivedMessage = receivedMessage;
      });

      socket.on("close", () => {
        logger.log("Mock WebSocket Server: server closed");
      });
    });
  }

  function resetAll(): void {
    resetMockServer();
    resetPromises();
    resetSpies();
  }

  function resetMockServer(): void {
    mockServerReceivedMessage = undefined;
  }

  function resetPromises(): void {
    connectPromise = undefined;
    disconnectPromise = undefined;
    sendPromise = undefined;
  }

  function resetSpies(): void {
    onConnectMock.calls.reset();
    onDisconnectMock.calls.reset();
    onMessageMock.calls.reset();
    transportStateSpy.calls.reset();
  }

  function constructTransport(): void {
    it("protocol MUST be WSS", () => {
      expect(transport.protocol).toBe("WSS");
    });

    it("state MUST be 'Disconnected'", () => {
      expect(transport.state).toBe(TransportState.Disconnected);
    });

    it("callbacks MUST NOT have been called", () => {
      expect(onConnectMock).toHaveBeenCalledTimes(0);
      expect(onDisconnectMock).toHaveBeenCalledTimes(0);
      expect(onMessageMock).toHaveBeenCalledTimes(0);
    });

    it("isConnected MUST be false", () => {
      expect(transport.isConnected()).toBe(false);
    });
  }

  /**
   * Run the suite of transport tests at each "node" of the transport FSM (see api/transport.ts).
   *
   * Traverses the entire transport FSM via the following state paths...
   *
   *  0.  Disconnected
   *
   *  1.  Disconnected -> Connecting
   *  1a. Disconnected -> Connecting -> Disconnected (network disconnected) -> TERMINAL
   *
   *  2.  Disconnected -> Connecting -> Disconnecting
   *  2a. Disconnected -> Connecting -> Disconnecting -> Disconnected (network disconnected) -> TERMINAL
   *  2b. Disconnected -> Connecting -> Disconnecting -> Disconnected -> TERMINAL
   *
   *  3.  Disconnected -> Connecting -> Connected
   *  3a. Disconnected -> Connecting -> Connected -> Disconnected (network) -> TERMINAL
   *
   *  4.  Disconnected -> Connecting -> Connected -> Disconnecting
   *  4a. Disconnected -> Connecting -> Connected -> Disconnecting -> Disconnected (network disconnected) -> TERMINAL
   *  4b. Disconnected -> Connecting -> Connected -> Disconnecting -> Disconnected -> TERMINAL
   *
   * Traversal stops upon reaching the Disconnected state (which is where it starts),
   * but may continue on recursively for some number of cycles - two (2) by default
   * so that returning to initial state is tested.
   *
   * @param cycles - The number of times to cycle through the FSM.
   * @param cyclesCompleted - The number of cycles completed.
   */
  function traverseTransportStateMachine(cycles = 2, cyclesCompleted = 0): void {
    if (cyclesCompleted === cycles) {
      return;
    }

    // 0. Disconnected
    describe(`Traverse FSM (${cyclesCompleted + 1} of ${cycles})`, () => {
      // The transport state is now Disconnected, run the test suite
      transportSuiteIn(TransportState.Disconnected);

      // 1. Disconnected -> Connecting
      describe(".connect in Disconnected state to Connecting state", () => {
        // Connect to network by calling connect() but not waiting for promise to resolve
        connectIn(TransportState.Disconnected);
        // The transport state is now Connecting, run the test suite
        transportSuiteIn(TransportState.Connecting);

        // 1a. Disconnected -> Connecting -> Disconnected (network disconnected)
        describe("Server close in Connecting state to Disconnected state", () => {
          // Disconnect network
          serverCloseIn(TransportState.Connecting);
          // TERMINAL: The transport state is now back to Disconnected, so we are at a terminal and may recurse...
          traverseTransportStateMachine(cycles, cyclesCompleted + 1);
        });

        // 2. Disconnected -> Connecting -> Disconnecting
        describe(".disconnect in Connecting state to Disconnecting state", () => {
          // Disconnect from the network by calling disconnect() but not waiting for promise to resolve
          disconnectIn(TransportState.Connecting);
          // The transport state is now Disconnecting, run the test suite
          transportSuiteIn(TransportState.Disconnecting);

          // 2a. Disconnected -> Connecting -> Disconnecting -> Disconnected (network disconnected)
          describe("Server close in Disconnecting state to Disconnecting state", () => {
            // Disconnect network
            serverCloseIn(TransportState.Disconnecting);
            // TERMINAL: The transport state is now back to Disconnected, so we are at a terminal and may recurse...
            traverseTransportStateMachine(cycles, cyclesCompleted + 1);
          });
        });

        // 2b. Disconnected -> Connecting -> Disconnecting -> Disconnected
        describe(".disconnect in Connecting state to Disconnecting state resolves to Disconnected state", () => {
          // Disconnect from the network by calling disconnect() but not waiting for promise to resolve
          disconnectAcceptedCompletesIn(TransportState.Connecting);
          // TERMINAL: The transport state is now back to Disconnected, so we are at a terminal and may recurse...
          traverseTransportStateMachine(cycles, cyclesCompleted + 1);
        });
      });

      // 3. Disconnected -> Connecting -> Connected
      describe(".connect in Disconnected state resolves to Connected state", () => {
        // Connect to network by calling connect() and waiting for promise to resolve
        connectAcceptedCompletesIn(TransportState.Disconnected);
        // The transport state is now Connected, run the test suite
        transportSuiteIn(TransportState.Connected);

        // 3a. Disconnected -> Connecting -> Connected -> Disconnected (network disconnected)
        describe("Server close in Connected state to Disconnected state", () => {
          // Disconnect network
          serverCloseIn(TransportState.Connected);
          // TERMINAL: The transport state is now back to Disconnected, so we are at a terminal and may recurse...
          traverseTransportStateMachine(cycles, cyclesCompleted + 1);
        });

        // 4. Disconnected -> Connecting -> Connected -> Disconnecting
        describe(".disconnect in Connected state to Disconnecting state", () => {
          // Disconnect from the network by calling disconnect() but not waiting for promise to resolve
          disconnectIn(TransportState.Connected);
          // The transport state is now Disconnecting, run the test suite
          transportSuiteIn(TransportState.Disconnecting);

          // 4a. Disconnected -> Connecting -> Connected -> Disconnecting -> Disconnected (network disconnected)
          describe("Server close in Disconnecting state to Disconnected state", () => {
            // Disconnect network
            serverCloseIn(TransportState.Disconnecting);
            // TERMINAL: The transport state is now back to Disconnected, so we are at a terminal and may recurse...
            traverseTransportStateMachine(cycles, cyclesCompleted + 1);
          });
        });

        // 4b. Disconnected -> Connecting -> Connected -> Disconnecting -> Disconnected
        describe(".disconnect in Connected state to Disconnecting state resolves to Disconnected state", () => {
          // Disconnect from the network by calling disconnect() but not waiting for promise to resolve
          disconnectAcceptedCompletesIn(TransportState.Connected);
          // TERMINAL: The transport state is now back to Disconnected, so we are at a terminal and may recurse...
          traverseTransportStateMachine(cycles, cyclesCompleted + 1);
        });
      });
    });
  }

  function transportSuiteIn(state: TransportState): void {
    it(`assert transport state is ${state}`, () => {
      expect(transport.state).toBe(state);
    });

    sendSuiteIn(state);
    disconnectSuiteIn(state);
    connectSuiteIn(state);

    describe(`callbacks fail calling .connect`, () => {
      function assertLoopDetected(error: Error): void {
        if (error instanceof StateTransitionError) {
          return;
        }
        throw error;
      }

      beforeEach(() => {
        onConnectMock.and.callFake(() => transport.connect().catch((error: Error) => assertLoopDetected(error)));
        onDisconnectMock.and.callFake(() => transport.connect().catch((error: Error) => assertLoopDetected(error)));
        onMessageMock.and.callFake(() => transport.connect().catch((error: Error) => assertLoopDetected(error)));
      });

      afterEach(() => {
        onConnectMock.and.stub();
        onDisconnectMock.and.stub();
        onMessageMock.and.stub();
      });

      // Running the entire suite of tests is not necessary
      // connectSuiteIn(state);
      // disconnectSuiteIn(state);

      // This subset tests what we are looking to test
      describe(`.connect accepted in ${state} state completes`, () => {
        connectAcceptedCompletesIn(state);
      });
      describe(`.disconnect accepted in ${state} state completes`, () => {
        disconnectAcceptedCompletesIn(state);
      });
    });

    describe(`callbacks fail calling .disconnect`, () => {
      function assertLoopDetected(error: Error): void {
        if (error instanceof StateTransitionError) {
          return;
        }
        throw error;
      }

      beforeEach(() => {
        onConnectMock.and.callFake(() => transport.disconnect().catch((error: Error) => assertLoopDetected(error)));
        onDisconnectMock.and.callFake(() => transport.disconnect().catch((error: Error) => assertLoopDetected(error)));
        onMessageMock.and.callFake(() => transport.disconnect().catch((error: Error) => assertLoopDetected(error)));
      });

      afterEach(() => {
        onConnectMock.and.stub();
        onDisconnectMock.and.stub();
        onMessageMock.and.stub();
      });

      // Running the entire suite of tests is not necessary
      // connectSuiteIn(state);
      // disconnectSuiteIn(state);

      // This subset tests what we are looking to test
      describe(`.connect accepted in ${state} state completes`, () => {
        connectAcceptedCompletesIn(state);
      });
      describe(`.disconnect accepted in ${state} state completes`, () => {
        disconnectAcceptedCompletesIn(state);
      });
    });
  }

  function connectIn(state: TransportState): void {
    let connectError: Error | undefined;

    beforeEach(() => {
      resetAll();
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
    });

    switch (state) {
      case TransportState.Connecting:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Disconnecting:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        it("state MUST transition to 'Connecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        it("state MUST transition to 'Connecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function connectDisconnectIn(state: TransportState): void {
    let connectError: Error | undefined;
    let disconnectError: Error | undefined;

    beforeEach(() => {
      resetAll();
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
      disconnectPromise = transport.disconnect().catch((error: Error) => {
        disconnectError = error;
      });
    });

    switch (state) {
      case TransportState.Connecting:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        it("state MUST transition to 'Disconnecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        it("state MUST transition to 'Disconnecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
        });
        it("callback 'onDisconnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(1);
        });
        it("'onDisconnect' MUST NOT have Error", () => {
          expect(onDisconnectMock.calls.argsFor(0).length).toEqual(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnecting:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        it("state MUST transition to 'Connecting', 'Disconnecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        it("state MUST transition to 'Connecting', 'Disconnecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function connectDisconnectCompletesIn(state: TransportState): void {
    let connectError: Error | undefined;
    let disconnectError: Error | undefined;

    beforeEach(async () => {
      resetAll();
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
      disconnectPromise = transport.disconnect().catch((error: Error) => {
        disconnectError = error;
      });
      await soon(serverDelay);
    });

    switch (state) {
      case TransportState.Connecting:
        it("connect error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("callback 'onDisconnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(1);
        });
        it("'onDisconnect' MUST NOT have Error", () => {
          expect(onDisconnectMock.calls.argsFor(0).length).toEqual(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnecting:
        it("connect error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("connect error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function connectRejectedCompletesIn(state: TransportState): void {
    let connectError: Error | undefined;

    beforeEach(async () => {
      resetAll();
      // Server rejects connection
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (mockServer.options as any) = { selectProtocol: (protocols: Array<string>): string => "invalid" };
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
      await soon(serverDelay);
    });

    switch (state) {
      case TransportState.Connecting:
        it("connect error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Disconnecting:
        it("error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Connecting', 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Connecting', 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function connectTimeoutCompletesIn(state: TransportState): void {
    let openBlocked: boolean;
    let connectError: Error | undefined;

    beforeEach(async () => {
      openBlocked = false;
      resetAll();
      // HACK: prevent the transport from processing the WebSocket.onopen callback
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (transport as any).onWebSocketOpen = (ev: Event, ws: WebSocket): void => {
        openBlocked = true;
        return;
      };
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
      await soon(serverDelay);
      await soon(connectionTimeout * 1000);
    });

    switch (state) {
      case TransportState.Connecting:
        it("assert open blocked (hack for test working)", () => {
          expect(openBlocked).toEqual(true);
        });
        it("connect error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("assert open not blocked (hack for test working)", () => {
          expect(openBlocked).toEqual(false);
        });
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Disconnecting:
        it("assert open blocked (hack for test working)", () => {
          expect(openBlocked).toEqual(true);
        });
        it("error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Connecting', 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("assert open blocked (hack for test working)", () => {
          expect(openBlocked).toEqual(true);
        });
        it("error MUST be thrown", () => {
          expect(connectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Connecting', 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function connectAcceptedCompletesIn(state: TransportState): void {
    let connectError: Error | undefined;

    beforeEach(async () => {
      resetAll();
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
      await soon(serverDelay);
    });

    switch (state) {
      case TransportState.Connecting:
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST transition to 'Connected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connected]);
        });
        it("callback 'onConnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(1);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Connected:
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Disconnecting:
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST transition to 'Connecting', 'Connected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connected]);
        });
        it("callback 'onConnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(1);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Disconnected:
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST transition to 'Connecting', 'Connected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connected]);
        });
        it("callback 'onConnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(1);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function connectSuiteIn(state: TransportState): void {
    describe(`.connect in ${state} state`, () => {
      connectIn(state);
    });

    describe(`.connect .disconnect in ${state} state`, () => {
      connectDisconnectIn(state);
    });

    describe(`.connect .disconnect in ${state} state completes`, () => {
      connectDisconnectCompletesIn(state);
    });

    describe(`.connect rejected in ${state} state completes`, () => {
      connectRejectedCompletesIn(state);
    });

    describe(`.connect timeout in ${state} state completes`, () => {
      connectTimeoutCompletesIn(state);
    });

    describe(`.connect accepted in ${state} state completes`, () => {
      connectAcceptedCompletesIn(state);
    });
  }

  function disconnectIn(state: TransportState): void {
    let disconnectError: Error | undefined;

    beforeEach(() => {
      resetAll();
      disconnectPromise = transport.disconnect().catch((error: Error) => {
        disconnectError = error;
      });
    });

    switch (state) {
      case TransportState.Connecting:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        it("state MUST transition to 'Disconnecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        it("state MUST transition to 'Disconnecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
        });
        it("callback 'onDisconnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(1);
        });
        it("'onDisconnect' MUST NOT have Error", () => {
          expect(onDisconnectMock.calls.argsFor(0).length).toEqual(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnecting:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function disconnectConnectIn(state: TransportState): void {
    let connectError: Error | undefined;
    let disconnectError: Error | undefined;

    beforeEach(() => {
      resetAll();
      disconnectPromise = transport.disconnect().catch((error: Error) => {
        disconnectError = error;
      });
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
    });

    switch (state) {
      case TransportState.Connecting:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        it("state MUST transition to 'Disconnecting', 'Connecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        it("state MUST transition to 'Disconnecting', 'Connecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connecting]);
        });
        it("callback 'onDisconnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(1);
        });
        it("'onDisconnect' MUST NOT have Error", () => {
          expect(onDisconnectMock.calls.argsFor(0).length).toEqual(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnecting:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        it("state MUST transition to 'Connecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        it("state MUST transition to 'Connecting'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function disconnectConnectCompletesIn(state: TransportState): void {
    let connectError: Error | undefined;
    let disconnectError: Error | undefined;

    beforeEach(async () => {
      resetAll();
      disconnectPromise = transport.disconnect().catch((error: Error) => {
        disconnectError = error;
      });
      connectPromise = transport.connect().catch((error: Error) => {
        connectError = error;
      });
      await soon(serverDelay);
    });

    switch (state) {
      case TransportState.Connecting:
        it("disconnect error MUST be thrown", () => {
          expect(connectError).toEqual(undefined);
          expect(disconnectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST transition to 'Disconnecting', 'Connecting', 'Connected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(3);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(2)).toEqual([TransportState.Connected]);
        });
        it("callback 'onConnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(1);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Connected:
        it("disconnect error MUST be thrown", () => {
          expect(connectError).toEqual(undefined);
          expect(disconnectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST transition to 'Disconnecting', 'Connecting', 'Connected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(3);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(2)).toEqual([TransportState.Connected]);
        });
        it("callback 'onDisconnect' 'onConnected' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(1);
          expect(onDisconnectMock).toHaveBeenCalledTimes(1);
        });
        it("'onDisconnect' MUST NOT have Error", () => {
          expect(onDisconnectMock.calls.argsFor(0).length).toEqual(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Disconnecting:
        it("disconnect error MUST be thrown", () => {
          expect(connectError).toEqual(undefined);
          expect(disconnectError).toEqual(jasmine.any(Error));
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST transition to 'Connecting', 'Connected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connected]);
        });
        it("callback 'onConnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(1);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      case TransportState.Disconnected:
        it("error MUST NOT be thrown", () => {
          expect(connectError).toEqual(undefined);
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        it("state MUST transition to 'Connecting', 'Connected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Connecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Connected]);
        });
        it("callback 'onConnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(1);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be true", () => {
          expect(transport.isConnected()).toBe(true);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function disconnectAcceptedCompletesIn(state: TransportState): void {
    let disconnectError: Error | undefined;

    beforeEach(async () => {
      resetAll();
      disconnectPromise = transport.disconnect().catch((error: Error) => {
        disconnectError = error;
      });
      await soon(serverDelay);
    });

    switch (state) {
      case TransportState.Connecting:
        it("error MUST NOT be thrown", () => {
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnecting', 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("error MUST NOT be thrown", () => {
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnecting', 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(2);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnecting]);
          expect(transportStateSpy.calls.argsFor(1)).toEqual([TransportState.Disconnected]);
        });
        it("callback 'onDisconnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(1);
        });
        it("'onDisconnect' MUST NOT have Error", () => {
          expect(onDisconnectMock.calls.argsFor(0).length).toEqual(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnecting:
        it("error MUST NOT be thrown", () => {
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        it("error MUST NOT be thrown", () => {
          expect(disconnectError).toEqual(undefined);
        });
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST not transition", () => {
          expect(transportStateSpy).not.toHaveBeenCalled();
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function disconnectSuiteIn(state: TransportState): void {
    describe(`.disconnect in ${state} state`, () => {
      disconnectIn(state);
    });

    describe(`.disconnect .connect in ${state} state`, () => {
      disconnectConnectIn(state);
    });

    describe(`.disconnect .connect in ${state} state completes`, () => {
      disconnectConnectCompletesIn(state);
    });

    describe(`.disconnect accepted in ${state} state completes`, () => {
      disconnectAcceptedCompletesIn(state);
    });
  }

  function sendIn(state: TransportState): void {
    let sendError: Error | undefined;

    beforeEach(() => {
      resetAll();
      sendPromise = transport.send(sendMessage).catch((error: Error) => {
        sendError = error;
      });
    });

    switch (state) {
      case TransportState.Connecting:
        it("state MUST be 'Connecting'", () => {
          expect(transport.state).toBe(TransportState.Connecting);
        });
        break;
      case TransportState.Connected:
        it("state MUST be 'Connected'", () => {
          expect(transport.state).toBe(TransportState.Connected);
        });
        break;
      case TransportState.Disconnecting:
        it("state MUST be 'Disconnecting'", () => {
          expect(transport.state).toBe(TransportState.Disconnecting);
        });
        break;
      case TransportState.Disconnected:
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }

  function sendCompletesIn(state: TransportState): void {
    let sendError: Error | undefined;

    beforeEach(async () => {
      resetAll();
      sendPromise = transport.send(sendMessage).catch((error: Error) => {
        sendError = error;
      });
      await soon(serverDelay);
    });

    if (state === TransportState.Connected) {
      it("Error MUST NOT be thrown", () => {
        expect(sendError).toEqual(undefined);
      });

      it("Message sent should match message received", () => {
        expect(mockServerReceivedMessage).toEqual(sendMessage);
      });
    } else {
      it("Error MUST be thrown", () => {
        expect(sendError).toEqual(jasmine.any(Error));
      });
    }
  }

  function sendServerCompletesIn(state: TransportState): void {
    beforeEach(async () => {
      resetAll();
      if (mockServerWebSocket) {
        mockServerWebSocket.send(sendMessage);
      }
      await soon(serverDelay);
    });

    if (state === TransportState.Connected) {
      it("Message sent should match message received", () => {
        expect(onMessageMock).toHaveBeenCalledTimes(1);
        expect(onMessageMock.calls.argsFor(0)).toEqual([sendMessage]);
      });
    } else {
      it("Message callback MUST NOT have been called", () => {
        expect(onMessageMock).toHaveBeenCalledTimes(0);
      });
    }
  }

  function sendSuiteIn(state: TransportState): void {
    describe(`.send in ${state} state`, () => {
      sendIn(state);
    });

    describe(`.send in ${state} state completes`, () => {
      sendCompletesIn(state);
    });

    describe(`.onMessage in ${state} state`, () => {
      sendServerCompletesIn(state);
    });
  }

  function serverCloseIn(state: TransportState): void {
    beforeEach(() => {
      resetAll();
      initServer(); // closes and restarts mock server
    });

    switch (state) {
      case TransportState.Connecting:
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
          expect(onMessageMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Connected:
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnected]);
        });
        it("callback 'onDisconnect' MUST have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(1);
          expect(onMessageMock).toHaveBeenCalledTimes(0);
        });
        it("'onDisconnect' MUST have Error", () => {
          expect(onDisconnectMock.calls.argsFor(0)).toEqual([jasmine.any(Error)]);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnecting:
        it("state MUST be 'Disconnected'", () => {
          expect(transport.state).toBe(TransportState.Disconnected);
        });
        it("state MUST transition to 'Disconnected'", () => {
          expect(transportStateSpy).toHaveBeenCalledTimes(1);
          expect(transportStateSpy.calls.argsFor(0)).toEqual([TransportState.Disconnected]);
        });
        it("callbacks MUST NOT have been called", () => {
          expect(onConnectMock).toHaveBeenCalledTimes(0);
          expect(onDisconnectMock).toHaveBeenCalledTimes(0);
          expect(onMessageMock).toHaveBeenCalledTimes(0);
        });
        it("isConnected MUST be false", () => {
          expect(transport.isConnected()).toBe(false);
        });
        break;
      case TransportState.Disconnected:
        // should not be able to get here
        it(`assert prior state was not Disconnected`, () => {
          expect(state).not.toBe(TransportState.Disconnected);
        });
        break;
      default:
        throw new Error("Unknown state.");
    }
  }
});
