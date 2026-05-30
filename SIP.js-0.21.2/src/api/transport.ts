import { Transport as CoreTransport } from "../core/transport.js";
import { Emitter } from "./emitter.js";
import { TransportState } from "./transport-state.js";

/**
 * Transport layer interface expected by the `UserAgent`.
 *
 * @remarks
 * The transport behaves in a deterministic manner according to the
 * the state defined in {@link TransportState}.
 *
 * The "Connecting" state is ONLY entered in response to the user calling `connect()`.
 * The "Disconnecting" state is ONLY entered in response to the user calling `disconnect()`.
 * The `onConnect` callback is ALWAYS called upon transitioning to the "Connected" state.
 * The `onDisconnect` callback is ALWAYS called upon transitioning from the "Connected" state.
 *
 * Adherence to the state machine by the transport implementation is critical as the
 * UserAgent depends on this behavior. Furthermore it is critical that the transport
 * transition to the "Disconnected" state in all instances where network connectivity
 * is lost as the UserAgent, API, and application layer more generally depend on knowing
 * network was lost. For example, from a practical standpoint registrations and subscriptions are invalidated
 * when network is lost - particularly in the case of connection oriented transport
 * protocols such as a secure WebSocket transport.
 *
 * Proper handling the application level protocol recovery must be left to the application layer,
 * thus the transport MUST NOT attempt to "auto-recover" from or otherwise hide loss of network.
 * Note that callbacks and emitters such as `onConnect`  and `onDisconnect` MUST NOT call methods
 * `connect()` and `direct()` synchronously (state change handlers must not loop back). They may
 * however do so asynchronously using a Promise resolution, `setTimeout`, or some other method.
 * For example...
 * ```ts
 * transport.onDisconnect = () => {
 *   Promise.resolve().then(() => transport.connect());
 * }
 * ```
 * @public
 */
export interface Transport extends CoreTransport {
  /**
   * Transport state.
   *
   * @remarks
   * The initial Transport state MUST be "disconnected" (after calling constructor).
   */
  readonly state: TransportState;

  /**
   * Transport state change emitter.
   */
  readonly stateChange: Emitter<TransportState>;

  /**
   * Callback on state transition to "Connected".
   *
   * @remarks
   * When the `UserAgent` is constructed, this property is set.
   * ```txt
   * - The `state` MUST be "Connected" when called.
   * ```
   */
  onConnect: (() => void) | undefined;

  /**
   * Callback on state transition from "Connected".
   *
   * @remarks
   * When the `UserAgent` is constructed, this property is set.
   * ```txt
   * - The `state` MUST NOT "Connected" when called.
   * - If prior `state` is "Connecting" or "Connected", `error` MUST be defined.
   * - If prior `state` is "Disconnecting", `error` MUST NOT be undefined.
   * ```
   * If the transition from "Connected" occurs because the transport
   * user requested it by calling `disconnect`, then `error` will be undefined.
   * Otherwise `error` will be defined to provide an indication that the
   * transport initiated the transition from "Connected" - for example,
   * perhaps network connectivity was lost.
   */
  onDisconnect: ((error?: Error) => void) | undefined;

  /**
   * Callback on receipt of a message.
   *
   * @remarks
   * When the `UserAgent` is constructed, this property is set.
   * The `state` MUST be "Connected" when this is called.
   */
  onMessage: ((message: string) => void) | undefined;

  /**
   * Connect to network.
   *
   * @remarks
   * ```txt
   * - If `state` is "Connecting", `state` MUST NOT transition before returning.
   * - If `state` is "Connected", `state` MUST NOT transition before returning.
   * - If `state` is "Disconnecting", `state` MUST transition to "Connecting" before returning.
   * - If `state` is "Disconnected" `state` MUST transition to "Connecting" before returning.
   * - The `state` MUST transition to "Connected" before resolving (assuming `state` is not already "Connected").
   * - The `state` MUST transition to "Disconnecting" or "Disconnected" before rejecting and MUST reject with an Error.
   * ```
   * Resolves when the transport connects. Rejects if transport fails to connect.
   * Rejects with {@link StateTransitionError} if a loop is detected.
   * In particular, callbacks and emitters MUST NOT call this method synchronously.
   */
  connect(): Promise<void>;

  /**
   * Disconnect from network.
   *
   * @remarks
   * ```txt
   * - If `state` is "Connecting", `state` MUST transition to "Disconnecting" before returning.
   * - If `state` is "Connected", `state` MUST transition to "Disconnecting" before returning.
   * - If `state` is "Disconnecting", `state` MUST NOT transition before returning.
   * - If `state` is "Disconnected", `state` MUST NOT transition before returning.
   * - The `state` MUST transition to "Disconnected" before resolving (assuming `state` is not already "Disconnected").
   * - The `state` MUST transition to "Connecting" or "Connected" before rejecting and MUST reject with an Error.
   * ```
   * Resolves when the transport disconnects. Rejects if transport fails to disconnect.
   * Rejects with {@link StateTransitionError} if a loop is detected.
   * In particular, callbacks and emitters MUST NOT call this method synchronously.
   */
  disconnect(): Promise<void>;

  /**
   * Dispose.
   *
   * @remarks
   * When the `UserAgent` is disposed or stopped, this method is called.
   * The `UserAgent` MUST NOT continue to utilize the instance after calling this method.
   */
  dispose(): Promise<void>;

  /**
   * Returns true if the `state` equals "Connected".
   *
   * @remarks
   * This is equivalent to `state === TransportState.Connected`.
   * It is convenient. A common paradigm is, for example...
   *
   * @example
   * ```ts
   * // Monitor transport connectivity
   * userAgent.transport.stateChange.addListener(() => {
   *   if (userAgent.transport.isConnected()) {
   *     // handle transport connect
   *   } else {
   *     // handle transport disconnect
   *   }
   * });
   * ```
   */
  isConnected(): boolean;

  /**
   * Send a message.
   *
   * @remarks
   * ```txt
   * - If `state` is "Connecting", rejects with an Error.
   * - If `state` is "Connected", resolves when the message is sent otherwise rejects with an Error.
   * - If `state` is "Disconnecting", rejects with an Error.
   * - If `state` is "Disconnected", rejects with an Error.
   * ```
   * @param message - Message to send.
   */
  send(message: string): Promise<void>;
}
