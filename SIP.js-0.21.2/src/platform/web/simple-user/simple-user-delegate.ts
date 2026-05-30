/**
 * Delegate for {@link SimpleUser}.
 * @public
 */
export interface SimpleUserDelegate {
  /**
   * Called when a call is answered.
   * @remarks
   * Callback for handling establishment of a new Session.
   */
  onCallAnswered?(): void;

  /**
   * Called when a call is created.
   * @remarks
   * Callback for handling the creation of a new Session.
   */
  onCallCreated?(): void;

  /**
   * Called when a call is received.
   * @remarks
   * Callback for handling incoming INVITE requests.
   * The callback must either accept or reject the incoming call by calling `answer()` or `decline()` respectively.
   */
  onCallReceived?(): void;

  /**
   * Called when a call is hung up.
   * @remarks
   * Callback for handling termination of a Session.
   */
  onCallHangup?(): void;

  /**
   * Called when a call is put on hold or taken off hold.
   * @remarks
   * Callback for handling re-INVITE responses.
   */
  onCallHold?(held: boolean): void;

  /**
   * Called when a call receives an incoming DTMF tone.
   * @remarks
   * Callback for handling an incoming INFO request with content type application/dtmf-relay.
   */
  onCallDTMFReceived?(tone: string, duration: number): void;

  /**
   * Called upon receiving a message.
   * @remarks
   * Callback for handling incoming MESSAGE requests.
   * @param message - The message received.
   */
  onMessageReceived?(message: string): void;

  /**
   * Called when user is registered to received calls.
   */
  onRegistered?(): void;

  /**
   * Called when user is no longer registered to received calls.
   */
  onUnregistered?(): void;

  /**
   * Called when user is connected to server.
   * @remarks
   * Callback for handling user becomes connected.
   */
  onServerConnect?(): void;

  /**
   * Called when user is no longer connected.
   * @remarks
   * Callback for handling user becomes disconnected.
   *
   * @param error - An Error if server caused the disconnect. Otherwise undefined.
   */
  onServerDisconnect?(error?: Error): void;
}
