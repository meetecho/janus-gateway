/**
 * Delegate for {@link Session} offer/answer exchange.
 * @public
 */
export interface SessionDescriptionHandler {
  /**
   * Destructor.
   */
  close(): void;

  /**
   * Gets the local description from the underlying media implementation.
   * @param options - Options object to be used by getDescription.
   * @param modifiers - Array with one time use description modifiers.
   * @returns Promise that resolves with the local description to be used for the session.
   * Rejects with `ClosedSessionDescriptionHandlerError` when this method
   * is called after close or when close occurs before complete.
   */
  getDescription(
    options?: SessionDescriptionHandlerOptions,
    modifiers?: Array<SessionDescriptionHandlerModifier>
  ): Promise<BodyAndContentType>;

  /**
   * Returns true if the Session Description Handler can handle the Content-Type described by a SIP message.
   * @param contentType - The content type that is in the SIP Message.
   * @returns True if the content type is  handled by this session description handler. False otherwise.
   */
  hasDescription(contentType: string): boolean;

  /**
   * Rolls back the current local/remote offer to the prior stable state.
   */
  rollbackDescription?(): Promise<void>;

  /**
   * Sets the remote description to the underlying media implementation.
   * @param  sessionDescription - The description provided by a SIP message to be set on the media implementation.
   * @param options - Options object to be used by setDescription.
   * @param modifiers - Array with one time use description modifiers.
   * @returns Promise that resolves once the description is set.
   * Rejects with `ClosedSessionDescriptionHandlerError` when this method
   * is called after close or when close occurs before complete.
   */
  setDescription(
    sdp: string,
    options?: SessionDescriptionHandlerOptions,
    modifiers?: Array<SessionDescriptionHandlerModifier>
  ): Promise<void>;

  /**
   * Send DTMF via RTP (RFC 4733).
   * Returns true if DTMF send is successful, false otherwise.
   * @param tones - A string containing DTMF digits.
   * @param options - Options object to be used by sendDtmf.
   * @returns True if DTMF send is successful, false otherwise.
   */
  sendDtmf(tones: string, options?: unknown): boolean;
}

/**
 * Modifier for {@link SessionDescriptionHandler} offer/answer.
 * @public
 */
export interface SessionDescriptionHandlerModifier {
  (sessionDescription: RTCSessionDescriptionInit): Promise<RTCSessionDescriptionInit>;
}

/**
 * Options for {@link SessionDescriptionHandler} methods.
 * @remarks
 * These options are provided to various UserAgent methods (invite() for example)
 * and passed through on calls to getDescription() and setDescription().
 * @public
 */
export interface SessionDescriptionHandlerOptions {
  constraints?: object;
}

/**
 * Message body content and type.
 * @public
 */
export interface BodyAndContentType {
  /** Message body content. */
  body: string;
  /** Message body content type. */
  contentType: string;
}
