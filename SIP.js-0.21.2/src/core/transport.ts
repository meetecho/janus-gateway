/**
 * Transport layer interface expected by the user agent core.
 *
 * @remarks
 * The transport layer is responsible for the actual transmission of
 * requests and responses over network transports.  This includes
 * determination of the connection to use for a request or response in
 * the case of connection-oriented transports.
 * https://tools.ietf.org/html/rfc3261#section-18
 *
 * @public
 */
export interface Transport {
  /**
   * The transport protocol.
   *
   * @remarks
   * Formatted as defined for the Via header sent-protocol transport.
   * https://tools.ietf.org/html/rfc3261#section-20.42
   */
  readonly protocol: string;

  /**
   * Send a message.
   *
   * @remarks
   * Resolves once message is sent. Otherwise rejects with an Error.
   *
   * @param message - Message to send.
   */
  send(message: string): Promise<void>;
}
