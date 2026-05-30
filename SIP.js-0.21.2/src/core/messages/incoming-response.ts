import { IncomingResponseMessage } from "./incoming-response-message.js";

/**
 * A SIP message sent from a remote server to a local client.
 * @remarks
 * For indicating the status of a request sent from the client to the server.
 * https://tools.ietf.org/html/rfc3261#section-7.2
 * @public
 */
export interface IncomingResponse {
  /** The incoming message. */
  readonly message: IncomingResponseMessage;
}
