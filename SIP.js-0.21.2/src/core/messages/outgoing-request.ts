import { Body } from "./body.js";
import { IncomingResponse } from "./incoming-response.js";
import { OutgoingRequestMessage } from "./outgoing-request-message.js";

/**
 * A SIP message sent from a local client to a remote server.
 * @remarks
 * For the purpose of invoking a particular operation.
 * https://tools.ietf.org/html/rfc3261#section-7.1
 * @public
 */
export interface OutgoingRequest {
  /** Delegate providing custom handling of this outgoing request. */
  delegate?: OutgoingRequestDelegate;

  /** The outgoing message. */
  readonly message: OutgoingRequestMessage;

  /**
   * Destroy request.
   */
  dispose(): void;

  /**
   * Sends a CANCEL message targeting this request to the UAS.
   * @param reason - Reason for canceling request.
   * @param options - Request options bucket.
   */
  cancel(reason?: string, options?: RequestOptions): void;
}

/**
 * Delegate providing custom handling of outgoing requests.
 * @public
 */
export interface OutgoingRequestDelegate {
  /**
   * Received a 2xx positive final response to this request.
   * @param response - Incoming response.
   */
  onAccept?(response: IncomingResponse): void;

  /**
   * Received a 1xx provisional response to this request. Excluding 100 responses.
   * @param response - Incoming response.
   */
  onProgress?(response: IncomingResponse): void;

  /**
   * Received a 3xx negative final response to this request.
   * @param response - Incoming response.
   */
  onRedirect?(response: IncomingResponse): void;

  /**
   * Received a 4xx, 5xx, or 6xx negative final response to this request.
   * @param response - Incoming response.
   */
  onReject?(response: IncomingResponse): void;

  /**
   * Received a 100 provisional response.
   * @param response - Incoming response.
   */
  onTrying?(response: IncomingResponse): void;
}

/**
 * Request options bucket.
 * @public
 */
export interface RequestOptions {
  /** Extra headers to include in the message. */
  extraHeaders?: Array<string>;
  /** Body to include in the message. */
  body?: Body;
}
