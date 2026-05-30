import { Session } from "../../session/session.js";
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest, OutgoingRequestDelegate, RequestOptions } from "../outgoing-request.js";
import { OutgoingResponse, ResponseOptions } from "../outgoing-response.js";
import { OutgoingAckRequest } from "./ack.js";
import { OutgoingPrackRequest } from "./prack.js";

////////////////////
// Incoming INVITE
//

/**
 * Incoming INVITE request.
 * @public
 */
export interface IncomingInviteRequest extends IncomingRequest {
  /**
   * Send a 2xx positive final response to this request. Defaults to 200.
   * @param options - Response options bucket.
   * @returns Outgoing response and a confirmed Session.
   */
  accept(options?: ResponseOptions): OutgoingResponseWithSession;

  /**
   * Send a 1xx provisional response to this request. Defaults to 180. Excludes 100.
   * @param options - Response options bucket.
   * @returns Outgoing response and an early Session.
   */
  progress(options?: ResponseOptions): OutgoingResponseWithSession;
}

/**
 * Outgoing INVITE response with the associated {@link Session}.
 * @public
 */
export interface OutgoingResponseWithSession extends OutgoingResponse {
  /**
   * Session associated with incoming request acceptance, or
   * Session associated with incoming request progress (if an out of dialog request, an early dialog).
   */
  readonly session: Session;
}

////////////////////
// Outgoing INVITE
//

/**
 * Outgoing INVITE request.
 * @public
 */
export interface OutgoingInviteRequest extends OutgoingRequest {
  /** Delegate providing custom handling of this outgoing INVITE request. */
  delegate?: OutgoingInviteRequestDelegate;
}

/**
 * Delegate providing custom handling of outgoing INVITE requests.
 * @public
 */
export interface OutgoingInviteRequestDelegate extends OutgoingRequestDelegate {
  /**
   * Received a 2xx positive final response to this request.
   * @param response - Incoming response (including a confirmed Session).
   */
  onAccept?(response: AckableIncomingResponseWithSession): void;

  /**
   * Received a 1xx provisional response to this request. Excluding 100 responses.
   * @param response - Incoming response (including an early Session).
   */
  onProgress?(response: PrackableIncomingResponseWithSession): void;
}

/**
 * Incoming INVITE response received when request is accepted.
 * @public
 */
export interface AckableIncomingResponseWithSession extends IncomingResponse {
  /** Session associated with outgoing request acceptance. */
  readonly session: Session;

  /**
   * Send an ACK to acknowledge this response.
   * @param options - Request options bucket.
   */
  ack(options?: RequestOptions): OutgoingAckRequest;
}

/**
 * Incoming INVITE response received when request is progressed.
 * @public
 */
export interface PrackableIncomingResponseWithSession extends IncomingResponse {
  /** Session associated with outgoing request progress. If out of dialog request, an early dialog. */
  readonly session: Session;

  /**
   * Send an PRACK to acknowledge this response.
   * @param options - Request options bucket.
   */
  prack(options?: RequestOptions): OutgoingPrackRequest;
}
