import { URI } from "../../grammar/uri.js";
import { Body } from "../messages/body.js";
import { OutgoingByeRequest } from "../messages/methods/bye.js";
import { OutgoingInfoRequest } from "../messages/methods/info.js";
import { OutgoingInviteRequest, OutgoingInviteRequestDelegate } from "../messages/methods/invite.js";
import { OutgoingMessageRequest } from "../messages/methods/message.js";
import { OutgoingNotifyRequest } from "../messages/methods/notify.js";
import { OutgoingPrackRequest } from "../messages/methods/prack.js";
import { OutgoingReferRequest } from "../messages/methods/refer.js";
import { OutgoingRequestDelegate, RequestOptions } from "../messages/outgoing-request.js";
import { SessionDelegate } from "./session-delegate.js";

/**
 * Session.
 * @remarks
 * https://tools.ietf.org/html/rfc3261#section-13
 * @public
 */
export interface Session {
  /** Session delegate. */
  delegate: SessionDelegate | undefined;
  /** The session id. Equal to callId + localTag + remoteTag. */
  readonly id: string;
  /** Call Id. */
  readonly callId: string;
  /** Local Tag. */
  readonly localTag: string;
  /** Local URI. */
  readonly localURI: URI;
  /** Remote Tag. */
  readonly remoteTag: string;
  /** Remote Target. */
  readonly remoteTarget: URI;
  /** Remote URI. */
  readonly remoteURI: URI;
  /** Session state. */
  readonly sessionState: SessionState;
  /** Current state of the offer/answer exchange. */
  readonly signalingState: SignalingState;
  /** The current answer if signalingState is stable. Otherwise undefined. */
  readonly answer: Body | undefined;
  /** The current offer if signalingState is not initial or closed. Otherwise undefined. */
  readonly offer: Body | undefined;

  /**
   * Destroy session.
   */
  dispose(): void;

  /**
   * Send a BYE request.
   * Terminating a session.
   * https://tools.ietf.org/html/rfc3261#section-15
   * @param delegate - Request delegate.
   * @param options - Options bucket.
   */
  bye(delegate?: OutgoingRequestDelegate, options?: RequestOptions): OutgoingByeRequest;

  /**
   * Send an INFO request.
   * Exchange information during a session.
   * https://tools.ietf.org/html/rfc6086#section-4.2.1
   * @param delegate - Request delegate.
   * @param options - Options bucket.
   */
  info(delegate?: OutgoingRequestDelegate, options?: RequestOptions): OutgoingInfoRequest;

  /**
   * Send re-INVITE request.
   * Modifying a session.
   * https://tools.ietf.org/html/rfc3261#section-14.1
   * @param delegate - Request delegate.
   * @param options - Options bucket.
   */
  invite(delegate?: OutgoingInviteRequestDelegate, options?: RequestOptions): OutgoingInviteRequest;

  /**
   * Send MESSAGE request.
   * Deliver a message during a session.
   * https://tools.ietf.org/html/rfc3428#section-4
   * @param delegate - Request delegate.
   * @param options - Options bucket.
   */
  message(delegate?: OutgoingRequestDelegate, options?: RequestOptions): OutgoingMessageRequest;

  /**
   * Send NOTIFY request.
   * Inform referrer of transfer progress.
   * The use of this is limited to the implicit creation of subscription by REFER (historical).
   * Otherwise, notifiers MUST NOT create subscriptions except upon receipt of a SUBSCRIBE request.
   * https://tools.ietf.org/html/rfc3515#section-3.7
   * @param delegate - Request delegate.
   * @param options - Options bucket.
   */
  notify(delegate?: OutgoingRequestDelegate, options?: RequestOptions): OutgoingNotifyRequest;

  /**
   * Send PRACK request.
   * Acknowledge a reliable provisional response.
   * https://tools.ietf.org/html/rfc3262#section-4
   * @param delegate - Request delegate.
   * @param options - Options bucket.
   */
  prack(delegate?: OutgoingRequestDelegate, options?: RequestOptions): OutgoingPrackRequest;

  /**
   * Send REFER request.
   * Transfer a session.
   * https://tools.ietf.org/html/rfc3515#section-2.4.1
   * @param delegate - Request delegate.
   * @param options - Options bucket.
   */
  refer(delegate?: OutgoingRequestDelegate, options?: RequestOptions): OutgoingReferRequest;
}

/**
 * Session state.
 * @remarks
 * https://tools.ietf.org/html/rfc3261#section-13
 * @public
 */
export enum SessionState {
  Initial = "Initial",
  Early = "Early",
  AckWait = "AckWait",
  Confirmed = "Confirmed",
  Terminated = "Terminated"
}

/**
 * Offer/Answer state.
 * @remarks
 * ```txt
 *         Offer                Answer             RFC    Ini Est Early
 *  -------------------------------------------------------------------
 *  1. INVITE Req.          2xx INVITE Resp.     RFC 3261  Y   Y    N
 *  2. 2xx INVITE Resp.     ACK Req.             RFC 3261  Y   Y    N
 *  3. INVITE Req.          1xx-rel INVITE Resp. RFC 3262  Y   Y    N
 *  4. 1xx-rel INVITE Resp. PRACK Req.           RFC 3262  Y   Y    N
 *  5. PRACK Req.           200 PRACK Resp.      RFC 3262  N   Y    Y
 *  6. UPDATE Req.          2xx UPDATE Resp.     RFC 3311  N   Y    Y
 *
 *       Table 1: Summary of SIP Usage of the Offer/Answer Model
 * ```
 * https://tools.ietf.org/html/rfc6337#section-2.2
 * @public
 */
export enum SignalingState {
  Initial = "Initial", // Initial state
  HaveLocalOffer = "HaveLocalOffer", // Patterns 1, 3, 5, 6
  HaveRemoteOffer = "HaveRemoteOffer", // Patterns 2, 4
  Stable = "Stable",
  Closed = "Closed"
}
