/* eslint-disable @typescript-eslint/no-empty-interface */
import { Subscription } from "../../subscription/subscription.js";
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest, OutgoingRequestDelegate } from "../outgoing-request.js";
import { IncomingNotifyRequest } from "./notify.js";

/**
 * Incoming SUBSCRIBE request.
 * @public
 */
export interface IncomingSubscribeRequest extends IncomingRequest {}

/**
 * Incoming SUBSCRIBE response.
 * @public
 */
export interface IncomingSubscribeResponse extends IncomingResponse {}

/**
 * Outgoing SUBSCRIBE request.
 * @public
 */
export interface OutgoingSubscribeRequest extends OutgoingRequest {
  /** Delegate providing custom handling of this outgoing SUBSCRIBE request. */
  delegate?: OutgoingSubscribeRequestDelegate;
  /** Stop waiting for an inital subscription creating NOTIFY. */
  waitNotifyStop(): void;
}

/**
 * Delegate providing custom handling of outgoing SUBSCRIBE requests.
 * @public
 */
export interface OutgoingSubscribeRequestDelegate extends OutgoingRequestDelegate {
  /**
   * Received the initial subscription creating NOTIFY in response to this request.
   * Called for out of dialog SUBSCRIBE requests only (not called for re-SUBSCRIBE requests).
   * @param request - Incoming NOTIFY request (including a Subscription).
   */
  onNotify?(request: IncomingRequestWithSubscription): void;

  /**
   * Timed out waiting to receive the initial subscription creating NOTIFY in response to this request.
   * Called for out of dialog SUBSCRIBE requests only (not called for re-SUBSCRIBE requests).
   */
  onNotifyTimeout?(): void;
}

/**
 * Incoming NOTIFY request with associated {@link Subscription}.
 * @public
 */
export interface IncomingRequestWithSubscription {
  /** The NOTIFY request which established the subscription. */
  readonly request: IncomingNotifyRequest;
  /** If subscription state is not "terminated", then the subscription. Otherwise undefined. */
  readonly subscription?: Subscription;
}
