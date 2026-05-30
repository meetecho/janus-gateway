import { IncomingNotifyRequest } from "../messages/methods/notify.js";
import { OutgoingSubscribeRequest } from "../messages/methods/subscribe.js";

/**
 * Subscription delegate.
 * @public
 */
export interface SubscriptionDelegate {
  /**
   * Receive NOTIFY request. This includes in dialog NOTIFY requests only.
   * Thus the first NOTIFY (the subscription creating NOTIFY) will not be provided.
   * https://tools.ietf.org/html/rfc6665#section-4.1.3
   * @param request - Incoming NOTIFY request.
   */
  onNotify?(request: IncomingNotifyRequest): void;

  /**
   * Sent a SUBSCRIBE request. This includes "auto refresh" in dialog SUBSCRIBE requests only.
   * Thus SUBSCRIBE requests triggered by calls to `refresh()` or `subscribe()` will not be provided.
   * Thus the first SUBSCRIBE (the subscription creating SUBSCRIBE) will not be provided.
   * @param request - Outgoing SUBSCRIBE request.
   */
  onRefresh?(request: OutgoingSubscribeRequest): void;

  /**
   * Subscription termination. This includes non-NOTIFY termination causes only.
   * Thus this will not be called if a NOTIFY is the cause of termination.
   * https://tools.ietf.org/html/rfc6665#section-4.4.1
   */
  onTerminated?(): void;
}
