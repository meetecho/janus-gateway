import { OutgoingSubscribeRequest, OutgoingSubscribeRequestDelegate } from "../messages/methods/subscribe.js";
import { RequestOptions } from "../messages/outgoing-request.js";
import { SubscriptionDelegate } from "./subscription-delegate.js";

/**
 * Subscription.
 * @remarks
 * https://tools.ietf.org/html/rfc6665
 * @public
 */
export interface Subscription {
  /** Subscription delegate. */
  delegate: SubscriptionDelegate | undefined;
  /** The subscription id. */
  readonly id: string;
  /** Subscription expires. Number of seconds until the subscription expires. */
  readonly subscriptionExpires: number;
  /** Subscription state. */
  readonly subscriptionState: SubscriptionState;
  /** If true, refresh subscription prior to expiration. Default is false. */
  autoRefresh: boolean;

  /**
   * Destroy subscription.
   */
  dispose(): void;

  /**
   * Send re-SUBSCRIBE request.
   * Refreshing a subscription and unsubscribing.
   * https://tools.ietf.org/html/rfc6665#section-4.1.2.2
   * @param delegate - Request delegate.
   * @param options - Options bucket
   */
  subscribe(delegate?: OutgoingSubscribeRequestDelegate, options?: RequestOptions): OutgoingSubscribeRequest;

  /**
   * 4.1.2.2.  Refreshing of Subscriptions
   * https://tools.ietf.org/html/rfc6665#section-4.1.2.2
   */
  refresh(): OutgoingSubscribeRequest;

  /**
   * 4.1.2.3.  Unsubscribing
   * https://tools.ietf.org/html/rfc6665#section-4.1.2.3
   */
  unsubscribe(): OutgoingSubscribeRequest;
}

/**
 * Subscription state.
 * @remarks
 * https://tools.ietf.org/html/rfc6665#section-4.1.2
 * @public
 */
export enum SubscriptionState {
  Initial = "Initial",
  NotifyWait = "NotifyWait",
  Pending = "Pending",
  Active = "Active",
  Terminated = "Terminated"
}
