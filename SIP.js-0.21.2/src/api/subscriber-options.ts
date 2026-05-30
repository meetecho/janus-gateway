import { SubscriptionOptions } from "./subscription-options.js";

/**
 * Options for {@link Subscriber} constructor.
 * @public
 */
export interface SubscriberOptions extends SubscriptionOptions {
  expires?: number;
  extraHeaders?: Array<string>;
  body?: string;
  contentType?: string;
}
