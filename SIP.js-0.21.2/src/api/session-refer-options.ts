import { OutgoingRequestDelegate, RequestOptions } from "../core/messages/outgoing-request.js";
import { Notification } from "./notification.js";

/**
 * Options for {@link Session.refer}.
 * @public
 */
export interface SessionReferOptions {
  /** Called upon receiving an incoming NOTIFY associated with a REFER. */
  onNotify?: (notification: Notification) => void;
  /** See `core` API. */
  requestDelegate?: OutgoingRequestDelegate;
  /** See `core` API. */
  requestOptions?: RequestOptions;
}
