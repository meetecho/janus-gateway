import { OutgoingRequestDelegate, RequestOptions } from "../core/messages/outgoing-request.js";

/**
 * Options for {@link Session.bye}.
 * @public
 */
export interface SessionByeOptions {
  /** See `core` API. */
  requestDelegate?: OutgoingRequestDelegate;
  /** See `core` API. */
  requestOptions?: RequestOptions;
}
