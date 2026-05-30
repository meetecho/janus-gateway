import { OutgoingRequestDelegate, RequestOptions } from "../core/messages/outgoing-request.js";

/**
 * Options for {@link Session.message}.
 * @public
 */
export interface SessionMessageOptions {
  /** See `core` API. */
  requestDelegate?: OutgoingRequestDelegate;
  /** See `core` API. */
  requestOptions?: RequestOptions;
}
