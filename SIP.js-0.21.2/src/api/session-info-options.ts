import { OutgoingRequestDelegate, RequestOptions } from "../core/messages/outgoing-request.js";

/**
 * Options for {@link Session.info}.
 * @public
 */
export interface SessionInfoOptions {
  /** See `core` API. */
  requestDelegate?: OutgoingRequestDelegate;
  /** See `core` API. */
  requestOptions?: RequestOptions;
}
