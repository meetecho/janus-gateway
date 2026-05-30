import { OutgoingRequestDelegate, RequestOptions } from "../core/messages/outgoing-request.js";

/**
 * Options for {@link Messager.message}.
 * @public
 */
export interface MessagerMessageOptions {
  /** See `core` API. */
  requestDelegate?: OutgoingRequestDelegate;
  /** See `core` API. */
  requestOptions?: RequestOptions;
}
