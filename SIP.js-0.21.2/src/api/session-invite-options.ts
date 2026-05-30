import { OutgoingRequestDelegate, RequestOptions } from "../core/messages/outgoing-request.js";
import { SessionDescriptionHandlerModifier, SessionDescriptionHandlerOptions } from "./session-description-handler.js";

/**
 * Options for {@link Session.invite}.
 * @public
 */
export interface SessionInviteOptions {
  /**
   * See `core` API.
   */
  requestDelegate?: OutgoingRequestDelegate;
  /**
   * See `core` API.
   */
  requestOptions?: RequestOptions;
  /**
   * Modifiers to pass to SessionDescriptionHandler during re-INVITE transaction.
   */
  sessionDescriptionHandlerModifiers?: Array<SessionDescriptionHandlerModifier>;
  /**
   * Options to pass to SessionDescriptionHandler during re-INVITE transaction.
   */
  sessionDescriptionHandlerOptions?: SessionDescriptionHandlerOptions;
  /**
   * If true, send INVITE without SDP. Default is false.
   */
  withoutSdp?: boolean;
}
