import { SessionDescriptionHandlerModifier, SessionDescriptionHandlerOptions } from "./session-description-handler.js";

/**
 * Options for {@link Invitation.accept}.
 * @public
 */
export interface InvitationAcceptOptions {
  /**
   * Array of extra headers added to the response.
   */
  extraHeaders?: Array<string>;
  /**
   * Modifiers to pass to SessionDescriptionHandler during the initial INVITE transaction.
   */
  sessionDescriptionHandlerModifiers?: Array<SessionDescriptionHandlerModifier>;
  /**
   * Options to pass to SessionDescriptionHandler during the initial INVITE transaction.
   */
  sessionDescriptionHandlerOptions?: SessionDescriptionHandlerOptions;
}
