import { SessionDescriptionHandlerModifier, SessionDescriptionHandlerOptions } from "./session-description-handler.js";

/**
 * Options for {@link Invitation.progress}.
 * @public
 */
export interface InvitationProgressOptions {
  /**
   * Body
   */
  body?: string | { body: string; contentType: string };
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
  /**
   * Status code for response.
   */
  statusCode?: number;
  /**
   * Reason phrase for response.
   */
  reasonPhrase?: string;
  /**
   * Send reliable response.
   */
  rel100?: boolean;
}
