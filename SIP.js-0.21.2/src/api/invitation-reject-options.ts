/**
 * Options for {@link Invitation.reject}.
 * @public
 */
export interface InvitationRejectOptions {
  /**
   * Body
   */
  body?: string | { body: string; contentType: string };
  /**
   * Array of extra headers added to the response.
   */
  extraHeaders?: Array<string>;
  /**
   * Status code for response.
   */
  statusCode?: number;
  /**
   * Reason phrase for response.
   */
  reasonPhrase?: string;
}
