import { URI } from "../../grammar/uri.js";
import { SessionDialog } from "../dialogs/session-dialog.js";
import { IncomingInviteRequest, OutgoingResponseWithSession } from "../messages/methods/invite.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { OutgoingResponse, ResponseOptions } from "../messages/outgoing-response.js";
import { InviteServerTransaction } from "../transactions/invite-server-transaction.js";
import { UserAgentServer } from "./user-agent-server.js";

/**
 * Re-INVITE UAS.
 * @remarks
 * 14 Modifying an Existing Session
 * https://tools.ietf.org/html/rfc3261#section-14
 * 14.2 UAS Behavior
 * https://tools.ietf.org/html/rfc3261#section-14.2
 * @public
 */
export class ReInviteUserAgentServer extends UserAgentServer implements IncomingInviteRequest {
  private dialog: SessionDialog;

  constructor(dialog: SessionDialog, message: IncomingRequestMessage, delegate?: IncomingRequestDelegate) {
    super(InviteServerTransaction, dialog.userAgentCore, message, delegate);
    dialog.reinviteUserAgentServer = this;
    this.dialog = dialog;
  }

  /**
   * Update the dialog signaling state on a 2xx response.
   * @param options - Options bucket.
   */
  public accept(options: ResponseOptions = { statusCode: 200 }): OutgoingResponseWithSession {
    // FIXME: The next two lines SHOULD go away, but I suppose it's technically harmless...
    // These are here because some versions of SIP.js prior to 0.13.8 set the route set
    // of all in dialog ACKs based on the Record-Route headers in the associated 2xx
    // response. While this worked for dialog forming 2xx responses, it was technically
    // broken for re-INVITE ACKS as it only worked if the UAS populated the Record-Route
    // headers in the re-INVITE 2xx response (which is not required and a waste of bandwidth
    // as the should be ignored if present in re-INVITE ACKS) and the UAS populated
    // the Record-Route headers with the correct values (would be weird not too, but...).
    // Anyway, for now the technically useless Record-Route headers are being added
    // to maintain "backwards compatibility" with the older broken versions of SIP.js.
    options.extraHeaders = options.extraHeaders || [];
    options.extraHeaders = options.extraHeaders.concat(this.dialog.routeSet.map((route) => `Record-Route: ${route}`));

    // Send and return the response
    const response = super.accept(options);
    const session = this.dialog;
    const result: OutgoingResponseWithSession = { ...response, session };

    if (options.body) {
      // Update dialog signaling state with offer/answer in body
      this.dialog.signalingStateTransition(options.body);
    }

    // Update dialog
    this.dialog.reConfirm();

    return result;
  }

  /**
   * Update the dialog signaling state on a 1xx response.
   * @param options - Progress options bucket.
   */
  public progress(options: ResponseOptions = { statusCode: 180 }): OutgoingResponseWithSession {
    // Send and return the response
    const response = super.progress(options);
    const session = this.dialog;
    const result: OutgoingResponseWithSession = { ...response, session };

    // Update dialog signaling state
    if (options.body) {
      this.dialog.signalingStateTransition(options.body);
    }

    return result;
  }

  /**
   * TODO: Not Yet Supported
   * @param contacts - Contacts to redirect to.
   * @param options - Redirect options bucket.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public redirect(contacts: Array<URI>, options: ResponseOptions = { statusCode: 302 }): OutgoingResponse {
    this.dialog.signalingStateRollback();
    this.dialog.reinviteUserAgentServer = undefined; // ACK will be handled by transaction
    throw new Error("Unimplemented.");
  }

  /**
   * 3.1 Background on Re-INVITE Handling by UASs
   * An error response to a re-INVITE has the following semantics.  As
   * specified in Section 12.2.2 of RFC 3261 [RFC3261], if a re-INVITE is
   * rejected, no state changes are performed.
   * https://tools.ietf.org/html/rfc6141#section-3.1
   * @param options - Reject options bucket.
   */
  public reject(options: ResponseOptions = { statusCode: 488 }): OutgoingResponse {
    this.dialog.signalingStateRollback();
    this.dialog.reinviteUserAgentServer = undefined; // ACK will be handled by transaction
    return super.reject(options);
  }
}
