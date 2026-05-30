import { SessionDialog } from "../dialogs/session-dialog.js";
import { IncomingPrackRequest } from "../messages/methods/prack.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { OutgoingResponse, ResponseOptions } from "../messages/outgoing-response.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { UserAgentServer } from "./user-agent-server.js";

/**
 * PRACK UAS.
 * @public
 */
export class PrackUserAgentServer extends UserAgentServer implements IncomingPrackRequest {
  private dialog: SessionDialog;

  constructor(dialog: SessionDialog, message: IncomingRequestMessage, delegate?: IncomingRequestDelegate) {
    super(NonInviteServerTransaction, dialog.userAgentCore, message, delegate);
    // Update dialog signaling state with offer/answer in body
    dialog.signalingStateTransition(message);
    this.dialog = dialog;
  }

  /**
   * Update the dialog signaling state on a 2xx response.
   * @param options - Options bucket.
   */
  public accept(options: ResponseOptions = { statusCode: 200 }): OutgoingResponse {
    if (options.body) {
      // Update dialog signaling state with offer/answer in body
      this.dialog.signalingStateTransition(options.body);
    }
    return super.accept(options);
  }
}
