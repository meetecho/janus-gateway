import { SessionDialog } from "../dialogs/session-dialog.js";
import { C } from "../messages/methods/constants.js";
import { OutgoingPrackRequest } from "../messages/methods/prack.js";
import { OutgoingRequestDelegate, RequestOptions } from "../messages/outgoing-request.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentClient } from "./user-agent-client.js";

/**
 * PRACK UAC.
 * @public
 */
export class PrackUserAgentClient extends UserAgentClient implements OutgoingPrackRequest {
  constructor(dialog: SessionDialog, delegate?: OutgoingRequestDelegate, options?: RequestOptions) {
    const message = dialog.createOutgoingRequestMessage(C.PRACK, options);
    super(NonInviteClientTransaction, dialog.userAgentCore, message, delegate);
    dialog.signalingStateTransition(message);
  }
}
