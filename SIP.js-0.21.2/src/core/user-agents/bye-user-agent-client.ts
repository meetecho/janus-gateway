import { SessionDialog } from "../dialogs/session-dialog.js";
import { C } from "../messages/methods/constants.js";
import { OutgoingByeRequest } from "../messages/methods/bye.js";
import { OutgoingRequestDelegate, RequestOptions } from "../messages/outgoing-request.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentClient } from "./user-agent-client.js";

/**
 * BYE UAC.
 * @public
 */
export class ByeUserAgentClient extends UserAgentClient implements OutgoingByeRequest {
  constructor(dialog: SessionDialog, delegate?: OutgoingRequestDelegate, options?: RequestOptions) {
    const message = dialog.createOutgoingRequestMessage(C.BYE, options);
    super(NonInviteClientTransaction, dialog.userAgentCore, message, delegate);
    dialog.dispose();
  }
}
