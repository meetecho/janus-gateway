import { SessionDialog } from "../dialogs/session-dialog.js";
import { C } from "../messages/methods/constants.js";
import { OutgoingReferRequest } from "../messages/methods/refer.js";
import { OutgoingRequestDelegate, RequestOptions } from "../messages/outgoing-request.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentClient } from "./user-agent-client.js";

/**
 * REFER UAC.
 * @public
 */
export class ReferUserAgentClient extends UserAgentClient implements OutgoingReferRequest {
  constructor(dialog: SessionDialog, delegate?: OutgoingRequestDelegate, options?: RequestOptions) {
    const message = dialog.createOutgoingRequestMessage(C.REFER, options);
    super(NonInviteClientTransaction, dialog.userAgentCore, message, delegate);
  }
}
