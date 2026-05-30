import { SessionDialog } from "../dialogs/session-dialog.js";
import { C } from "../messages/methods/constants.js";
import { OutgoingInfoRequest } from "../messages/methods/info.js";
import { OutgoingRequestDelegate, RequestOptions } from "../messages/outgoing-request.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentClient } from "./user-agent-client.js";

/**
 * INFO UAC.
 * @public
 */
export class InfoUserAgentClient extends UserAgentClient implements OutgoingInfoRequest {
  constructor(dialog: SessionDialog, delegate?: OutgoingRequestDelegate, options?: RequestOptions) {
    const message = dialog.createOutgoingRequestMessage(C.INFO, options);
    super(NonInviteClientTransaction, dialog.userAgentCore, message, delegate);
  }
}
