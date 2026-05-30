import { SessionDialog } from "../dialogs/session-dialog.js";
import { C } from "../messages/methods/constants.js";
import { OutgoingNotifyRequest } from "../messages/methods/notify.js";
import { OutgoingRequestDelegate, RequestOptions } from "../messages/outgoing-request.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentClient } from "./user-agent-client.js";

/**
 * NOTIFY UAS.
 * @public
 */
export class NotifyUserAgentClient extends UserAgentClient implements OutgoingNotifyRequest {
  constructor(dialog: SessionDialog, delegate?: OutgoingRequestDelegate, options?: RequestOptions) {
    const message = dialog.createOutgoingRequestMessage(C.NOTIFY, options);
    super(NonInviteClientTransaction, dialog.userAgentCore, message, delegate);
  }
}
