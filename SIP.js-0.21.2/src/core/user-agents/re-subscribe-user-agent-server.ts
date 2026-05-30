import { Dialog } from "../dialogs/dialog.js";
import { IncomingSubscribeRequest } from "../messages/methods/subscribe.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { UserAgentServer } from "./user-agent-server.js";

/**
 * Re-SUBSCRIBE UAS.
 * @public
 */
export class ReSubscribeUserAgentServer extends UserAgentServer implements IncomingSubscribeRequest {
  constructor(dialog: Dialog, message: IncomingRequestMessage, delegate?: IncomingRequestDelegate) {
    super(NonInviteServerTransaction, dialog.userAgentCore, message, delegate);
  }
}
