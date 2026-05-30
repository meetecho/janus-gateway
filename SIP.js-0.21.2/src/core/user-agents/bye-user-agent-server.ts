import { SessionDialog } from "../dialogs/session-dialog.js";
import { IncomingByeRequest } from "../messages/methods/bye.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { UserAgentServer } from "./user-agent-server.js";

/**
 * BYE UAS.
 * @public
 */
export class ByeUserAgentServer extends UserAgentServer implements IncomingByeRequest {
  constructor(dialog: SessionDialog, message: IncomingRequestMessage, delegate?: IncomingRequestDelegate) {
    super(NonInviteServerTransaction, dialog.userAgentCore, message, delegate);
  }
}
