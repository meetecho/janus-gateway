import { SessionDialog } from "../dialogs/session-dialog.js";
import { IncomingReferRequest } from "../messages/methods/refer.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";
import { UserAgentServer } from "./user-agent-server.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function instanceOfSessionDialog(object: any): object is SessionDialog {
  return object.userAgentCore !== undefined;
}

/**
 * REFER UAS.
 * @public
 */
export class ReferUserAgentServer extends UserAgentServer implements IncomingReferRequest {
  /**
   * REFER UAS constructor.
   * @param dialogOrCore - Dialog for in dialog REFER, UserAgentCore for out of dialog REFER.
   * @param message - Incoming REFER request message.
   */
  constructor(
    dialogOrCore: SessionDialog | UserAgentCore,
    message: IncomingRequestMessage,
    delegate?: IncomingRequestDelegate
  ) {
    const userAgentCore = instanceOfSessionDialog(dialogOrCore) ? dialogOrCore.userAgentCore : dialogOrCore;
    super(NonInviteServerTransaction, userAgentCore, message, delegate);
  }
}
