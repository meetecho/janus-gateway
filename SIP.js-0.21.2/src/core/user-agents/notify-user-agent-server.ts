import { Dialog } from "../dialogs/dialog.js";
import { IncomingNotifyRequest } from "../messages/methods/notify.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";
import { UserAgentServer } from "./user-agent-server.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function instanceOfDialog(object: any): object is Dialog {
  return object.userAgentCore !== undefined;
}

/**
 * NOTIFY UAS.
 * @public
 */
export class NotifyUserAgentServer extends UserAgentServer implements IncomingNotifyRequest {
  /**
   * NOTIFY UAS constructor.
   * @param dialogOrCore - Dialog for in dialog NOTIFY, UserAgentCore for out of dialog NOTIFY (deprecated).
   * @param message - Incoming NOTIFY request message.
   */
  constructor(
    dialogOrCore: Dialog | UserAgentCore,
    message: IncomingRequestMessage,
    delegate?: IncomingRequestDelegate
  ) {
    const userAgentCore = instanceOfDialog(dialogOrCore) ? dialogOrCore.userAgentCore : dialogOrCore;
    super(NonInviteServerTransaction, userAgentCore, message, delegate);
  }
}
