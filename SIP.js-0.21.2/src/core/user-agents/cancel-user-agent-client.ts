import { OutgoingCancelRequest } from "../messages/methods/cancel.js";
import { OutgoingRequestDelegate } from "../messages/outgoing-request.js";
import { OutgoingRequestMessage } from "../messages/outgoing-request-message.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";
import { UserAgentClient } from "./user-agent-client.js";

/**
 * CANCEL UAC.
 * @public
 */
export class CancelUserAgentClient extends UserAgentClient implements OutgoingCancelRequest {
  constructor(core: UserAgentCore, message: OutgoingRequestMessage, delegate?: OutgoingRequestDelegate) {
    super(NonInviteClientTransaction, core, message, delegate);
  }
}
