import { OutgoingMessageRequest } from "../messages/methods/message.js";
import { OutgoingRequestDelegate } from "../messages/outgoing-request.js";
import { OutgoingRequestMessage } from "../messages/outgoing-request-message.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";
import { UserAgentClient } from "./user-agent-client.js";

/**
 * MESSAGE UAC.
 * @public
 */
export class MessageUserAgentClient extends UserAgentClient implements OutgoingMessageRequest {
  constructor(core: UserAgentCore, message: OutgoingRequestMessage, delegate?: OutgoingRequestDelegate) {
    super(NonInviteClientTransaction, core, message, delegate);
  }
}
