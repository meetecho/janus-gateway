import { OutgoingRegisterRequest } from "../messages/methods/register.js";
import { OutgoingRequestDelegate } from "../messages/outgoing-request.js";
import { OutgoingRequestMessage } from "../messages/outgoing-request-message.js";
import { NonInviteClientTransaction } from "../transactions/non-invite-client-transaction.js";
import { UserAgentClient } from "./user-agent-client.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";

/**
 * REGISTER UAC.
 * @public
 */
export class RegisterUserAgentClient extends UserAgentClient implements OutgoingRegisterRequest {
  constructor(core: UserAgentCore, message: OutgoingRequestMessage, delegate?: OutgoingRequestDelegate) {
    super(NonInviteClientTransaction, core, message, delegate);
  }
}
