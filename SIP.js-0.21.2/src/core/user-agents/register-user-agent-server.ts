import { IncomingRegisterRequest } from "../messages/methods/register.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";
import { UserAgentServer } from "./user-agent-server.js";

/**
 * REGISTER UAS.
 * @public
 */
export class RegisterUserAgentServer extends UserAgentServer implements IncomingRegisterRequest {
  constructor(protected core: UserAgentCore, message: IncomingRequestMessage, delegate?: IncomingRequestDelegate) {
    super(NonInviteServerTransaction, core, message, delegate);
  }
}
