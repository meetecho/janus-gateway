import { IncomingSubscribeRequest } from "../messages/methods/subscribe.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";
import { UserAgentServer } from "./user-agent-server.js";

/**
 * SUBSCRIBE UAS.
 * @public
 */
export class SubscribeUserAgentServer extends UserAgentServer implements IncomingSubscribeRequest {
  constructor(protected core: UserAgentCore, message: IncomingRequestMessage, delegate?: IncomingRequestDelegate) {
    super(NonInviteServerTransaction, core, message, delegate);
  }
}
