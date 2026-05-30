import { IncomingAckRequest } from "../core/messages/methods/ack.js";
import { IncomingRequestMessage } from "../core/messages/incoming-request-message.js";

/**
 * A request to confirm a {@link Session} (incoming ACK).
 * @public
 */
export class Ack {
  /** @internal */
  public constructor(private incomingAckRequest: IncomingAckRequest) {}

  /** Incoming ACK request message. */
  public get request(): IncomingRequestMessage {
    return this.incomingAckRequest.message;
  }
}
