import { IncomingRequestMessage } from "../core/messages/incoming-request-message.js";

/**
 * A request to reject an {@link Invitation} (incoming CANCEL).
 * @public
 */
export class Cancel {
  /** @internal */
  public constructor(private incomingCancelRequest: IncomingRequestMessage) {}

  /** Incoming CANCEL request message. */
  public get request(): IncomingRequestMessage {
    return this.incomingCancelRequest;
  }
}
