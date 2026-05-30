import { IncomingMessageRequest } from "../core/messages/methods/message.js";
import { IncomingRequestMessage } from "../core/messages/incoming-request-message.js";
import { ResponseOptions } from "../core/messages/outgoing-response.js";

/**
 * A received message (incoming MESSAGE).
 * @public
 */
export class Message {
  /** @internal */
  public constructor(private incomingMessageRequest: IncomingMessageRequest) {}

  /** Incoming MESSAGE request message. */
  public get request(): IncomingRequestMessage {
    return this.incomingMessageRequest.message;
  }

  /** Accept the request. */
  public accept(options?: ResponseOptions): Promise<void> {
    this.incomingMessageRequest.accept(options);
    return Promise.resolve();
  }

  /** Reject the request. */
  public reject(options?: ResponseOptions): Promise<void> {
    this.incomingMessageRequest.reject(options);
    return Promise.resolve();
  }
}
