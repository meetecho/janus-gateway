import { IncomingNotifyRequest } from "../core/messages/methods/notify.js";
import { IncomingRequestMessage } from "../core/messages/incoming-request-message.js";
import { ResponseOptions } from "../core/messages/outgoing-response.js";

/**
 * A notification of an event (incoming NOTIFY).
 * @public
 */
export class Notification {
  /** @internal */
  public constructor(private incomingNotifyRequest: IncomingNotifyRequest) {}

  /** Incoming NOTIFY request message. */
  public get request(): IncomingRequestMessage {
    return this.incomingNotifyRequest.message;
  }

  /** Accept the request. */
  public accept(options?: ResponseOptions): Promise<void> {
    this.incomingNotifyRequest.accept(options);
    return Promise.resolve();
  }

  /** Reject the request. */
  public reject(options?: ResponseOptions): Promise<void> {
    this.incomingNotifyRequest.reject(options);
    return Promise.resolve();
  }
}
