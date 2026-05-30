import { IncomingInfoRequest } from "../core/messages/methods/info.js";
import { IncomingRequestMessage } from "../core/messages/incoming-request-message.js";
import { ResponseOptions } from "../core/messages/outgoing-response.js";

/**
 * An exchange of information (incoming INFO).
 * @public
 */
export class Info {
  /** @internal */
  public constructor(private incomingInfoRequest: IncomingInfoRequest) {}

  /** Incoming MESSAGE request message. */
  public get request(): IncomingRequestMessage {
    return this.incomingInfoRequest.message;
  }

  /** Accept the request. */
  public accept(options?: ResponseOptions): Promise<void> {
    this.incomingInfoRequest.accept(options);
    return Promise.resolve();
  }

  /** Reject the request. */
  public reject(options?: ResponseOptions): Promise<void> {
    this.incomingInfoRequest.reject(options);
    return Promise.resolve();
  }
}
