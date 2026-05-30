import { URI } from "../../grammar/uri.js";
import { IncomingMessage } from "./incoming-message.js";

/**
 * Incoming request message.
 * @public
 */
export class IncomingRequestMessage extends IncomingMessage {
  public ruri: URI | undefined;

  constructor() {
    super();
  }
}
