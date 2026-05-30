import { Exception } from "../../core/exceptions/exception.js";

/**
 * An exception indicating an outstanding prior request prevented execution.
 * @public
 */
export class RequestPendingError extends Exception {
  /** @internal */
  public constructor(message?: string) {
    super(message ? message : "Request pending.");
  }
}
