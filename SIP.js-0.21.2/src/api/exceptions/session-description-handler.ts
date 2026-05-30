import { Exception } from "../../core/exceptions/exception.js";

/**
 * An exception indicating a session description handler error occured.
 * @public
 */
export class SessionDescriptionHandlerError extends Exception {
  public constructor(message?: string) {
    super(message ? message : "Unspecified session description handler error.");
  }
}
