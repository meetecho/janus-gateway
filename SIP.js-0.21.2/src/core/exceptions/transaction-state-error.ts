import { Exception } from "./exception.js";

/**
 * Indicates that the operation could not be completed given the current transaction state.
 * @public
 */
export class TransactionStateError extends Exception {
  constructor(message?: string) {
    super(message ? message : "Transaction state error.");
  }
}
