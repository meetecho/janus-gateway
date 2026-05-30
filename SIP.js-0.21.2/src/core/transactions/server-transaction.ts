import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { Transport } from "../transport.js";
import { Transaction } from "./transaction.js";
import { TransactionState } from "./transaction-state.js";
import { ServerTransactionUser } from "./transaction-user.js";

/**
 * Server Transaction.
 * @remarks
 * The server transaction is responsible for the delivery of requests to
 * the TU and the reliable transmission of responses.  It accomplishes
 * this through a state machine.  Server transactions are created by the
 * core when a request is received, and transaction handling is desired
 * for that request (this is not always the case).
 * https://tools.ietf.org/html/rfc3261#section-17.2
 * @public
 */
export abstract class ServerTransaction extends Transaction {
  protected constructor(
    private _request: IncomingRequestMessage,
    transport: Transport,
    protected user: ServerTransactionUser,
    state: TransactionState,
    loggerCategory: string
  ) {
    super(transport, user, _request.viaBranch, state, loggerCategory);
  }

  /** The incoming request the transaction handling. */
  get request(): IncomingRequestMessage {
    return this._request;
  }

  /**
   * Receive incoming requests from the transport which match this transaction.
   * @param request - The incoming request.
   */
  public abstract receiveRequest(request: IncomingRequestMessage): void;

  /**
   * Receive outgoing responses to this request from the transaction user.
   * Responses will be delivered to the transport as necessary.
   * @param statusCode - Response status code.
   * @param response - Response.
   */
  public abstract receiveResponse(statusCode: number, response: string): void;
}
