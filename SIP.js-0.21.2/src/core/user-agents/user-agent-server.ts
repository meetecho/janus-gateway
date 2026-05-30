import { TransactionStateError } from "../exceptions/transaction-state-error.js";
import { URI } from "../../grammar/uri.js";
import { Logger } from "../log/logger.js";
import { LoggerFactory } from "../log/logger-factory.js";
import { IncomingRequestDelegate } from "../messages/incoming-request.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { IncomingRequest } from "../messages/incoming-request.js";
import { constructOutgoingResponse, OutgoingResponse, ResponseOptions } from "../messages/outgoing-response.js";
import { newTag } from "../messages/utils.js";
import { InviteServerTransaction } from "../transactions/invite-server-transaction.js";
import { NonInviteServerTransaction } from "../transactions/non-invite-server-transaction.js";
import { ServerTransaction } from "../transactions/server-transaction.js";
import { ServerTransactionUser } from "../transactions/transaction-user.js";
import { TransactionState } from "../transactions/transaction-state.js";
import { Transport } from "../transport.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";

type ServerTransactionConstructor = new (
  message: IncomingRequestMessage,
  transport: Transport,
  user: ServerTransactionUser
) => ServerTransaction;

/**
 * User Agent Server (UAS).
 * @remarks
 * A user agent server is a logical entity
 * that generates a response to a SIP request.  The response
 * accepts, rejects, or redirects the request.  This role lasts
 * only for the duration of that transaction.  In other words, if
 * a piece of software responds to a request, it acts as a UAS for
 * the duration of that transaction.  If it generates a request
 * later, it assumes the role of a user agent client for the
 * processing of that transaction.
 * https://tools.ietf.org/html/rfc3261#section-6
 * @public
 */
export class UserAgentServer implements IncomingRequest {
  protected logger: Logger;
  protected toTag: string;

  private _transaction: ServerTransaction | undefined;

  constructor(
    private transactionConstructor: ServerTransactionConstructor,
    protected core: UserAgentCore,
    public message: IncomingRequestMessage,
    public delegate?: IncomingRequestDelegate
  ) {
    this.logger = this.loggerFactory.getLogger("sip.user-agent-server");
    this.toTag = message.toTag ? message.toTag : newTag();
    this.init();
  }

  public dispose(): void {
    this.transaction.dispose();
  }

  get loggerFactory(): LoggerFactory {
    return this.core.loggerFactory;
  }

  /** The transaction associated with this request. */
  get transaction(): ServerTransaction {
    if (!this._transaction) {
      throw new Error("Transaction undefined.");
    }
    return this._transaction;
  }

  public accept(options: ResponseOptions = { statusCode: 200 }): OutgoingResponse {
    if (!this.acceptable) {
      throw new TransactionStateError(`${this.message.method} not acceptable in state ${this.transaction.state}.`);
    }
    const statusCode = options.statusCode;
    if (statusCode < 200 || statusCode > 299) {
      throw new TypeError(`Invalid statusCode: ${statusCode}`);
    }
    const response = this.reply(options);
    return response;
  }

  public progress(options: ResponseOptions = { statusCode: 180 }): OutgoingResponse {
    if (!this.progressable) {
      throw new TransactionStateError(`${this.message.method} not progressable in state ${this.transaction.state}.`);
    }
    const statusCode = options.statusCode;
    if (statusCode < 101 || statusCode > 199) {
      throw new TypeError(`Invalid statusCode: ${statusCode}`);
    }
    const response = this.reply(options);
    return response;
  }

  public redirect(contacts: Array<URI>, options: ResponseOptions = { statusCode: 302 }): OutgoingResponse {
    if (!this.redirectable) {
      throw new TransactionStateError(`${this.message.method} not redirectable in state ${this.transaction.state}.`);
    }
    const statusCode = options.statusCode;
    if (statusCode < 300 || statusCode > 399) {
      throw new TypeError(`Invalid statusCode: ${statusCode}`);
    }
    const contactHeaders = new Array<string>();
    contacts.forEach((contact) => contactHeaders.push(`Contact: ${contact.toString()}`));
    options.extraHeaders = (options.extraHeaders || []).concat(contactHeaders);
    const response = this.reply(options);
    return response;
  }

  public reject(options: ResponseOptions = { statusCode: 480 }): OutgoingResponse {
    if (!this.rejectable) {
      throw new TransactionStateError(`${this.message.method} not rejectable in state ${this.transaction.state}.`);
    }
    const statusCode = options.statusCode;
    if (statusCode < 400 || statusCode > 699) {
      throw new TypeError(`Invalid statusCode: ${statusCode}`);
    }
    const response = this.reply(options);
    return response;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public trying(options?: ResponseOptions): OutgoingResponse {
    if (!this.tryingable) {
      throw new TransactionStateError(`${this.message.method} not tryingable in state ${this.transaction.state}.`);
    }
    const response = this.reply({ statusCode: 100 });
    return response;
  }

  /**
   * If the UAS did not find a matching transaction for the CANCEL
   * according to the procedure above, it SHOULD respond to the CANCEL
   * with a 481 (Call Leg/Transaction Does Not Exist).  If the transaction
   * for the original request still exists, the behavior of the UAS on
   * receiving a CANCEL request depends on whether it has already sent a
   * final response for the original request.  If it has, the CANCEL
   * request has no effect on the processing of the original request, no
   * effect on any session state, and no effect on the responses generated
   * for the original request.  If the UAS has not issued a final response
   * for the original request, its behavior depends on the method of the
   * original request.  If the original request was an INVITE, the UAS
   * SHOULD immediately respond to the INVITE with a 487 (Request
   * Terminated).  A CANCEL request has no impact on the processing of
   * transactions with any other method defined in this specification.
   * https://tools.ietf.org/html/rfc3261#section-9.2
   * @param request - Incoming CANCEL request.
   */
  public receiveCancel(message: IncomingRequestMessage): void {
    // Note: Currently CANCEL is being handled as a special case.
    // No UAS is created to handle the CANCEL and the response to
    // it CANCEL is being handled statelessly by the user agent core.
    // As such, there is currently no way to externally impact the
    // response to the a CANCEL request.
    if (this.delegate && this.delegate.onCancel) {
      this.delegate.onCancel(message);
    }
  }

  protected get acceptable(): boolean {
    if (this.transaction instanceof InviteServerTransaction) {
      return (
        this.transaction.state === TransactionState.Proceeding || this.transaction.state === TransactionState.Accepted
      );
    }
    if (this.transaction instanceof NonInviteServerTransaction) {
      return (
        this.transaction.state === TransactionState.Trying || this.transaction.state === TransactionState.Proceeding
      );
    }
    throw new Error("Unknown transaction type.");
  }

  protected get progressable(): boolean {
    if (this.transaction instanceof InviteServerTransaction) {
      return this.transaction.state === TransactionState.Proceeding;
    }
    if (this.transaction instanceof NonInviteServerTransaction) {
      return false; // https://tools.ietf.org/html/rfc4320#section-4.1
    }
    throw new Error("Unknown transaction type.");
  }

  protected get redirectable(): boolean {
    if (this.transaction instanceof InviteServerTransaction) {
      return this.transaction.state === TransactionState.Proceeding;
    }
    if (this.transaction instanceof NonInviteServerTransaction) {
      return (
        this.transaction.state === TransactionState.Trying || this.transaction.state === TransactionState.Proceeding
      );
    }
    throw new Error("Unknown transaction type.");
  }

  protected get rejectable(): boolean {
    if (this.transaction instanceof InviteServerTransaction) {
      return this.transaction.state === TransactionState.Proceeding;
    }
    if (this.transaction instanceof NonInviteServerTransaction) {
      return (
        this.transaction.state === TransactionState.Trying || this.transaction.state === TransactionState.Proceeding
      );
    }
    throw new Error("Unknown transaction type.");
  }

  protected get tryingable(): boolean {
    if (this.transaction instanceof InviteServerTransaction) {
      return this.transaction.state === TransactionState.Proceeding;
    }
    if (this.transaction instanceof NonInviteServerTransaction) {
      return this.transaction.state === TransactionState.Trying;
    }
    throw new Error("Unknown transaction type.");
  }

  /**
   * When a UAS wishes to construct a response to a request, it follows
   * the general procedures detailed in the following subsections.
   * Additional behaviors specific to the response code in question, which
   * are not detailed in this section, may also be required.
   *
   * Once all procedures associated with the creation of a response have
   * been completed, the UAS hands the response back to the server
   * transaction from which it received the request.
   * https://tools.ietf.org/html/rfc3261#section-8.2.6
   * @param statusCode - Status code to reply with.
   * @param options - Reply options bucket.
   */
  private reply(options: ResponseOptions): OutgoingResponse {
    if (!options.toTag && options.statusCode !== 100) {
      options.toTag = this.toTag;
    }
    options.userAgent = options.userAgent || this.core.configuration.userAgentHeaderFieldValue;
    options.supported = options.supported || this.core.configuration.supportedOptionTagsResponse;
    const response = constructOutgoingResponse(this.message, options);
    this.transaction.receiveResponse(options.statusCode, response.message);
    return response;
  }

  private init(): void {
    // We are the transaction user.
    const user: ServerTransactionUser = {
      loggerFactory: this.loggerFactory,
      onStateChange: (newState) => {
        if (newState === TransactionState.Terminated) {
          // Remove the terminated transaction from the core.
          // eslint-disable-next-line @typescript-eslint/no-use-before-define
          this.core.userAgentServers.delete(userAgentServerId);
          this.dispose();
        }
      },
      onTransportError: (error) => {
        this.logger.error(error.message);
        if (this.delegate && this.delegate.onTransportError) {
          this.delegate.onTransportError(error);
        } else {
          this.logger.error("User agent server response transport error.");
        }
      }
    };
    // Create a new transaction with us as the user.
    const transaction = new this.transactionConstructor(this.message, this.core.transport, user);
    this._transaction = transaction;
    // Add the new transaction to the core.
    const userAgentServerId = transaction.id;
    this.core.userAgentServers.set(transaction.id, this);
  }
}
