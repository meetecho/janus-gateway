/* eslint-disable @typescript-eslint/no-empty-interface */
import { TransportError } from "../exceptions/transport-error.js";
import { LoggerFactory } from "../log/logger-factory.js";
import { IncomingResponseMessage } from "../messages/incoming-response-message.js";
import { TransactionState } from "./transaction-state.js";

/**
 * Transaction User (TU).
 * @remarks
 * The layer of protocol processing that resides above the transaction layer.
 * Transaction users include the UAC core, UAS core, and proxy core.
 * https://tools.ietf.org/html/rfc3261#section-5
 * https://tools.ietf.org/html/rfc3261#section-6
 * @public
 */
export interface TransactionUser {
  /**
   * Logger factory.
   */
  loggerFactory: LoggerFactory;

  /**
   * Callback for notification of transaction state changes.
   *
   * Not called when transaction is constructed, so there is
   * no notification of entering the initial transaction state.
   * Otherwise, called once for each transaction state change.
   * State changes adhere to the following RFCs.
   * https://tools.ietf.org/html/rfc3261#section-17
   * https://tools.ietf.org/html/rfc6026
   */
  onStateChange?: (newState: TransactionState) => void;

  /**
   * Callback for notification of a transport error.
   *
   * If a fatal transport error is reported by the transport layer
   * (generally, due to fatal ICMP errors in UDP or connection failures in
   * TCP), the condition MUST be treated as a 503 (Service Unavailable)
   * status code.
   * https://tools.ietf.org/html/rfc3261#section-8.1.3.1
   * https://tools.ietf.org/html/rfc3261#section-17.1.4
   * https://tools.ietf.org/html/rfc3261#section-17.2.4
   * https://tools.ietf.org/html/rfc6026
   */
  onTransportError?: (error: TransportError) => void;
}

/**
 * UAC Core Transaction User.
 * @public
 */
export interface ClientTransactionUser extends TransactionUser {
  /**
   * Callback for request timeout error.
   *
   * When a timeout error is received from the transaction layer, it MUST be
   * treated as if a 408 (Request Timeout) status code has been received.
   * https://tools.ietf.org/html/rfc3261#section-8.1.3.1
   * TU MUST be informed of a timeout.
   * https://tools.ietf.org/html/rfc3261#section-17.1.2.2
   */
  onRequestTimeout?: () => void;

  /**
   * Callback for delegation of valid response handling.
   *
   * Valid responses are passed up to the TU from the client transaction.
   * https://tools.ietf.org/html/rfc3261#section-17.1
   */
  receiveResponse?: (response: IncomingResponseMessage) => void;
}

/**
 * UAS Core Transaction User.
 * @public
 */
export interface ServerTransactionUser extends TransactionUser {
  /**
   * For completeness. Same as `TransactionUser` at this point.
   */
}
