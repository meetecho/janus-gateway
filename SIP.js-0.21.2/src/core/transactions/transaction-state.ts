/**
 * Transaction state.
 * @public
 */
export enum TransactionState {
  Accepted = "Accepted",
  Calling = "Calling",
  Completed = "Completed",
  Confirmed = "Confirmed",
  Proceeding = "Proceeding",
  Terminated = "Terminated",
  Trying = "Trying"
}
