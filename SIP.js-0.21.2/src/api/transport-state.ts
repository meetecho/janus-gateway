/**
 * {@link Transport} state.
 *
 * @remarks
 * The {@link Transport} behaves in a deterministic manner according to the following
 * Finite State Machine (FSM).
 * ```txt
 *                    ______________________________
 *                   |    ____________              |
 * Transport         v   v            |             |
 * Constructed -> Disconnected -> Connecting -> Connected -> Disconnecting
 *                     ^            ^    |_____________________^  |  |
 *                     |            |_____________________________|  |
 *                     |_____________________________________________|
 * ```
 * @public
 */
export enum TransportState {
  /**
   * The `connect()` method was called.
   */
  Connecting = "Connecting",
  /**
   * The `connect()` method resolved.
   */
  Connected = "Connected",
  /**
   * The `disconnect()` method was called.
   */
  Disconnecting = "Disconnecting",
  /**
   * The `connect()` method was rejected, or
   * the `disconnect()` method completed, or
   * network connectivity was lost.
   */
  Disconnected = "Disconnected"
}
