/**
 * {@link Session} state.
 *
 * @remarks
 * The {@link Session} behaves in a deterministic manner according to the following
 * Finite State Machine (FSM).
 * ```txt
 *                   ___________________________________________________________
 *                  |  ____________________________________________             |
 *                  | |            ____________________________    |            |
 * Session          | |           |                            v   v            v
 * Constructed -> Initial -> Establishing -> Established -> Terminating -> Terminated
 *                                |               |___________________________^   ^
 *                                |_______________________________________________|
 * ```
 * @public
 */
export enum SessionState {
  /**
   * If `Inviter`, INVITE not sent yet.
   * If `Invitation`, received INVITE (but no final response sent yet).
   */
  Initial = "Initial",
  /**
   * If `Inviter`, sent INVITE and waiting for a final response.
   * If `Invitation`, received INVITE and attempting to send 200 final response (but has not sent it yet).
   */
  Establishing = "Establishing",
  /**
   * If `Inviter`, sent INVITE and received 200 final response and sent ACK.
   * If `Invitation`, received INVITE and sent 200 final response.
   */
  Established = "Established",
  /**
   * If `Inviter`, sent INVITE, sent CANCEL and now waiting for 487 final response to ACK (or 200 to ACK & BYE).
   * If `Invitation`, received INVITE, sent 200 final response and now waiting on ACK and upon receipt will attempt BYE
   * (as the protocol specification requires, before sending a BYE we must receive the ACK - so we are waiting).
   */
  Terminating = "Terminating",
  /**
   * If `Inviter`, sent INVITE and received non-200 final response (or sent/received BYE after receiving 200).
   * If `Invitation`, received INVITE and sent non-200 final response (or sent/received BYE after sending 200).
   */
  Terminated = "Terminated"
}
