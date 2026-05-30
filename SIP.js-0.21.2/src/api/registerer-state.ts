/**
 * {@link Registerer} state.
 * @remarks
 * The {@link Registerer} behaves in a deterministic manner according to the following
 * Finite State Machine (FSM).
 * ```txt
 *                   __________________________________________
 *                  |  __________________________              |
 * Registerer       | |                          v             v
 * Constructed -> Initial -> Registered -> Unregistered -> Terminated
 *                              |   ^____________|             ^
 *                              |______________________________|
 * ```
 * @public
 */
export enum RegistererState {
  Initial = "Initial",
  Registered = "Registered",
  Unregistered = "Unregistered",
  Terminated = "Terminated"
}
