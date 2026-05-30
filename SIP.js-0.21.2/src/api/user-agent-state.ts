/**
 * {@link UserAgent} state.
 * @remarks
 * Valid state transitions:
 * ```
 * 1. "Started" --> "Stopped"
 * 2. "Stopped" --> "Started"
 * ```
 * @public
 */
export enum UserAgentState {
  Started = "Started",
  Stopped = "Stopped"
}
