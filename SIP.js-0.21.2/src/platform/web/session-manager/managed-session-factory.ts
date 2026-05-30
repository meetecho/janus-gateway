import { Session } from "../../../api/session.js";
import { ManagedSession } from "./managed-session.js";
import { SessionManager } from "./session-manager.js";

/**
 * Factory for {@link ManagedSession}.
 * @public
 */
export interface ManagedSessionFactory {
  /**
   * SessionDescriptionHandler factory function.
   * @remarks
   * The `options` are provided as part of the UserAgent configuration
   * and passed through on every call to SessionDescriptionHandlerFactory's constructor.
   */
  (sessionManager: SessionManager, session: Session): ManagedSession;
}
