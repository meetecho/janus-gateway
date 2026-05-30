import { Session } from "../../../api/session.js";
import { ManagedSessionFactory } from "./managed-session-factory.js";
import { ManagedSession } from "./managed-session.js";
import { SessionManager } from "./session-manager.js";

/**
 * Function which returns a ManagedSessionFactory.
 * @public
 */
export function defaultManagedSessionFactory(): ManagedSessionFactory {
  return (sessionManager: SessionManager, session: Session): ManagedSession => {
    return { session, held: false, muted: false };
  };
}
