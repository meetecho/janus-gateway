import { Session } from "../../../api/session.js";
import { SessionManagerMediaLocal, SessionManagerMediaRemote } from "./session-manager-options.js";

/**
 * An interface for managed the sessions.
 * @public
 */
export interface ManagedSession {
  held: boolean;
  muted: boolean;
  session: Session;
  mediaLocal?: SessionManagerMediaLocal;
  mediaRemote?: SessionManagerMediaRemote;
}
