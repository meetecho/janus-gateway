import { SessionDelegate } from "./session-delegate.js";
/**
 * Options for {@link Session} constructor.
 * @public
 */
export interface SessionOptions {
  delegate?: SessionDelegate;
}
