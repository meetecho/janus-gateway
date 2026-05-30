import { Session } from "../../../api/session.js";
import { SessionDescriptionHandlerFactory as SessionDescriptionHandlerFactoryDefinition } from "../../../api/session-description-handler-factory.js";
import { SessionDescriptionHandler } from "./session-description-handler.js";
import { SessionDescriptionHandlerFactoryOptions } from "./session-description-handler-factory-options.js";

/**
 * Factory for {@link SessionDescriptionHandler}.
 * @public
 */
export interface SessionDescriptionHandlerFactory extends SessionDescriptionHandlerFactoryDefinition {
  /**
   * SessionDescriptionHandler factory function.
   * @remarks
   * The `options` are provided as part of the UserAgent configuration
   * and passed through on every call to SessionDescriptionHandlerFactory's constructor.
   */
  (session: Session, options?: SessionDescriptionHandlerFactoryOptions): SessionDescriptionHandler;
}
