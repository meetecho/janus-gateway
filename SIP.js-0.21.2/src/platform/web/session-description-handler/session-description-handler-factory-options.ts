import { SessionDescriptionHandlerConfiguration } from "./session-description-handler-configuration.js";

/**
 * Options for SessionDescriptionHandlerFactory.
 * @remarks
 * The "options" are provided as part of the UserAgent configuration and passed through
 * on every call to SessionDescriptionHandlerFactory's constructor.
 * @public
 */
export type SessionDescriptionHandlerFactoryOptions = SessionDescriptionHandlerConfiguration;
