import { SessionDescriptionHandler } from "./session-description-handler.js";
import { SessionDescriptionHandlerOptions } from "./session-description-handler-options.js";

/**
 * Interface of factory function which produces a MediaStream.
 * @public
 */
export type MediaStreamFactory = (
  constraints: MediaStreamConstraints,
  sessionDescriptionHandler: SessionDescriptionHandler,
  options?: SessionDescriptionHandlerOptions
) => Promise<MediaStream>;
