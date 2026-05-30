import { URI } from "../grammar/uri.js";

/**
 * Options for {@link Publisher} constructor.
 * @public
 */
export interface PublisherOptions {
  /** @deprecated TODO: provide alternative. */
  body?: string;
  /** @deprecated TODO: provide alternative. */
  contentType?: string;
  /**
   * Expire value for the published event.
   * @defaultValue 3600
   */
  expires?: number;
  /**
   * Array of extra headers added to the PUBLISH request message.
   */
  extraHeaders?: Array<string>;
  /** @deprecated TODO: provide alternative. */
  params?: {
    fromDisplayName?: string;
    fromTag?: string;
    fromUri?: URI;
    toDisplayName?: string;
    toUri?: URI;
  };
  /**
   * If set true, UA will gracefully unpublish for the event on UA close.
   * @defaultValue true
   */
  unpublishOnClose?: boolean;
}
