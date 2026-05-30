import { URI } from "../grammar/uri.js";

/**
 * Options for {@link Registerer} constructor.
 * @public
 */
export interface RegistererOptions {
  /** Registration expiration time in seconds. */
  expires?: number;

  /** Array of extra Contact header parameters. */
  extraContactHeaderParams?: Array<string>;

  /** Array of extra headers added to the REGISTER. */
  extraHeaders?: Array<string>;

  /**
   * UUID to provide with "+sip.instance" Contact parameter.
   * @defaultValue A randomly generated uuid
   * @deprecated Use UserAgentOptions.instanceId
   */
  instanceId?: string;

  /**
   * If true, constructor logs the registerer configuration.
   * @defaultValue `true`
   */
  logConfiguration?: boolean;

  /** @deprecated TODO: provide alternative. */
  params?: {
    fromDisplayName?: string;
    fromTag?: string;
    fromUri?: URI;
    toDisplayName?: string;
    toUri?: URI;
  };

  /**
   * Value to provide with "reg-id" Contact parameter.
   * @defaultValue 1
   */
  regId?: number;

  /**
   * The URI of the registrar to send the REGISTER requests.
   * @defaultValue domain portion of the user agent's uri
   */
  registrar?: URI;

  /**
   * Determines when a re-REGISTER request is sent. The value should be specified as a percentage of the expiration time (between 50 and 99).
   * @defaultValue 99
   */
  refreshFrequency?: number;
}
