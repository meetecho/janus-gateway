import { URI } from "../grammar/uri.js";
import { Logger } from "../core/log/logger.js";
import { SessionDescriptionHandlerFactory } from "./session-description-handler-factory.js";
import { Transport } from "./transport.js";
import { UserAgentDelegate } from "./user-agent-delegate.js";

/**
 * Log level.
 * @public
 */
export type LogLevel = "debug" | "log" | "warn" | "error";

/**
 * Log connector function.
 * @public
 */
export type LogConnector = (level: LogLevel, category: string, label: string | undefined, content: string) => void;

/**
 * SIP extension support level.
 * @public
 */
export enum SIPExtension {
  Required = "Required",
  Supported = "Supported",
  Unsupported = "Unsupported"
}

/**
 * Options for {@link UserAgent} constructor.
 * @public
 */
export interface UserAgentOptions {
  /**
   * If `true`, the user agent will accept out of dialog NOTIFY.
   * @remarks
   * RFC 6665 obsoletes the use of out of dialog NOTIFY from RFC 3265.
   * @defaultValue `false`
   */
  allowLegacyNotifications?: boolean;

  /**
   * Authorization ha1.
   * @defaultValue `""`
   */
  authorizationHa1?: string;

  /**
   * Authorization password.
   * @defaultValue `""`
   */
  authorizationPassword?: string;

  /**
   * Authorization username.
   * @defaultValue `""`
   */
  authorizationUsername?: string;

  /**
   * The user portion of user agent's contact URI.
   * @remarks
   * If not specifed a random string will be generated and utilized as the user portion of the contact URI.
   * @defaultValue `""`
   */
  contactName?: string;

  /**
   * The URI parameters of the user agent's contact URI.
   * @defaultValue `{ transport: "ws" }`
   */
  contactParams?: { [name: string]: string };

  /**
   * Delegate for {@link UserAgent}.
   * @defaultValue `{}`
   */
  delegate?: UserAgentDelegate;

  /**
   * The display name associated with the user agent.
   * @remarks
   * Descriptive name to be shown to the called party when calling or sending IM messages
   * (the display name portion of the From header).
   * It must NOT be enclosed between double quotes even if the given name contains multi-byte symbols
   * (SIPjs will always enclose the `displayName` value between double quotes).
   * @defaultValue `""`
   */
  displayName?: string;

  /**
   * Force adding rport to Via header.
   * @defaultValue `false`
   */
  forceRport?: boolean;

  /**
   * If `true`, the `stop()` method will attempt to gracefully end all dialogs and registrations before disconnecting.
   * Otherwise `stop()` will transition immediately abandoning all dialogs and registrations.
   * @defaultValue `true`
   */
  gracefulShutdown?: boolean;

  /**
   * Hack
   * @deprecated TBD
   */
  hackIpInContact?: boolean | string;

  /**
   * Hack
   * @deprecated TBD
   */
  hackAllowUnregisteredOptionTags?: boolean;

  /**
   * Hack
   * @deprecated TBD
   */
  hackViaTcp?: boolean;

  /**
   * UUID to provide with "+sip.instance" Contact header parameter.
   * @defaultValue A randomly generated uuid
   */
  instanceId?: string;

  /**
   * Add "+sip.instance" Contact header parameter to all requests.
   * @defaultValue `false`
   */
  instanceIdAlwaysAdded?: boolean;

  /**
   * Indicates whether log messages should be written to the browser console.
   * @defaultValue `true`
   */
  logBuiltinEnabled?: boolean;

  /**
   * If true, constructor logs the user agent configuration.
   * @defaultValue `true`
   */
  logConfiguration?: boolean;

  /**
   * A function which will be called every time a log is generated.
   * @defaultValue A noop
   */
  logConnector?: LogConnector;

  /**
   * Indicates the verbosity level of the log messages.
   * @defaultValue `"log"`
   */
  logLevel?: LogLevel;

  /**
   * Number of seconds after which an incoming call is rejected if not answered.
   * @defaultValue 60
   */
  noAnswerTimeout?: number;

  /**
   * Adds a Route header(s) to outgoing requests.
   * @defaultValue `[]`
   */
  preloadedRouteSet?: Array<string>;

  /**
   * @deprecated
   * Maximum number of times to attempt to reconnect when the transport connection drops.
   * @defaultValue 0
   */
  reconnectionAttempts?: number;

  /**
   * @deprecated
   * Seconds to wait between reconnection attempts when the transport connection drops.
   * @defaultValue 4
   */
  reconnectionDelay?: number;

  /**
   * If true, a first provisional response after the 100 Trying will be sent automatically if UAC does not
   * require reliable provisional responses.
   * @defaultValue `true`
   */
  sendInitialProvisionalResponse?: boolean;

  /**
   * A factory for generating `SessionDescriptionHandler` instances.
   * @remarks
   * The factory will be passed a `Session` object for the current session
   * and the `sessionDescriptionHandlerFactoryOptions` object.
   * @defaultValue `Web.SessionDescriptionHandler.defaultFactory`
   */
  sessionDescriptionHandlerFactory?: SessionDescriptionHandlerFactory;

  /**
   * Options to passed to `sessionDescriptionHandlerFactory`.
   * @remarks
   * See `Web.SessionDescriptionHandlerOptions` for details.
   * @defaultValue `{}`
   */
  sessionDescriptionHandlerFactoryOptions?: object;

  /**
   * Reliable provisional responses.
   * https://tools.ietf.org/html/rfc3262
   * @defaultValue `SIPExtension.Unsupported`
   */
  sipExtension100rel?: SIPExtension;

  /**
   * Replaces header.
   * https://tools.ietf.org/html/rfc3891
   * @defaultValue `SIPExtension.Unsupported`
   */
  sipExtensionReplaces?: SIPExtension;

  /**
   * Extra option tags to claim support for.
   * @remarks
   * Setting an extra option tag does not enable support for the associated extension
   * it simply adds the tag to the list of supported options.
   * See {@link UserAgentRegisteredOptionTags} for valid option tags.
   * @defaultValue `[]`
   */
  sipExtensionExtraSupported?: Array<string>;

  /**
   * An id uniquely identify this user agent instance.
   * @defaultValue
   * A random id generated by default.
   */
  sipjsId?: string;

  /**
   * A constructor function for the user agent's `Transport`.
   * @remarks
   * For more information about creating your own transport see `Transport`.
   * @defaultValue `WebSocketTransport`
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transportConstructor?: new (logger: Logger, options: any) => Transport;

  /**
   * An options bucket object passed to `transportConstructor` when instantiated.
   * @remarks
   * See WebSocket Transport Configuration Parameters for the full list of options for the default transport.
   * @defaultValue `{}`
   */
  transportOptions?: unknown;

  /**
   * SIP Addresses-of-Record URI associated with the user agent.
   * @remarks
   * This is a SIP address given to you by your provider.
   * If the user agent registers, it is the address-of-record which the user agent registers a contact for.
   * An address-of-record represents an identity of the user, generally a long-term identity,
   * and it does not have a dependency on any device; users can move between devices or even
   * be associated with multiple devices at one time while retaining the same address-of-record.
   * A simple URI, generally of the form `sip:egdar@example.com`, is used for an address-of-record.
   * @defaultValue
   * By default, URI is set to `sip:anonymous.X@anonymous.invalid`, where X is a random token generated for each UA.
   */
  uri?: URI;

  /**
   * User agent string used in the UserAgent header.
   * @defaultValue
   * A reasonable value is utilized.
   */
  userAgentString?: string;

  /**
   * Hostname to use in Via header.
   * @defaultValue
   * A random hostname in the .invalid domain.
   */
  viaHost?: string;
}

/**
 * SIP Option Tags
 * @remarks
 * http://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-4
 * @public
 */
export const UserAgentRegisteredOptionTags: { [option: string]: boolean } = {
  "100rel": true, // RFC 3262
  "199": true, // RFC 6228
  answermode: true, // RFC 5373
  "early-session": true, // RFC 3959
  eventlist: true, // RFC 4662
  explicitsub: true, // RFC-ietf-sipcore-refer-explicit-subscription-03
  "from-change": true, // RFC 4916
  "geolocation-http": true, // RFC 6442
  "geolocation-sip": true, // RFC 6442
  gin: true, // RFC 6140
  gruu: true, // RFC 5627
  histinfo: true, // RFC 7044
  ice: true, // RFC 5768
  join: true, // RFC 3911
  "multiple-refer": true, // RFC 5368
  norefersub: true, // RFC 4488
  nosub: true, // RFC-ietf-sipcore-refer-explicit-subscription-03
  outbound: true, // RFC 5626
  path: true, // RFC 3327
  policy: true, // RFC 6794
  precondition: true, // RFC 3312
  pref: true, // RFC 3840
  privacy: true, // RFC 3323
  "recipient-list-invite": true, // RFC 5366
  "recipient-list-message": true, // RFC 5365
  "recipient-list-subscribe": true, // RFC 5367
  replaces: true, // RFC 3891
  "resource-priority": true, // RFC 4412
  "sdp-anat": true, // RFC 4092
  "sec-agree": true, // RFC 3329
  tdialog: true, // RFC 4538
  timer: true, // RFC 4028
  uui: true // RFC 7433
};
