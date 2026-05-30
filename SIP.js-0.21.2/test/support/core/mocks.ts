import { SIPExtension, UserAgent, UserAgentRegisteredOptionTags } from "../../../lib/api/index.js";
import {
  DigestAuthentication,
  IncomingAckRequest,
  IncomingInviteRequest,
  IncomingRequestMessage,
  IncomingResponseMessage,
  LoggerFactory,
  OutgoingRequestDelegate,
  OutgoingSubscribeRequestDelegate,
  Parser,
  SessionDelegate,
  SubscriptionDelegate,
  Transport,
  UserAgentCoreConfiguration,
  UserAgentCoreDelegate
} from "../../../lib/core/index.js";
import { URI } from "../../../lib/grammar/index.js";
import { createRandomToken } from "../../../lib/core/messages/utils.js";

export function connectTransportToUA(transport: jasmine.SpyObj<Transport>, ua: UserAgent): void {
  transport.send.and.callFake((message: string) => {
    // console.log(`Sending to ${ua.configuration.displayName}...`);
    // console.log(message);
    const incomingMessage = Parser.parseMessage(message, ua.getLogger("sip.parser"));
    Promise.resolve().then(() => {
      if (incomingMessage instanceof IncomingRequestMessage) {
        ua.userAgentCore.receiveIncomingRequestFromTransport(incomingMessage);
      }
      if (incomingMessage instanceof IncomingResponseMessage) {
        ua.userAgentCore.receiveIncomingResponseFromTransport(incomingMessage);
      }
    });
    return Promise.resolve();
  });
}

export function connectTransportToUAFork(transport: jasmine.SpyObj<Transport>, ua1: UserAgent, ua2: UserAgent): void {
  transport.send.and.callFake((message: string) => {
    // console.log(`Sending to ${ua1.configuration.displayName} and ${ua2.configuration.displayName}...`);
    // console.log(message);
    // Fork into two copies of the message.
    const incomingMessage1 = Parser.parseMessage(message, ua1.getLogger("sip.parser"));
    const incomingMessage2 = Parser.parseMessage(message, ua2.getLogger("sip.parser"));

    const requestMatches = (incomingMessage: IncomingRequestMessage, ua: UserAgent): boolean => {
      // FIXME: Configuration URI is a bad mix of tyes currently. It also needs to exist.
      if (!(ua.configuration.uri instanceof URI)) {
        throw new Error("Configuration URI not instance of URI.");
      }
      if (!incomingMessage.ruri) {
        // FIXME: A request message should always have an ruri
        throw new Error("Request-URI undefined.");
      }
      const ruri = incomingMessage.ruri;
      const ruriMatches = (uri: URI | undefined): boolean => {
        return !!uri && uri.user === ruri.user;
      };
      if (
        !ruriMatches(ua.configuration.uri) &&
        !(ruriMatches(ua.contact.uri) || ruriMatches(ua.contact.pubGruu) || ruriMatches(ua.contact.tempGruu))
      ) {
        return false;
      }
      return true;
    };

    Promise.resolve().then(() => {
      if (!ua1.userAgentCore) {
        throw new Error("User agent core undefined.");
      }
      if (incomingMessage1 instanceof IncomingRequestMessage) {
        if (requestMatches(incomingMessage1, ua1)) {
          ua1.userAgentCore.receiveIncomingRequestFromTransport(incomingMessage1);
        }
      }
      // TODO: Responses are not routed to specific UA...
      if (incomingMessage1 instanceof IncomingResponseMessage) {
        ua1.userAgentCore.receiveIncomingResponseFromTransport(incomingMessage1);
      }
    });
    Promise.resolve().then(() => {
      if (!ua2.userAgentCore) {
        throw new Error("User agent core undefined.");
      }
      if (incomingMessage2 instanceof IncomingRequestMessage) {
        if (requestMatches(incomingMessage2, ua2)) {
          ua2.userAgentCore.receiveIncomingRequestFromTransport(incomingMessage2);
        }
      }
      // TODO: Responses are not routed to specific UA...
      if (incomingMessage2 instanceof IncomingResponseMessage) {
        ua2.userAgentCore.receiveIncomingResponseFromTransport(incomingMessage2);
      }
    });
    return Promise.resolve();
  });
}

/** Mocked user agent core delegate factory function. */
export function makeMockOutgoingRequestDelegate(): jasmine.SpyObj<Required<OutgoingRequestDelegate>> {
  const delegate = jasmine.createSpyObj<Required<OutgoingRequestDelegate>>("OutgoingRequestDelegate", [
    "onAccept",
    "onProgress",
    "onRedirect",
    "onReject",
    "onTrying"
  ]);
  return delegate;
}

/** Mocked user agent core delegate factory function. */
export function makeMockOutgoingSubscribeRequestDelegate(): jasmine.SpyObj<Required<OutgoingSubscribeRequestDelegate>> {
  const delegate = jasmine.createSpyObj<Required<OutgoingSubscribeRequestDelegate>>(
    "OutgoingSubscribeRequestDelegate",
    ["onAccept", "onProgress", "onRedirect", "onReject", "onTrying", "onNotify", "onNotifyTimeout"]
  );
  return delegate;
}

/** Mocked session delegate factory function. */
export function makeMockSessionDelegate(): jasmine.SpyObj<Required<SessionDelegate>> {
  const delegate = jasmine.createSpyObj<Required<SessionDelegate>>("SessionDelegate", [
    "onAck",
    "onAckTimeout",
    "onBye",
    "onInfo",
    "onInvite",
    "onMessage",
    "onNotify",
    "onPrack",
    "onRefer"
  ]);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  delegate.onAck.and.callFake((request: IncomingAckRequest) => {
    return Promise.resolve();
  });
  return delegate;
}

/** Mocked subscription delegate factory function. */
export function makeMockSubscriptionDelegate(): jasmine.SpyObj<Required<SubscriptionDelegate>> {
  const delegate = jasmine.createSpyObj<Required<SubscriptionDelegate>>("SubscriptionDelegate", ["onNotify"]);
  return delegate;
}

/** Mocked transport factory function. */
export function makeMockTransport(): jasmine.SpyObj<Transport> {
  const transport = jasmine.createSpyObj<Transport>("Transport", ["send"]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (transport.protocol as any) = "TEST";
  transport.send.and.returnValue(Promise.resolve());
  return transport;
}

/** Mocked user agent core delegate factory function. */
export function makeMockUserAgentCoreDelegate(): jasmine.SpyObj<Required<UserAgentCoreDelegate>> {
  const delegate = jasmine.createSpyObj<Required<UserAgentCoreDelegate>>("UserAgentCoreDelegate", [
    "onInvite",
    "onMessage",
    "onNotify",
    "onRefer"
  ]);
  delegate.onInvite.and.callFake((incomingRequest: IncomingInviteRequest) => {
    incomingRequest.trying();
  });
  return delegate;
}

/** Mocked UA factory function. */
export function makeMockUA(user: string, domain: string, displayName: string, transport: Transport): UserAgent {
  const log = new LoggerFactory();
  const viaHost = `${user}Host.invalid`;
  const contactURI = new URI("sip", createRandomToken(8), viaHost, undefined, { transport: "ws" });
  const ua = {
    publishers: {},
    registerers: {},
    sessions: {},
    subscriptions: {},
    contact: {
      pubGruu: undefined,
      tempGruu: undefined,
      uri: contactURI,
      toString: (): string => "<" + contactURI.toString() + ">"
    },
    configuration: {
      displayName,
      noAnswerTimeout: 60000, // ms
      sipjsId: createRandomToken(5),
      uri: new URI("sip", user, domain, undefined),
      userAgentString: `SIP.js/${displayName}`,
      viaHost
    },
    logger: log.getLogger("sip.ua"),
    transport,
    getLogger: (category: string, label?: string) => log.getLogger(category, label),
    getLoggerFactory: () => log,
    getSupportedResponseOptions: () => ["outbound"]
  } as unknown as UserAgent;
  if (!ua.configuration) {
    throw new Error("UA configuration undefined.");
  }
  if (!ua.configuration.uri || !(ua.configuration.uri instanceof URI)) {
    throw new Error("UA configuration uri undefined.");
  }
  return ua;
}

/** Hijacked from UserAgent.initCore() */
export function makeUserAgentCoreConfigurationFromUserAgent(ua: UserAgent): UserAgentCoreConfiguration {
  // supported options
  let supportedOptionTags: Array<string> = [];
  supportedOptionTags.push("outbound"); // TODO: is this really supported?
  if (ua.configuration.sipExtension100rel === SIPExtension.Supported) {
    supportedOptionTags.push("100rel");
  }
  if (ua.configuration.sipExtensionReplaces === SIPExtension.Supported) {
    supportedOptionTags.push("replaces");
  }
  if (ua.configuration.sipExtensionExtraSupported) {
    supportedOptionTags.push(...ua.configuration.sipExtensionExtraSupported);
  }
  if (!ua.configuration.hackAllowUnregisteredOptionTags) {
    supportedOptionTags = supportedOptionTags.filter((optionTag) => UserAgentRegisteredOptionTags[optionTag]);
  }
  supportedOptionTags = Array.from(new Set(supportedOptionTags)); // array of unique values

  // FIXME: TODO: This was ported, but this is and was just plain broken.
  const supportedOptionTagsResponse = supportedOptionTags.slice();
  if (ua.contact.pubGruu || ua.contact.tempGruu) {
    supportedOptionTagsResponse.push("gruu");
  }

  // core configuration
  const userAgentCoreConfiguration: UserAgentCoreConfiguration = {
    aor: ua.configuration.uri,
    contact: ua.contact,
    displayName: ua.configuration.displayName,
    loggerFactory: ua.getLoggerFactory(),
    hackViaTcp: ua.configuration.hackViaTcp,
    routeSet: ua.configuration.preloadedRouteSet,
    supportedOptionTags,
    supportedOptionTagsResponse,
    sipjsId: ua.configuration.sipjsId,
    userAgentHeaderFieldValue: ua.configuration.userAgentString,
    viaForceRport: ua.configuration.forceRport,
    viaHost: ua.configuration.viaHost,
    authenticationFactory: () => {
      const username = ua.configuration.authorizationUsername
        ? ua.configuration.authorizationUsername
        : ua.configuration.uri.user; // if authorization username not provided, use uri user as username
      const password = ua.configuration.authorizationPassword ? ua.configuration.authorizationPassword : undefined;
      const ha1 = ua.configuration.authorizationHa1 ? ua.configuration.authorizationHa1 : undefined;
      return new DigestAuthentication(ua.getLoggerFactory(), ha1, username, password);
    },
    transportAccessor: () => ua.transport
  };
  return userAgentCoreConfiguration;
}
