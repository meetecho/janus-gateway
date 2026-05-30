import { URI } from "../../../lib/index.js";
import { SessionDescriptionHandler, SIPExtension, UserAgent, UserAgentOptions } from "../../../lib/api/index.js";
import { makeMockSessionDescriptionHandlerFactory } from "./session-description-handler-mock.js";
import { TransportFake } from "./transport-fake.js";

export interface UserFake {
  user: string;
  domain: string;
  displayName: string;
  transport: TransportFake;
  transportReceiveSpy: jasmine.Spy;
  transportSendSpy: jasmine.Spy;
  uri: URI;
  userAgent: UserAgent;
  userAgentOptions: UserAgentOptions;
  isShutdown: () => boolean;
}

export async function makeUserFake(
  user: string | undefined,
  domain: string,
  displayName: string,
  options: UserAgentOptions = {}
): Promise<UserFake> {
  const mockSessionDescriptionHandlers: Array<jasmine.SpyObj<SessionDescriptionHandler>> = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const userHack: any = user; // FIXME: this is because grammar/parser produces undefined on no user
  const uri = new URI("sip", userHack, domain);
  const userAgentOptions: UserAgentOptions = {
    ...{
      uri,
      displayName,
      noAnswerTimeout: 90, // seconds
      sipExtension100rel: SIPExtension.Supported,
      sipExtensionReplaces: SIPExtension.Supported,
      sessionDescriptionHandlerFactory: makeMockSessionDescriptionHandlerFactory(
        displayName,
        0,
        mockSessionDescriptionHandlers
      ),
      transportConstructor: TransportFake
    },
    ...options
  };

  const userAgent = new UserAgent(userAgentOptions);
  await userAgent.start();

  if (!(userAgent.transport instanceof TransportFake)) {
    throw new Error("Transport not TransportFake");
  }
  userAgent.transport.id = displayName;

  const isShutdown = (): boolean => {
    // TODO: Check user agent state finalized

    // Confirm any and all session description handlers have been closed
    const sdhClosed = mockSessionDescriptionHandlers.every((mock) => {
      if (mock.close.calls.count() === 0) {
        // console.error(`${displayName} SDH Not Closed`);
        return false;
      }
      if (mock.close.calls.count() > 1) {
        // console.error(`${displayName} SDH Closed Multiple Times`);
        return false;
      }
      return true;
    });

    const shutdown = sdhClosed;

    // console.warn(`${displayName} is shutdown ${shutdown}`);
    return shutdown;
  };

  return {
    user: user ? user : "",
    domain,
    displayName,
    transport: userAgent.transport,
    transportReceiveSpy: spyOn(userAgent.transport, "receive").and.callThrough(),
    transportSendSpy: spyOn(userAgent.transport, "send").and.callThrough(),
    uri,
    userAgent,
    userAgentOptions,
    isShutdown
  };
}

export function connectUserFake(user1: UserFake, user2: UserFake): void {
  user1.transport.addPeer(user2.transport);
  user2.transport.addPeer(user1.transport);
}
