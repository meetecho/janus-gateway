import { UserAgent } from "../../../lib/api/index.js";
import {
  AckableIncomingResponseWithSession,
  C,
  constructOutgoingResponse,
  IncomingByeRequest,
  IncomingInfoRequest,
  IncomingInviteRequest,
  IncomingMessageRequest,
  IncomingNotifyRequest,
  IncomingPrackRequest,
  IncomingReferRequest,
  IncomingRequestMessage,
  IncomingRequestWithSubscription,
  IncomingResponse,
  IncomingResponseMessage,
  InviteClientTransaction,
  InviteUserAgentClient,
  OutgoingInviteRequest,
  OutgoingPublishRequest,
  OutgoingRequestDelegate,
  OutgoingRequestMessage,
  OutgoingSubscribeRequest,
  OutgoingSubscribeRequestDelegate,
  Parser,
  PrackableIncomingResponseWithSession,
  Session,
  SessionDelegate,
  SessionDialog,
  SignalingState,
  Subscription,
  SubscriptionDelegate,
  Timers,
  Transport,
  TransportError,
  UserAgentCore,
  UserAgentCoreConfiguration
} from "../../../lib/core/index.js";
import { URI } from "../../../lib/grammar/index.js";
import {
  connectTransportToUA,
  makeMockOutgoingRequestDelegate,
  makeMockOutgoingSubscribeRequestDelegate,
  makeMockSessionDelegate,
  makeMockSubscriptionDelegate,
  makeMockTransport,
  makeMockUA,
  makeMockUserAgentCoreDelegate,
  makeUserAgentCoreConfigurationFromUserAgent
} from "../../support/core/mocks.js";

import { soon } from "../../support/api/utils.js";

describe("Core UserAgentCore", () => {
  const userAlice = "alice";
  const userBob = "bob";
  const domainAlice = "example.com";
  const domainBob = "example.com";
  const displayNameAlice = "Alice";
  const displayNameBob = "Bob";
  let configurationAlice: UserAgentCoreConfiguration;
  let configurationBob: UserAgentCoreConfiguration;
  let coreAlice: UserAgentCore;
  let coreBob: UserAgentCore;
  let transportAlice: jasmine.SpyObj<Transport>;
  let transportBob: jasmine.SpyObj<Transport>;
  let uaAlice: UserAgent;
  let uaBob: UserAgent;

  beforeEach(() => {
    transportAlice = makeMockTransport();
    transportBob = makeMockTransport();
    uaAlice = makeMockUA(userAlice, domainAlice, displayNameAlice, transportAlice);
    uaBob = makeMockUA(userBob, domainBob, displayNameBob, transportBob);
    connectTransportToUA(transportAlice, uaBob);
    connectTransportToUA(transportBob, uaAlice);
    configurationAlice = makeUserAgentCoreConfigurationFromUserAgent(uaAlice);
    configurationBob = makeUserAgentCoreConfigurationFromUserAgent(uaBob);
    coreAlice = new UserAgentCore(configurationAlice, {});
    coreBob = new UserAgentCore(configurationBob, {});
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (uaAlice as any).userAgentCore = coreAlice;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (uaBob as any).userAgentCore = coreBob;
  });

  afterEach(() => {
    coreAlice.dispose();
    coreBob.dispose();
  });

  describe("Session Initiation", () => {
    describe("Alice sends Bob an INVITE and...", () => {
      let ruri: URI;
      let from: URI;
      let to: URI;
      let contact: string;
      let message: OutgoingRequestMessage;
      let delegate: jasmine.SpyObj<Required<OutgoingRequestDelegate>>;
      let request: OutgoingInviteRequest;

      beforeEach(() => {
        if (!(uaAlice.configuration.uri instanceof URI)) {
          throw new Error("uri not instance of URI");
        }
        ruri = new URI("sip", userBob, domainBob, undefined);
        from = uaAlice.configuration.uri;
        to = ruri;
        contact = uaAlice.contact.toString();
        const extraHeaders = [`Contact: ${contact}`];
        message = coreAlice.makeOutgoingRequestMessage(C.INVITE, ruri, from, to, {}, extraHeaders);
        delegate = makeMockOutgoingRequestDelegate();
      });

      describe("Transport Error occurs", () => {
        beforeEach((done) => {
          transportAlice.send.and.callFake(() => Promise.reject(new TransportError("Test error.")));
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE, then receives internal 503 Service Unavailable", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(1);
          expect(transportAlice.send.calls.all()[0].args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(0);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(1);
          expect(delegate.onTrying).toHaveBeenCalledTimes(0);
          expect((delegate.onReject.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(503);
        });

        it("Bob's UAS sends nothing", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(0);
        });
      });

      describe("Alice CANCELs the request", () => {
        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.delegate = {
                onCancel: (): void => {
                  incomingRequest.reject({ statusCode: 487 });
                }
              };
            }
          };
          request = coreAlice.invite(message);
          request.delegate = delegate;
          request.cancel();
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE, then CANCEL, then ACK", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(3);
          expect(transportAlice.send.calls.all()[0].args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.all()[1].args[0]).toMatch(new RegExp(`^CANCEL ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.all()[2].args[0]).toMatch(new RegExp(`^ACK ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(0);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(1);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
          expect((delegate.onReject.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(487);
        });

        it("Bob's UAS sends 100 Trying, then 200 Ok (to CANCEL), then 487 Request Terminated", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(3);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 487 Request Terminated`));
        });
      });

      describe("Bob redirects", () => {
        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.redirect([new URI("sip", "carol", "example.com", undefined)]);
            }
          };
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE, then ACK", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(2);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^ACK ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(0);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(1);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
          expect((delegate.onRedirect.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(302);
        });

        it("Bob's UAS sends 100 Trying, then 302 Moved Temporarily", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(2);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 302 Moved Temporarily`));
        });
      });

      describe("Bob rejects (without delegate)", () => {
        beforeEach((done) => {
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE then an ACK", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(2);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^ACK ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(0);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(1);
          expect(delegate.onTrying).toHaveBeenCalledTimes(0);
          expect((delegate.onReject.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(486);
        });

        it("Bob's UAS sends 100 Trying then 486 Busy Here", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(1);
          expect(transportBob.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 486 Busy Here`));
        });
      });

      describe("Bob progresses then rejects", () => {
        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.progress({ statusCode: 180 });
              incomingRequest.reject({ statusCode: 486 });
            }
          };
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE, then ACK", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(2);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^ACK ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(0);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(1);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
          expect((delegate.onReject.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(486);
        });

        it("Bob's UAS sends 100 Trying, then 180 Ringing, then 486 Busy Here", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(3);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 180 Ringing`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 486 Busy Here`));
        });
      });

      describe("Bob progresses and accepts, Alice sends ACK with wrong CSeq", () => {
        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.progress({ statusCode: 180 });
              incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
              });
            }
          };
          delegate.onAccept.and.callFake((response: AckableIncomingResponseWithSession) => {
            if (!(request instanceof InviteUserAgentClient)) {
              throw new Error("Request not InviteUserAgentClient");
            }
            if (!(request.transaction instanceof InviteClientTransaction)) {
              throw new Error("Request transaction not InviteClientTransaction");
            }
            if (!(response.session instanceof SessionDialog)) {
              throw new Error("Response session not SessionDialog");
            }
            const cseq = request.message.cseq + 1;
            const dialog = response.session;
            const ack = dialog.createOutgoingRequestMessage(C.ACK, { cseq });
            request.transaction.ackResponse(ack);
          });
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 3000); // allows 2 retransmissions of ACK
        });

        it("Alice's UAC sends an INVITE, then retransmits wrong ACK (3x)", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(4); // INVITE + 3 ACKs
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
          expect((delegate.onAccept.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(200);
        });

        it("Bob's UAS sends 100 Trying, then 180 Ringing, 200 OK (3x)", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(5);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 180 Ringing`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
        });
      });

      describe("Bob progresses and accepts, but Alice never sends an ACK", () => {
        beforeEach(async () => {
          jasmine.clock().install();
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.progress({ statusCode: 180 });
              incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
              });
            }
          };
          request = coreAlice.invite(message);
          request.delegate = delegate;
          await soon(Timers.TIMER_L - 2); // transaction timeout waiting for ACK
          await soon(1); // a tick to let the retranmissions get processed after the clock jump
          await soon(100000); // and then send the BYE upon transaction timout
        });

        afterEach(() => {
          jasmine.clock().uninstall();
        });

        it("Alice's UAC sends an INVITE, then...", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(2); // 2nd time is 200 OK to the BYE
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
          expect((delegate.onAccept.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(200);
        });

        it("Bob's UAS sends 100 Trying, then 180 Ringing, 200 OK (11x), times out, and sends BYE", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(14);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 180 Ringing`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[4].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[13].args[0]).toMatch(
            new RegExp(`^BYE ${uaAlice.contact.uri.toString()} SIP/2.0`)
          );
        });
      });

      describe("Bob progresses and accepts, but Alice never sends an ACK, Bob withholds BYE", () => {
        let sessionDelegate: jasmine.SpyObj<Required<SessionDelegate>>;

        beforeEach(async () => {
          jasmine.clock().install();
          sessionDelegate = makeMockSessionDelegate();
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.progress({ statusCode: 180 });
              incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
              }).session.delegate = sessionDelegate;
            }
          };
          request = coreAlice.invite(message);
          request.delegate = delegate;
          await soon(Timers.TIMER_L - 2); // transaction timeout waiting for ACK
          await soon(1); // a tick to let the retranmissions get processed after the clock jump
          await soon(100000); // and then send the BYE upon transaction timout
        });

        afterEach(() => {
          jasmine.clock().uninstall();
        });

        it("Alice's UAC sends an INVITE, then...", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(1);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
          expect((delegate.onAccept.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(200);
        });

        it("Bob's UAS sends 100 Trying, then 180 Ringing, 200 OK (11x), and times out", () => {
          expect(transportBob.send).toHaveBeenCalledTimes(13);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 180 Ringing`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[12].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(sessionDelegate.onAckTimeout).toHaveBeenCalledTimes(1);
        });
      });
    });

    describe("Alice sends Bob an INVITE with Offer and...", () => {
      let ruri: URI;
      let from: URI;
      let to: URI;
      let contact: string;
      let message: OutgoingRequestMessage;
      let delegate: jasmine.SpyObj<Required<OutgoingRequestDelegate>>;
      let request: OutgoingInviteRequest;

      beforeEach(() => {
        if (!(uaAlice.configuration.uri instanceof URI)) {
          throw new Error("uri not instance of URI");
        }
        ruri = new URI("sip", userBob, domainBob, undefined);
        from = uaAlice.configuration.uri;
        to = ruri;
        contact = uaAlice.contact.toString();
        const extraHeaders = [`Contact: ${contact}`];
        message = coreAlice.makeOutgoingRequestMessage(C.INVITE, ruri, from, to, {}, extraHeaders, {
          contentDisposition: "session",
          contentType: "application/sdp",
          content: "Offer"
        });
        delegate = makeMockOutgoingRequestDelegate();
      });

      describe("Bob accepts with Answer in 200", () => {
        let sessionAlice: Session;
        let sessionBob: Session;

        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.progress();
              const response = incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Answer" }
              });
              sessionBob = response.session;
            }
          };
          delegate.onAccept.and.callFake((response: AckableIncomingResponseWithSession) => {
            sessionAlice = response.session;
            response.ack();
          });
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE with Offer, then an ACK, and has stable session", () => {
          expect(sessionAlice.signalingState === SignalingState.Stable);
          expect(transportAlice.send).toHaveBeenCalledTimes(2);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
            new RegExp(`^ACK ${uaBob.contact.uri.toString()} SIP/2.0`)
          );
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
        });

        it("Bob's UAS sends 100 Trying, then 200 Ok with Answer, and has stable session", () => {
          expect(sessionBob.signalingState === SignalingState.Stable);
          expect(transportBob.send).toHaveBeenCalledTimes(3);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 180 Ringing`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
        });
      });

      describe("Bob accepts with Answer in 183", () => {
        let sessionAlice: Session;
        let sessionBob: Session;

        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.progress({
                statusCode: 183,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Answer" }
              });
              const response = incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Answer" }
              });
              sessionBob = response.session;
            }
          };
          delegate.onAccept.and.callFake((response: AckableIncomingResponseWithSession) => {
            sessionAlice = response.session;
            response.ack();
          });
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE with Offer, then an ACK, and has stable session", () => {
          expect(sessionAlice.signalingState === SignalingState.Stable);
          expect(transportAlice.send).toHaveBeenCalledTimes(2);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
            new RegExp(`^ACK ${uaBob.contact.uri.toString()} SIP/2.0`)
          );
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
        });

        it("Bob's UAS sends 100 Trying, then 183 Session Progress with Answer, and has stable session", () => {
          expect(sessionBob.signalingState === SignalingState.Stable);
          expect(transportBob.send).toHaveBeenCalledTimes(3);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 183 Session Progress`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
        });
      });

      describe("Bob accepts with Answer in reliable 183", () => {
        let sessionAlice: Session;
        let sessionBob: Session;

        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              const response = incomingRequest.progress({
                statusCode: 183,
                extraHeaders: [`RSeq: 1`],
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Answer" }
              });
              if (!response.session) {
                throw new Error("Session undefined.");
              }
              sessionBob = response.session;
              sessionBob.delegate = {
                onPrack: (prack: IncomingInviteRequest): void => {
                  prack.accept();
                  incomingRequest.accept();
                }
              };
            }
          };
          delegate.onAccept.and.callFake((response: AckableIncomingResponseWithSession) => {
            sessionAlice = response.session;
            response.ack();
          });
          delegate.onProgress.and.callFake((response: PrackableIncomingResponseWithSession) => {
            sessionAlice = response.session;
            response.prack({
              extraHeaders: [`RAck: ${response.message.getHeader("rseq")} ${response.message.getHeader("cseq")}`]
            });
          });
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE with Offer, then a PRACK and ACK, and has stable session", () => {
          expect(sessionAlice.signalingState === SignalingState.Stable);
          expect(transportAlice.send).toHaveBeenCalledTimes(3);
          expect(transportAlice.send.calls.all()[0].args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.all()[1].args[0]).toMatch(
            new RegExp(`^PRACK ${uaBob.contact.uri.toString()} SIP/2.0`)
          );
          expect(transportAlice.send.calls.all()[2].args[0]).toMatch(
            new RegExp(`^ACK ${uaBob.contact.uri.toString()} SIP/2.0`)
          );
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
        });

        it("Bob's UAS sends 100 Trying, then 183 Session Progress with Answer, and has stable session", () => {
          expect(sessionBob.signalingState === SignalingState.Stable);
          expect(transportBob.send).toHaveBeenCalledTimes(4);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 183 Session Progress`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          expect(transportBob.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
        });
      });
    });

    describe("Alice sends Bob an INVITE without an Offer and...", () => {
      let ruri: URI;
      let from: URI;
      let to: URI;
      let contact: string;
      let message: OutgoingRequestMessage;
      let delegate: jasmine.SpyObj<Required<OutgoingRequestDelegate>>;
      let request: OutgoingInviteRequest;

      beforeEach(() => {
        if (!(uaAlice.configuration.uri instanceof URI)) {
          throw new Error("uri not instance of URI");
        }
        ruri = new URI("sip", userBob, domainBob, undefined);
        from = uaAlice.configuration.uri;
        to = ruri;
        contact = uaAlice.contact.toString();
        const extraHeaders = [`Contact: ${contact}`];
        message = coreAlice.makeOutgoingRequestMessage(C.INVITE, ruri, from, to, {}, extraHeaders);
        delegate = makeMockOutgoingRequestDelegate();
      });

      describe("Bob accepts with Offer in 200", () => {
        let sessionAlice: Session;
        let sessionAliceDelegate: jasmine.SpyObj<Required<SessionDelegate>>;
        let sessionBob: Session;
        let sessionBobDelegate: jasmine.SpyObj<Required<SessionDelegate>>;

        beforeEach((done) => {
          coreBob.delegate = {
            onInvite: (incomingRequest: IncomingInviteRequest): void => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.progress();
              const response = incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
              });
              sessionBob = response.session;
              sessionBobDelegate = makeMockSessionDelegate();
              sessionBob.delegate = sessionBobDelegate;
            }
          };
          delegate.onAccept.and.callFake((response: AckableIncomingResponseWithSession) => {
            sessionAlice = response.session;
            sessionAliceDelegate = makeMockSessionDelegate();
            sessionAlice.delegate = sessionAliceDelegate;
            response.ack({
              body: { contentDisposition: "session", contentType: "application/sdp", content: "Answer" }
            });
          });
          request = coreAlice.invite(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an INVITE, then ACKs with Answer, and has stable session", () => {
          expect(sessionAlice.signalingState === SignalingState.Stable);
          expect(transportAlice.send).toHaveBeenCalledTimes(2);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^INVITE ${ruri} SIP/2.0`));
          expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
            new RegExp(`^ACK ${uaBob.contact.uri.toString()} SIP/2.0`)
          );
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(1);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(1);
        });

        it("Bob's UAS sends 100 Trying, then 200 Ok with Offer, and has stable session", () => {
          expect(sessionBob.signalingState === SignalingState.Stable);
          expect(transportBob.send).toHaveBeenCalledTimes(3);
          expect(transportBob.send.calls.all()[0].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
          expect(transportBob.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 180 Ringing`));
          expect(transportBob.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
        });

        describe("Alice sends an in dialog BYE", () => {
          beforeEach((done) => {
            sessionBobDelegate.onBye.and.callFake((incomingRequest: IncomingByeRequest) => {
              incomingRequest.accept();
            });
            sessionAlice.bye();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends a BYE", () => {
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^BYE ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAS receives a BYE and sends an 200 Ok", () => {
            expect(sessionBobDelegate.onBye).toHaveBeenCalledTimes(1);
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Bob sends an in dialog BYE", () => {
          beforeEach((done) => {
            sessionAliceDelegate.onBye.and.callFake((incomingRequest: IncomingByeRequest) => {
              incomingRequest.accept();
            });
            sessionBob.bye();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Bob's UAC sends a BYE", () => {
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^BYE ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Alice's UAS receives a BYE and sends an 200 Ok", () => {
            expect(sessionAliceDelegate.onBye).toHaveBeenCalledTimes(1);
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Alice sends an in dialog INFO", () => {
          beforeEach((done) => {
            sessionBobDelegate.onInfo.and.callFake((incomingRequest: IncomingInfoRequest) => {
              incomingRequest.accept();
            });
            sessionAlice.info();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends a INFO", () => {
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^INFO ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAS receives a INFO and sends an 200 Ok", () => {
            expect(sessionBobDelegate.onInfo).toHaveBeenCalledTimes(1);
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Bob sends an in dialog INFO", () => {
          beforeEach((done) => {
            sessionAliceDelegate.onInfo.and.callFake((incomingRequest: IncomingInfoRequest) => {
              incomingRequest.accept();
            });
            sessionBob.info();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Bob's UAC sends a INFO", () => {
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^INFO ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Alice's UAS receives a INFO and sends an 200 Ok", () => {
            expect(sessionAliceDelegate.onInfo).toHaveBeenCalledTimes(1);
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Alice sends an in dialog INVITE (re-INVITE)", () => {
          beforeEach((done) => {
            sessionBobDelegate.onInvite.and.callFake((incomingRequest: IncomingInviteRequest) => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Answer" }
              });
            });
            contact = uaAlice.contact.toString();
            const extraHeaders = [`Contact: ${contact}`];
            sessionAlice.invite(undefined, {
              extraHeaders,
              body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
            }).delegate = {
              onAccept: (response): void => {
                response.ack();
              }
            };
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends a INVITE and an ACK", () => {
            expect(sessionAlice.signalingState === SignalingState.Stable);
            expect(transportAlice.send).toHaveBeenCalledTimes(4);
            expect(transportAlice.send.calls.all()[2].args[0]).toMatch(
              new RegExp(`^INVITE ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
            expect(transportAlice.send.calls.all()[3].args[0]).toMatch(
              new RegExp(`^ACK ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAS receives a INVITE, sends 100 Trying and 200 Ok", () => {
            expect(sessionBob.signalingState === SignalingState.Stable);
            expect(sessionBobDelegate.onInvite).toHaveBeenCalledTimes(1);
            expect(transportBob.send).toHaveBeenCalledTimes(5);
            expect(transportBob.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
            expect(transportBob.send.calls.all()[4].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Bob sends an in dialog INVITE (re-INVITE)", () => {
          beforeEach((done) => {
            sessionAliceDelegate.onInvite.and.callFake((incomingRequest: IncomingInviteRequest) => {
              // Automatically send 100 Trying to mirror current UA behavior
              incomingRequest.trying();
              incomingRequest.accept({
                statusCode: 200,
                body: { contentDisposition: "session", contentType: "application/sdp", content: "Answer" }
              });
            });
            contact = uaBob.contact.toString();
            const extraHeaders = [`Contact: ${contact}`];
            sessionBob.invite(undefined, {
              extraHeaders,
              body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
            }).delegate = {
              onAccept: (response): void => {
                response.ack();
              }
            };
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Bob's UAC sends a INVITE and an ACK", () => {
            expect(sessionBob.signalingState === SignalingState.Stable);
            expect(transportBob.send).toHaveBeenCalledTimes(5);
            expect(transportBob.send.calls.all()[3].args[0]).toMatch(
              new RegExp(`^INVITE ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
            expect(transportBob.send.calls.all()[4].args[0]).toMatch(
              new RegExp(`^ACK ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Alice's UAS receives a INVITE, sends 100 Trying and 200 Ok", () => {
            expect(sessionAlice.signalingState === SignalingState.Stable);
            expect(sessionAliceDelegate.onInvite).toHaveBeenCalledTimes(1);
            expect(transportAlice.send).toHaveBeenCalledTimes(4);
            expect(transportAlice.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 100 Trying`));
            expect(transportAlice.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Alice sends an in dialog INVITE (re-INVITE)", () => {
          beforeEach((done) => {
            sessionAlice.invite(undefined, {
              extraHeaders: [`Contact: ${uaAlice.contact.toString()}`],
              body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
            }).delegate = {
              onAccept: (response): void => {
                response.ack();
              }
            };
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("should throw if attempt another before first completed", () => {
            expect(() => sessionAlice.invite()).toThrow();
          });
        });

        describe("Alice and Bob send re-INVITE at same time (glare)", () => {
          beforeEach((done) => {
            sessionAlice.invite(undefined, {
              extraHeaders: [`Contact: ${uaAlice.contact.toString()}`],
              body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
            });
            sessionBob.invite(undefined, {
              extraHeaders: [`Contact: ${uaBob.contact.toString()}`],
              body: { contentDisposition: "session", contentType: "application/sdp", content: "Offer" }
            });
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends an INVITE which is rejected with 491 Request Pending", () => {
            expect(sessionAlice.signalingState === SignalingState.Stable);
            expect(transportAlice.send).toHaveBeenCalledTimes(5);
            expect(transportAlice.send.calls.all()[2].args[0]).toMatch(
              new RegExp(`^INVITE ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
            expect(transportAlice.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 491 Request Pending`));
            expect(transportAlice.send.calls.all()[4].args[0]).toMatch(
              new RegExp(`^ACK ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAC sends an INVITE which is rejected with 491 Request Pending", () => {
            expect(sessionBob.signalingState === SignalingState.Stable);
            expect(transportBob.send).toHaveBeenCalledTimes(6);
            expect(transportBob.send.calls.all()[3].args[0]).toMatch(
              new RegExp(`^INVITE ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
            expect(transportBob.send.calls.all()[4].args[0]).toMatch(new RegExp(`^SIP/2.0 491 Request Pending`));
            expect(transportBob.send.calls.all()[5].args[0]).toMatch(
              new RegExp(`^ACK ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });
        });

        describe("Alice sends an in dialog MESSAGE", () => {
          beforeEach((done) => {
            sessionBobDelegate.onMessage.and.callFake((incomingRequest: IncomingMessageRequest) => {
              incomingRequest.accept();
            });
            sessionAlice.message();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends a MESSAGE", () => {
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^MESSAGE ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAS receives a MESSAGE and sends an 200 Ok", () => {
            expect(sessionBobDelegate.onMessage).toHaveBeenCalledTimes(1);
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Bob sends an in dialog MESSAGE", () => {
          beforeEach((done) => {
            sessionAliceDelegate.onMessage.and.callFake((incomingRequest: IncomingMessageRequest) => {
              incomingRequest.accept();
            });
            sessionBob.message();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Bob's UAC sends a MESSAGE", () => {
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^MESSAGE ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Alice's UAS receives a MESSAGE and sends an 200 Ok", () => {
            expect(sessionAliceDelegate.onMessage).toHaveBeenCalledTimes(1);
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Alice sends an in dialog NOTIFY", () => {
          beforeEach((done) => {
            sessionBobDelegate.onNotify.and.callFake((incomingRequest: IncomingNotifyRequest) => {
              incomingRequest.accept();
            });
            sessionAlice.notify(undefined, { extraHeaders: ["Event: foo"] });
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends a NOTIFY", () => {
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^NOTIFY ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAS receives a NOTIFY and sends an 200 Ok", () => {
            expect(sessionBobDelegate.onNotify).toHaveBeenCalledTimes(1);
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Bob sends an in dialog NOTIFY", () => {
          beforeEach((done) => {
            sessionAliceDelegate.onNotify.and.callFake((incomingRequest: IncomingNotifyRequest) => {
              incomingRequest.accept();
            });
            sessionBob.notify(undefined, { extraHeaders: ["Event: foo"] });
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Bob's UAC sends a NOTIFY", () => {
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^NOTIFY ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Alice's UAS receives a NOTIFY and sends an 200 Ok", () => {
            expect(sessionAliceDelegate.onNotify).toHaveBeenCalledTimes(1);
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Alice sends an in dialog PRACK", () => {
          beforeEach((done) => {
            sessionBobDelegate.onPrack.and.callFake((incomingRequest: IncomingPrackRequest) => {
              incomingRequest.accept();
            });
            sessionAlice.prack();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends a PRACK", () => {
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^PRACK ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAS receives a PRACK and sends an 200 Ok", () => {
            expect(sessionBobDelegate.onPrack).toHaveBeenCalledTimes(1);
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Bob sends an in dialog PRACK", () => {
          beforeEach((done) => {
            sessionAliceDelegate.onPrack.and.callFake((incomingRequest: IncomingPrackRequest) => {
              incomingRequest.accept();
            });
            sessionBob.prack();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Bob's UAC sends a PRACK", () => {
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^PRACK ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Alice's UAS receives a PRACK and sends an 200 Ok", () => {
            expect(sessionAliceDelegate.onPrack).toHaveBeenCalledTimes(1);
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Alice sends an in dialog REFER", () => {
          beforeEach((done) => {
            sessionBobDelegate.onRefer.and.callFake((incomingRequest: IncomingReferRequest) => {
              incomingRequest.accept();
            });
            sessionAlice.refer();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAC sends a REFER", () => {
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^REFER ${uaBob.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Bob's UAS receives a REFER and sends an 200 Ok", () => {
            expect(sessionBobDelegate.onRefer).toHaveBeenCalledTimes(1);
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });

        describe("Bob sends an in dialog REFER", () => {
          beforeEach((done) => {
            sessionAliceDelegate.onRefer.and.callFake((incomingRequest: IncomingReferRequest) => {
              incomingRequest.accept();
            });
            sessionBob.refer();
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Bob's UAC sends a REFER", () => {
            expect(transportBob.send).toHaveBeenCalledTimes(4);
            expect(transportBob.send.calls.mostRecent().args[0]).toMatch(
              new RegExp(`^REFER ${uaAlice.contact.uri.toString()} SIP/2.0`)
            );
          });

          it("Alice's UAS receives a REFER and sends an 200 Ok", () => {
            expect(sessionAliceDelegate.onRefer).toHaveBeenCalledTimes(1);
            expect(transportAlice.send).toHaveBeenCalledTimes(3);
            expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
          });
        });
      });
    });
  });

  describe("Sending a Message", () => {
    describe("Alice sends Bob an MESSAGE and...", () => {
      let ruri: URI;
      let from: URI;
      let to: URI;
      let contact: string;
      let message: OutgoingRequestMessage;
      let delegate: jasmine.SpyObj<Required<OutgoingRequestDelegate>>;
      let request: OutgoingInviteRequest;

      beforeEach(() => {
        if (!(uaAlice.configuration.uri instanceof URI)) {
          throw new Error("uri not instance of URI");
        }
        ruri = new URI("sip", userBob, domainBob, undefined);
        from = uaAlice.configuration.uri;
        to = ruri;
        contact = uaAlice.contact.toString();
        const extraHeaders = [`Contact: ${contact}`];
        message = coreAlice.makeOutgoingRequestMessage(C.MESSAGE, ruri, from, to, {}, extraHeaders);
        delegate = makeMockOutgoingRequestDelegate();
      });

      describe("Bob accepts (without delegate)", () => {
        beforeEach((done) => {
          request = coreAlice.message(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an MESSAGE", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(1);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^MESSAGE ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(0);
          expect((delegate.onAccept.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(200);
        });
      });
    });
  });

  describe("Sending a Publish", () => {
    describe("Alice sends Bob an PUBLISH and...", () => {
      let ruri: URI;
      let from: URI;
      let to: URI;
      let contact: string;
      let message: OutgoingRequestMessage;
      let delegate: jasmine.SpyObj<Required<OutgoingRequestDelegate>>;
      let request: OutgoingPublishRequest;

      beforeEach(() => {
        if (!(uaAlice.configuration.uri instanceof URI)) {
          throw new Error("uri not instance of URI");
        }
        ruri = new URI("sip", userBob, domainBob, undefined);
        from = uaAlice.configuration.uri;
        to = ruri;
        contact = uaAlice.contact.toString();
        const extraHeaders = [`Contact: ${contact}`];
        message = coreAlice.makeOutgoingRequestMessage(C.PUBLISH, ruri, from, to, {}, extraHeaders);
        delegate = makeMockOutgoingRequestDelegate();
      });

      describe("Bob rejects (without delegate)", () => {
        beforeEach((done) => {
          request = coreAlice.message(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an PUBLISH", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(1);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^PUBLISH ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(0);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(1);
          expect(delegate.onTrying).toHaveBeenCalledTimes(0);
          expect((delegate.onReject.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(405);
        });
      });
    });
  });

  describe("Subscription Initiation", () => {
    describe("Alice sends a SUBSCRIBE", () => {
      let ruri: URI;
      let from: URI;
      let to: URI;
      let contact: string;
      let message: OutgoingRequestMessage;
      let delegate: jasmine.SpyObj<Required<OutgoingSubscribeRequestDelegate>>;
      let request: OutgoingSubscribeRequest;

      beforeEach(() => {
        if (!(uaAlice.configuration.uri instanceof URI)) {
          throw new Error("uri not instance of URI");
        }
        ruri = new URI("sip", userBob, domainBob, undefined);
        from = uaAlice.configuration.uri;
        to = ruri;
        contact = uaAlice.contact.toString();
        const extraHeaders: Array<string> = [];
        extraHeaders.push(`Event: foo`);
        extraHeaders.push(`Expires: 420`);
        extraHeaders.push(`Subscription-State: active`);
        extraHeaders.push(`Contact: ${contact}`);
        message = coreAlice.makeOutgoingRequestMessage(C.SUBSCRIBE, ruri, from, to, {}, extraHeaders);
        delegate = makeMockOutgoingSubscribeRequestDelegate();
      });

      describe("to Bob", () => {
        beforeEach((done) => {
          request = coreAlice.subscribe(message);
          request.delegate = delegate;
          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an SUBSCRIBE and receives rejection from Bob", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(1);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^SUBSCRIBE ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(0);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(1);
          expect(delegate.onTrying).toHaveBeenCalledTimes(0);
          expect((delegate.onReject.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(480);
        });
      });

      describe("to a presence server mocked up by Bob", () => {
        let subscriptionAlice: Subscription;
        let subscriptionAliceDelegate: jasmine.SpyObj<Required<SubscriptionDelegate>>;
        let subscriptionAliceMessage: IncomingRequestMessage;

        beforeEach((done) => {
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          transportAlice.send.and.callFake((msg: string) => {
            // console.log(`${displayNameAlice} sending...`);
            // console.log(msg);
            return Promise.resolve();
          });
          subscriptionAliceDelegate = makeMockSubscriptionDelegate();
          subscriptionAliceDelegate.onNotify.and.callFake((notifyRequest) => {
            notifyRequest.accept();
          });
          delegate.onNotify.and.callFake((incomingRequest: IncomingRequestWithSubscription) => {
            if (incomingRequest.subscription) {
              subscriptionAlice = incomingRequest.subscription;
              subscriptionAlice.delegate = subscriptionAliceDelegate;
            }
            subscriptionAliceMessage = incomingRequest.request.message;
            incomingRequest.request.accept();
          });
          request = coreAlice.subscribe(message);
          request.delegate = delegate;

          //
          // Manually generaete a 200 OK response to the SUBSCRIBE
          // I don't have a presence server handy, so gonna have Bob fake it...
          //

          // convert outgoing request to incoming request message
          const incomingRequestMessage = Parser.parseMessage(request.message.toString(), uaBob.getLogger("sip.parser"));
          if (!(incomingRequestMessage instanceof IncomingRequestMessage)) {
            throw new Error("Not instance of IncomingRequestMessage.");
          }

          // create 200 OK outgoing response based on incoming request message
          const statusCode = 200;
          const extraHeaders = [`Contact: ${uaBob.contact.toString()}`];
          const outgoingResponse = constructOutgoingResponse(incomingRequestMessage, { statusCode, extraHeaders });

          // convert 200 OK outgoing response to an incoming response message
          const incomingResponseMessage = Parser.parseMessage(
            outgoingResponse.message,
            uaAlice.getLogger("sip.parser")
          );
          if (!(incomingResponseMessage instanceof IncomingResponseMessage)) {
            throw new Error("Not instance of IncomingResponseMessage.");
          }
          coreAlice.receiveIncomingResponseFromTransport(incomingResponseMessage);

          // Cobble together a NOTIFY and send it from Bob's core.
          if (!(uaBob.configuration.uri instanceof URI)) {
            throw new Error("uri not instance of URI");
          }
          const ruriNotify = uaAlice.contact.uri;
          const fromNotify = uaBob.configuration.uri;
          const toNotify = ruriNotify;
          const extraHeadersNotify: Array<string> = [];
          extraHeadersNotify.push(`Event: foo`);
          extraHeadersNotify.push(`Expires: 420`);
          extraHeadersNotify.push(`Subscription-State: active`);
          extraHeadersNotify.push(`Contact: ${uaBob.contact.toString()}`);

          const outgoingRequestMessage1 = coreBob.makeOutgoingRequestMessage(
            C.NOTIFY,
            ruriNotify,
            fromNotify,
            toNotify,
            {
              cseq: 1,
              callId: incomingResponseMessage.callId,
              toTag: incomingResponseMessage.fromTag,
              fromTag: incomingResponseMessage.toTag
            },
            extraHeadersNotify,
            undefined
          );
          coreBob.request(outgoingRequestMessage1);

          setTimeout(() => done(), 10); // transport calls are async, so give it some time
        });

        it("Alice's UAC sends an SUBSCRIBE and receives a 200 OK and a NOTIFY", () => {
          expect(transportAlice.send).toHaveBeenCalledTimes(2);
          expect(transportAlice.send.calls.first().args[0]).toMatch(new RegExp(`^SUBSCRIBE ${ruri} SIP/2.0`));
          expect(delegate.onAccept).toHaveBeenCalledTimes(1);
          expect(delegate.onProgress).toHaveBeenCalledTimes(0);
          expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
          expect(delegate.onReject).toHaveBeenCalledTimes(0);
          expect(delegate.onTrying).toHaveBeenCalledTimes(0);
          expect((delegate.onAccept.calls.first().args[0] as IncomingResponse).message.statusCode).toBe(200);
        });

        describe("which sends a couple of NOTIFY messages", () => {
          let outgoingRequestMessage2: OutgoingRequestMessage;
          let outgoingRequestMessage3: OutgoingRequestMessage;

          beforeEach((done) => {
            // Cobble together a NOTIFY and send it from Bob's core.
            if (!(uaBob.configuration.uri instanceof URI)) {
              throw new Error("uri not instance of URI");
            }
            ruri = uaAlice.contact.uri;
            const fromNotify = uaBob.configuration.uri;
            const toNotify = ruri;
            const extraHeaders: Array<string> = [];
            extraHeaders.push(`Event: foo`);
            extraHeaders.push(`Expires: 420`);
            extraHeaders.push(`Subscription-State: active`);
            extraHeaders.push(`Contact: ${uaBob.contact.toString()}`);
            outgoingRequestMessage2 = coreBob.makeOutgoingRequestMessage(
              C.NOTIFY,
              ruri,
              fromNotify,
              toNotify,
              {
                cseq: 2,
                callId: subscriptionAliceMessage.callId,
                toTag: subscriptionAliceMessage.toTag,
                fromTag: subscriptionAliceMessage.fromTag
              },
              extraHeaders,
              undefined
            );
            outgoingRequestMessage3 = coreBob.makeOutgoingRequestMessage(
              C.NOTIFY,
              ruri,
              fromNotify,
              toNotify,
              {
                cseq: 3,
                callId: subscriptionAliceMessage.callId,
                toTag: subscriptionAliceMessage.toTag,
                fromTag: subscriptionAliceMessage.fromTag
              },
              extraHeaders,
              undefined
            );
            coreBob.request(outgoingRequestMessage2);
            coreBob.request(outgoingRequestMessage3);
            setTimeout(() => done(), 10); // transport calls are async, so give it some time
          });

          it("Alice's UAS receives the NOTIFY messages and accepts them", () => {
            expect(transportAlice.send).toHaveBeenCalledTimes(4);
            expect(transportAlice.send.calls.all()[1].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
            expect(transportAlice.send.calls.all()[2].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
            expect(transportAlice.send.calls.all()[3].args[0]).toMatch(new RegExp(`^SIP/2.0 200 OK`));
            expect(delegate.onAccept).toHaveBeenCalledTimes(1);
            expect(delegate.onProgress).toHaveBeenCalledTimes(0);
            expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
            expect(delegate.onReject).toHaveBeenCalledTimes(0);
            expect(delegate.onTrying).toHaveBeenCalledTimes(0);
            expect((delegate.onAccept.calls.mostRecent().args[0] as IncomingResponse).message.statusCode).toBe(200);
            expect(subscriptionAliceDelegate.onNotify).toHaveBeenCalledTimes(2);
          });

          describe("followed by a couple of broken NOTIFY messages (bad sequence numbers)", () => {
            beforeEach((done) => {
              coreBob.request(outgoingRequestMessage2);
              coreBob.request(outgoingRequestMessage3);
              setTimeout(() => done(), 10); // transport calls are async, so give it some time
            });

            it("Alice's UAS receives the NOTIFY messages and rejects them", () => {
              expect(transportAlice.send).toHaveBeenCalledTimes(6);
              expect(transportAlice.send.calls.all()[4].args[0]).toMatch(
                new RegExp(`^SIP/2.0 500 Internal Server Error`)
              );
              expect(transportAlice.send.calls.all()[5].args[0]).toMatch(
                new RegExp(`^SIP/2.0 500 Internal Server Error`)
              );
              expect(delegate.onAccept).toHaveBeenCalledTimes(1);
              expect(delegate.onProgress).toHaveBeenCalledTimes(0);
              expect(delegate.onRedirect).toHaveBeenCalledTimes(0);
              expect(delegate.onReject).toHaveBeenCalledTimes(0);
              expect(delegate.onTrying).toHaveBeenCalledTimes(0);
            });
          });
        });
      });
    });
  });

  describe("Alice handling Bad Requests", () => {
    const makeBadMessage = (): IncomingRequestMessage => {
      const message = new IncomingRequestMessage();
      message.method = "INVITE";
      message.callId = "callid";
      message.cseq = 1;
      message.ruri = new URI("sip", "alice", "example.com", undefined);
      message.addHeader("To", "<sip:alice@example.com>");
      message.parseHeader("To");
      message.addHeader("From", "<sip:bob@example.com>;tag=123456789");
      message.parseHeader("From");
      message.addHeader("Contact", uaAlice.contact.toString());
      message.viaBranch = "z9hG4bK.0";
      return message;
    };

    // https://tools.ietf.org/html/rfc3261#section-8.2.1
    describe("upon receiving a request with unsupported method", () => {
      beforeEach(() => {
        const message = makeBadMessage();
        message.method = "FOOBAR";
        coreAlice.receiveIncomingRequestFromTransport(message);
      });

      it("Alice's UAS rejects with 405 Method Not Allowed", () => {
        expect(transportAlice.send).toHaveBeenCalledTimes(1);
        expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 405 Method Not Allowed`));
        expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`\r\nAllow: `));
      });
    });

    // https://tools.ietf.org/html/rfc3261#section-8.2.2.1
    describe("upon receiving a request with unsupported ruri scheme", () => {
      beforeEach(() => {
        const message = makeBadMessage();
        message.ruri = new URI("sips", "alice", "example.com", undefined);
        coreAlice.receiveIncomingRequestFromTransport(message);
      });

      it("Alice's UAS rejects with 416 Unsupported URI Scheme", () => {
        expect(transportAlice.send).toHaveBeenCalledTimes(1);
        expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(
          new RegExp(`^SIP/2.0 416 Unsupported URI Scheme`)
        );
      });
    });

    // https://tools.ietf.org/html/rfc3261#section-8.2.2.1
    describe("upon receiving a request with unmatched ruri", () => {
      beforeEach(() => {
        const message = makeBadMessage();
        message.ruri = new URI("sip", "notme", "example.com", undefined);
        coreAlice.receiveIncomingRequestFromTransport(message);
      });

      it("Alice's UAS rejects with 404 Not Found", () => {
        expect(transportAlice.send).toHaveBeenCalledTimes(1);
        expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 404 Not Found`));
      });
    });

    // https://tools.ietf.org/html/rfc3261#section-8.2.2.1
    describe("upon receiving a request which has arrived again via a different path", () => {
      beforeEach(() => {
        // need delegate to prevent rejecting first request automatically
        coreAlice.delegate = makeMockUserAgentCoreDelegate();
        const message = makeBadMessage();
        message.viaBranch = "z9hG4bK.0";
        coreAlice.receiveIncomingRequestFromTransport(message);
        message.viaBranch = "z9hG4bK.1";
        coreAlice.receiveIncomingRequestFromTransport(message);
      });

      it("Alice's UAS rejects with 482 Loop Detected", () => {
        expect(transportAlice.send).toHaveBeenCalledTimes(2);
        expect(transportAlice.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^SIP/2.0 482 Loop Detected`));
      });
    });
  });
});
