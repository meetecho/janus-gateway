/* eslint-disable @typescript-eslint/no-use-before-define */
import {
  Invitation,
  Inviter,
  Referral,
  RequestPendingError,
  Session,
  SessionDescriptionHandler,
  SessionState
} from "../../../lib/api/index.js";
import { URI } from "../../../lib/grammar/index.js";
import { OutgoingRequestDelegate, SignalingState } from "../../../lib/core/index.js";
import { EmitterSpy, makeEmitterSpy } from "../../support/api/emitter-spy.js";
import { connectUserFake, makeUserFake, UserFake } from "../../support/api/user-fake.js";
import { soon } from "../../support/api/utils.js";

const SIP_ACK = [jasmine.stringMatching(/^ACK/)];
const SIP_BYE = [jasmine.stringMatching(/^BYE/)];
const SIP_INVITE = [jasmine.stringMatching(/^INVITE/)];
const SIP_MESSAGE = [jasmine.stringMatching(/^MESSAGE/)];
const SIP_NOTIFY = [jasmine.stringMatching(/^NOTIFY/)];
const SIP_REFER = [jasmine.stringMatching(/^REFER/)];
const SIP_100 = [jasmine.stringMatching(/^SIP\/2.0 100/)];
const SIP_180 = [jasmine.stringMatching(/^SIP\/2.0 180/)];
const SIP_200 = [jasmine.stringMatching(/^SIP\/2.0 200/)];
const SIP_202 = [jasmine.stringMatching(/^SIP\/2.0 202/)];
const SIP_404 = [jasmine.stringMatching(/^SIP\/2.0 404/)];
const SIP_407 = [jasmine.stringMatching(/^SIP\/2.0 407/)];
const SIP_481 = [jasmine.stringMatching(/^SIP\/2.0 481/)];
const SIP_488 = [jasmine.stringMatching(/^SIP\/2.0 488/)];
const SIP_500 = [jasmine.stringMatching(/^SIP\/2.0 500/)];
const SIP_RETRY_AFTER = [jasmine.stringMatching(/Retry-After: /)];

//
// Simulatineous SIP Request Processing
//   The answers are scattered in the RFCS, but the following email reply
//   by Dale Worley does a very good job of pulling it all together...
//
// Q: Is it allowed to send an in-dialog request while a previous in-dialog
//    request (in same direction) has no final response?
//  Worley, Dale R (Dale) dworley at avaya.com
//  Tue Apr 10 12:19:03 EDT 2012
// --------
// > From: Iñaki Baz Castillo [ibc at aliax.net]
// >
// > Hi, what should do a UAS that receives an in-dialog request while it
// > has not yet replied a final response for a previous in-dialog
// > request?:
//
// ...
//
// https://lists.cs.columbia.edu/pipermail/sip-implementors/2012-April/028302.html
//
// TLDR;
// - A user agent should not send a request until the prior request is complete as
//   doing so will result in unexpected results as it becomes implementation dependent.
// - A user agent must treat received non-invite requests "atomically" and as such most
//   straight forward implementation is to serialize non-invite incoming requests.
// - One exception to that is the BYE request which should be sendable at any time and
//   handled upon receipt as it effects a state change per the state machine in RFC 5407.
// - Invite request handling needs to be aware that non-invite requests, including BYE,
//   may be occuring while an invite request is outstanding and guard accordingly.
// - Invite requests which arrive while an invite request is outstanding MUST be rejected.

/**
 * Session Integration Tests
 */

describe("API Session In-Dialog", () => {
  let alice: UserFake;
  let bob: UserFake;
  let target: URI;
  let inviter: Inviter;
  let inviterStateSpy: EmitterSpy<SessionState>;
  let invitation: Invitation;
  let invitationStateSpy: EmitterSpy<SessionState>;

  const inviterRequestDelegateMock = jasmine.createSpyObj<Required<OutgoingRequestDelegate>>(
    "OutgoingRequestDelegate",
    ["onAccept", "onProgress", "onRedirect", "onReject", "onTrying"]
  );

  function reinviteAccepted(withoutSdp: boolean): void {
    beforeEach(async () => {
      resetSpies();
      invitation.delegate = undefined;
      return inviter.invite({ withoutSdp }).then(() => alice.transport.waitSent()); // ACK
    });

    it("her ua should send INVITE, ACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
      expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
    });

    it("her ua should receive 200", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual(SIP_200);
    });

    it("her signaling should be stable", () => {
      if (!inviter.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
    });

    it("his signaling should be stable", () => {
      if (!invitation.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(invitation.dialog.signalingState).toEqual(SignalingState.Stable);
    });
  }

  function reinviteAcceptedAuthenticated(withoutSdp: boolean): void {
    beforeEach(async () => {
      resetSpies();
      invitation.delegate = undefined;
      {
        // Setup hacky thing to cause an auth rejection
        if (!invitation.dialog) {
          throw new Error("Session dialog undefined.");
        }
        const delegate = invitation.dialog.delegate; // save current dialog delegate
        invitation.dialog.delegate = {
          onInvite: (request): void => {
            if (!invitation.dialog) {
              throw new Error("Session dialog undefined.");
            }
            invitation.dialog.delegate = delegate; // restore dialog delegate
            // eslint-disable-next-line max-len
            const extraHeaders = [
              `Proxy-Authenticate: Digest realm="example.com", nonce="5cc8bf5800003e0181297d67d3a2e41aa964192a05e30fc4", qop="auth"`
            ];
            request.reject({ statusCode: 407, extraHeaders });
          }
        };
      }
      const session: Session = inviter;
      session.invite({ withoutSdp });
      await alice.transport.waitSent(); // ACK
      await bob.transport.waitReceived(); // INVITE
      await alice.transport.waitSent(); // ACK
    });

    it("her ua should send INVITE, ACK, INVITE, ACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(4);
      expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
      expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
      expect(spy.calls.argsFor(2)).toEqual(SIP_INVITE);
      expect(spy.calls.argsFor(3)).toEqual(SIP_ACK);
    });

    it("her ua should receive 407, 200", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual(SIP_407);
      expect(spy.calls.argsFor(1)).toEqual(SIP_200);
    });

    it("her signaling should be stable", () => {
      if (!inviter.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
    });

    it("his signaling should be stable", () => {
      if (!invitation.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(invitation.dialog.signalingState).toEqual(SignalingState.Stable);
    });
  }

  function reinviteAcceptedWithoutDescriptionFailure(withoutSdp: boolean): void {
    beforeEach(async () => {
      resetSpies();
      {
        // Setup hacky thing to cause undefined body returned once
        if (!invitation.sessionDescriptionHandler) {
          throw new Error("SDH undefined.");
        }
        const sdh = invitation.sessionDescriptionHandler as jasmine.SpyObj<SessionDescriptionHandler>;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (sdh as any).getDescriptionUndefinedBodyOnce = true;
      }
      const session: Session = inviter;
      return session.invite({ withoutSdp }).then(() => alice.transport.waitSent()); // ACK
    });

    if (withoutSdp) {
      it("her ua should send INVITE, ACK, BYE", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(3);
        expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
        expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
      });

      it("her ua should receive 200, 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(spy.calls.argsFor(1)).toEqual(SIP_200);
      });
    } else {
      it("her ua should send INVITE, ACK, BYE, 481", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(4);
        expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
        expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
        expect(spy.calls.argsFor(3)).toEqual(SIP_481);
      });

      it("her ua should receive 200, BYE, 481", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(3);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
        expect(spy.calls.argsFor(2)).toEqual(SIP_481);
      });
    }

    it("her signaling should be closed", () => {
      if (!inviter.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(inviter.dialog.signalingState).toEqual(SignalingState.Closed);
    });

    it("his signaling should be closed", () => {
      if (!invitation.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(invitation.dialog.signalingState).toEqual(SignalingState.Closed);
    });

    it("her session state should transition 'terminated'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)[0]).toEqual(SessionState.Terminated);
    });

    it("his session state should transition 'terminated'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)[0]).toEqual(SessionState.Terminated);
    });
  }

  function reinviteAcceptedOfferAnswerFailure(withoutSdp: boolean): void {
    beforeEach(async () => {
      resetSpies();
      invitation.delegate = undefined;
      const session: Session = inviter;
      return session
        .invite({ withoutSdp })
        .then(() => {
          const sessionDescriptionHandler = session.sessionDescriptionHandler;
          if (!sessionDescriptionHandler) {
            throw new Error("Session description handler undefined");
          }
          const sdh = sessionDescriptionHandler as jasmine.SpyObj<Required<SessionDescriptionHandler>>; // assumes a spy
          sdh.getDescription.and.callFake(() => Promise.reject(new Error("Failed to get description.")));
          sdh.setDescription.and.callFake(() => Promise.reject(new Error("Failed to set description.")));
        })
        .then(() => alice.transport.waitSent()); // ACK
    });

    if (withoutSdp) {
      it("her ua should send INVITE, ACK, BYE, 481", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(4);
        expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
        expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
        expect(spy.calls.argsFor(3)).toEqual(SIP_481);
      });

      it("her ua should receive 200, BYE, 481", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(3);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
        expect(spy.calls.argsFor(2)).toEqual(SIP_481);
      });
    } else {
      it("her ua should send INVITE, ACK, BYE", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(3);
        expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
        expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
      });

      it("her ua should receive 200, 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(spy.calls.argsFor(1)).toEqual(SIP_200);
      });
    }

    it("her signaling should be closed", () => {
      if (!inviter.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(inviter.dialog.signalingState).toEqual(SignalingState.Closed);
    });

    it("his signaling should be closed", () => {
      if (!invitation.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(invitation.dialog.signalingState).toEqual(SignalingState.Closed);
    });

    it("her session state should transition 'terminated'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)[0]).toEqual(SessionState.Terminated);
    });

    it("his session state should transition 'terminated'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)[0]).toEqual(SessionState.Terminated);
    });
  }

  function reinviteInProgress(withoutSdp: boolean): void {
    beforeEach(async () => {
      resetSpies();
      invitation.delegate = {
        onInvite: (): void => {
          return;
        } // ignore invite
      };
      return inviter.invite({ withoutSdp });
    });

    it("her ua should send INVITE", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
    });

    it("her ua should reject an additional INVITE", () => {
      inviter.invite({ withoutSdp }).catch((error: Error) => {
        expect(error).toEqual(jasmine.any(RequestPendingError));
      });
    });

    if (withoutSdp) {
      it("her signaling should be stable", () => {
        if (!inviter.dialog) {
          fail("Session dialog undefined");
          return;
        }
        expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
      });

      it("his signaling should be stable", () => {
        if (!invitation.dialog) {
          fail("Session dialog undefined");
          return;
        }
        expect(invitation.dialog.signalingState).toEqual(SignalingState.Stable);
      });
    } else {
      it("her signaling should be have local offer", () => {
        if (!inviter.dialog) {
          fail("Session dialog undefined");
          return;
        }
        expect(inviter.dialog.signalingState).toEqual(SignalingState.HaveLocalOffer);
      });

      it("his signaling should be has remote offer", () => {
        if (!invitation.dialog) {
          fail("Session dialog undefined");
          return;
        }
        expect(invitation.dialog.signalingState).toEqual(SignalingState.HaveRemoteOffer);
      });
    }
  }

  function reinviteRejected(withoutSdp: boolean): void {
    beforeEach(async () => {
      resetSpies();
      {
        // Setup hacky thing to cause a rejection once
        if (!invitation.sessionDescriptionHandler) {
          throw new Error("SDH undefined.");
        }
        const sdh = invitation.sessionDescriptionHandler as jasmine.SpyObj<SessionDescriptionHandler>;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (sdh as any).getDescriptionRejectOnce = true;
      }
      const session: Session = inviter;
      return session.invite({ withoutSdp }).then(() => alice.transport.waitSent()); // ACK
    });

    it("her ua should send INVITE, ACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
      expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
    });

    it("her ua should receive 488", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual(SIP_488);
    });

    it("her signaling should be stable", () => {
      if (!inviter.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
    });

    it("his signaling should be stable", () => {
      if (!invitation.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(invitation.dialog.signalingState).toEqual(SignalingState.Stable);
    });
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  function reinviteRejectedRollbackFailure(withoutSdp: boolean): void {
    beforeEach(async () => {
      resetSpies();
      {
        // Setup hacky thing to cause a rejection once
        if (!invitation.sessionDescriptionHandler) {
          throw new Error("SDH undefined.");
        }
        const sdh = invitation.sessionDescriptionHandler as jasmine.SpyObj<SessionDescriptionHandler>;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (sdh as any).getDescriptionRejectOnce = true;
      }
      const session: Session = inviter;
      return session
        .invite({ withoutSdp: false }) // Note that rollback on reject this only happens INVITE with SDP
        .then(() => {
          const sessionDescriptionHandler = session.sessionDescriptionHandler;
          if (!sessionDescriptionHandler) {
            throw new Error("Session description handler undefined");
          }
          const sdh = sessionDescriptionHandler as jasmine.SpyObj<Required<SessionDescriptionHandler>>; // assumes a spy
          sdh.rollbackDescription.and.callFake(() => Promise.reject(new Error("Failed to rollback description.")));
        })
        .then(() => alice.transport.waitSent()); // ACK
    });

    it("her ua should send INVITE, ACK, BYE", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(3);
      expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
      expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
      expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
    });

    it("her ua should receive 488", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual(SIP_488);
    });

    it("her signaling should be closed", () => {
      if (!inviter.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(inviter.dialog.signalingState).toEqual(SignalingState.Closed);
    });

    it("his signaling should be closed", () => {
      if (!invitation.dialog) {
        fail("Session dialog undefined");
        return;
      }
      expect(invitation.dialog.signalingState).toEqual(SignalingState.Closed);
    });

    it("her session state should transition 'terminated'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)[0]).toEqual(SessionState.Terminated);
    });

    it("his session state should transition 'terminated'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)[0]).toEqual(SessionState.Terminated);
    });
  }

  function reinviteSuite(withoutSdp: boolean): void {
    describe("Alice invite() accepted", () => {
      reinviteAccepted(withoutSdp);

      describe("Alice invite() accepted", () => {
        reinviteAccepted(withoutSdp);
      });
    });

    describe("Alice invite() accepted authenticated", () => {
      reinviteAcceptedAuthenticated(withoutSdp);
    });

    describe("Alice invite() accepted without description failure", () => {
      reinviteAcceptedWithoutDescriptionFailure(withoutSdp);
    });

    describe("Alice invite() accepted offer/answer failure", () => {
      reinviteAcceptedOfferAnswerFailure(withoutSdp);
    });

    describe("Alice invite() rejected", () => {
      reinviteRejected(withoutSdp);

      describe("Alice invite() accepted", () => {
        reinviteAccepted(withoutSdp);
      });
    });

    describe("Alice invite() rejected rollback failure", () => {
      reinviteRejectedRollbackFailure(withoutSdp);
    });

    describe("Alice invite() request in progress", () => {
      reinviteInProgress(withoutSdp);
    });
  }

  function resetSpies(): void {
    alice.transportReceiveSpy.calls.reset();
    alice.transportSendSpy.calls.reset();
    bob.transportReceiveSpy.calls.reset();
    bob.transportSendSpy.calls.reset();
    inviterStateSpy.calls.reset();
    if (invitationStateSpy) {
      invitationStateSpy.calls.reset();
    }
    inviterRequestDelegateMock.onAccept.calls.reset();
    inviterRequestDelegateMock.onProgress.calls.reset();
    inviterRequestDelegateMock.onRedirect.calls.reset();
    inviterRequestDelegateMock.onReject.calls.reset();
    inviterRequestDelegateMock.onTrying.calls.reset();
  }

  beforeEach(async () => {
    jasmine.clock().install();
    alice = await makeUserFake("alice", "example.com", "Alice");
    bob = await makeUserFake("bob", "example.com", "Bob");
    connectUserFake(alice, bob);
  });

  afterEach(async () => {
    return alice.userAgent
      .stop()
      .then(() => expect(alice.isShutdown()).toBe(true))
      .then(() => bob.userAgent.stop())
      .then(() => expect(bob.isShutdown()).toBe(true))
      .then(() => jasmine.clock().uninstall());
  });

  describe("In Dialog...", () => {
    beforeEach(async () => {
      target = bob.uri;
      bob.userAgent.delegate = {
        onInvite: (session): void => {
          invitation = session;
          invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
        }
      };
      inviter = new Inviter(alice.userAgent, target);
      inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
      await soon();
    });

    describe("Alice invite() without sdp", () => {
      beforeEach(async () => {
        inviter.invite({ withoutSdp: true });
        await bob.transport.waitSent();
      });

      describe("Bob accept() ACK dropped", () => {
        beforeEach(async () => {
          resetSpies();
          bob.transport.receiveDropOnce(); // ACK
          invitation.accept();
          await alice.transport.waitSent(); // ACK
        });

        it("her session state should be `established`", () => {
          expect(inviter.state).toBe(SessionState.Established);
        });

        it("his session state should be `established`", () => {
          expect(invitation.state).toBe(SessionState.Established);
        });

        describe("Re-INVITE race", () => {
          beforeEach(async () => {
            resetSpies();
            invitation.delegate = undefined;
            inviter.invite();
            await bob.transport.waitSent(); // 500
          });

          it("her ua should send INVITE, ACK", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
            expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
          });

          it("her ua should receive 500 with Retry-After", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_500);
            expect(spy.calls.argsFor(0)).toEqual(SIP_RETRY_AFTER);
          });

          it("her signaling should be stable", () => {
            if (!inviter.dialog) {
              fail("Session dialog undefined");
              return;
            }
            expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
          });

          it("his signaling should be have-local-offer", () => {
            if (!invitation.dialog) {
              fail("Session dialog undefined");
              return;
            }
            expect(invitation.dialog.signalingState).toEqual(SignalingState.HaveLocalOffer);
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });
      });

      describe("Bob accept() ACK processing", () => {
        beforeEach(async () => {
          resetSpies();
          invitation.accept();
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (invitation.sessionDescriptionHandler as any).setDescriptionWaitOnce = true;
          await alice.transport.waitSent(); // ACK
        });

        it("her session state should be `established`", () => {
          expect(inviter.state).toBe(SessionState.Established);
        });

        it("his session state should be `established`", () => {
          expect(invitation.state).toBe(SessionState.Established);
        });

        describe("Re-INVITE race", () => {
          beforeEach(async () => {
            resetSpies();
            invitation.delegate = undefined;
            inviter.invite();
            await bob.transport.waitSent();
            await soon(1);
          });

          it("her ua should send INVITE, ACK", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
            expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
          });

          it("her ua should receive 500 with Retry-After", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_500);
            expect(spy.calls.argsFor(0)).toEqual(SIP_RETRY_AFTER);
          });

          it("her signaling should be stable", () => {
            if (!inviter.dialog) {
              fail("Session dialog undefined");
              return;
            }
            expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
          });

          it("his signaling should be stable", () => {
            if (!invitation.dialog) {
              fail("Session dialog undefined");
              return;
            }
            expect(invitation.dialog.signalingState).toEqual(SignalingState.Stable);
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });
      });
    });

    describe("Alice invite() with sdp", () => {
      beforeEach(async () => {
        return inviter.invite().then(() => bob.transport.waitSent());
      });

      describe("Bob accept() ACK dropped", () => {
        beforeEach(async () => {
          resetSpies();
          bob.transport.receiveDropOnce(); // ACK
          invitation.accept();
          await alice.transport.waitSent(); // ACK
        });

        it("her session state should be `established`", () => {
          expect(inviter.state).toBe(SessionState.Established);
        });

        it("his session state should be `established`", () => {
          expect(invitation.state).toBe(SessionState.Established);
        });

        describe("Re-INVITE race", () => {
          beforeEach(async () => {
            resetSpies();
            invitation.delegate = undefined;
            inviter.invite();
            await bob.transport.waitSent();
            await alice.transport.waitSent();
          });

          it("her ua should send INVITE, ACK", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
            expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
          });

          it("her ua should receive 200", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          });

          it("her signaling should be stable", () => {
            if (!inviter.dialog) {
              fail("Session dialog undefined");
              return;
            }
            expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
          });

          it("his signaling should be stable", () => {
            if (!invitation.dialog) {
              fail("Session dialog undefined");
              return;
            }
            expect(invitation.dialog.signalingState).toEqual(SignalingState.Stable);
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });
      });

      describe("Bob accept()", () => {
        beforeEach(async () => {
          resetSpies();
          return invitation.accept().then(() => alice.transport.waitSent()); // ACK
        });

        it("her session state should be `established`", () => {
          expect(inviter.state).toBe(SessionState.Established);
        });

        it("his session state should be `established`", () => {
          expect(invitation.state).toBe(SessionState.Established);
        });

        describe("Re-INVITE with SDP...", () => {
          reinviteSuite(false);
        });

        describe("Re-INVITE without SDP...", () => {
          reinviteSuite(true);
        });

        describe("Re-INVITE with SDP failure...", () => {
          describe("Alice invite() failure", () => {
            beforeEach(async () => {
              resetSpies();
              const session: Session = inviter;
              const sessionDescriptionHandler = session.sessionDescriptionHandler;
              if (!sessionDescriptionHandler) {
                throw new Error("Session description handler undefined");
              }
              const sdh = sessionDescriptionHandler as jasmine.SpyObj<Required<SessionDescriptionHandler>>;
              sdh.getDescription.and.callFake(() => Promise.reject(new Error("Failed to get description.")));
              return session.invite().catch(() => {
                return;
              });
            });

            it("her ua should send nothing", () => {
              const spy = alice.transportSendSpy;
              expect(spy).toHaveBeenCalledTimes(0);
            });

            it("her signaling should be stable", () => {
              if (!inviter.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(inviter.dialog.signalingState).toEqual(SignalingState.Stable);
            });

            it("his signaling should be stable", () => {
              if (!invitation.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(invitation.dialog.signalingState).toEqual(SignalingState.Stable);
            });
          });
        });

        describe("Re-INVITE with SDP send BYE race...", () => {
          describe("Alice invite(), bye()", () => {
            beforeEach(async () => {
              resetSpies();
              invitation.delegate = undefined;
              return inviter
                .invite()
                .then(() => inviter.bye())
                .then(() => alice.transport.waitSent());
            });

            it("her ua should send INVITE, ACK, BYE", () => {
              const spy = alice.transportSendSpy;
              expect(spy).toHaveBeenCalledTimes(3);
              expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
              expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
              expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            });

            it("her ua should receive 200, 200", () => {
              const spy = alice.transportReceiveSpy;
              expect(spy).toHaveBeenCalledTimes(2);
              expect(spy.calls.argsFor(0)).toEqual(SIP_200);
              expect(spy.calls.argsFor(1)).toEqual(SIP_200);
            });

            it("her signaling should be closed", () => {
              if (!inviter.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(inviter.dialog.signalingState).toEqual(SignalingState.Closed);
            });

            it("his signaling should be closed", () => {
              if (!invitation.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(invitation.dialog.signalingState).toEqual(SignalingState.Closed);
            });
          });
        });

        describe("Re-INVITE without SDP send BYE race...", () => {
          describe("Alice invite(), bye()", () => {
            beforeEach(async () => {
              resetSpies();
              invitation.delegate = undefined;
              return inviter
                .invite({ withoutSdp: true })
                .then(() => inviter.bye())
                .then(() => alice.transport.waitSent());
            });

            it("her ua should send INVITE, ACK, BYE", () => {
              const spy = alice.transportSendSpy;
              expect(spy).toHaveBeenCalledTimes(3);
              expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
              expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
              expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            });

            it("her ua should receive 200, 200", () => {
              const spy = alice.transportReceiveSpy;
              expect(spy).toHaveBeenCalledTimes(2);
              expect(spy.calls.argsFor(0)).toEqual(SIP_200);
              expect(spy.calls.argsFor(1)).toEqual(SIP_200);
            });

            it("her signaling should be closed", () => {
              if (!inviter.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(inviter.dialog.signalingState).toEqual(SignalingState.Closed);
            });

            it("his signaling should be closed", () => {
              if (!invitation.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(invitation.dialog.signalingState).toEqual(SignalingState.Closed);
            });
          });
        });

        describe("Re-INVITE with SDP receive BYE race...", () => {
          describe("Alice invite(), Bob bye()", () => {
            beforeEach(async () => {
              resetSpies();
              invitation.delegate = undefined;
              return inviter
                .invite()
                .then(() => invitation.bye())
                .then(() => alice.transport.waitSent());
            });

            it("her ua should send INVITE, 200, ACK", () => {
              const spy = alice.transportSendSpy;
              expect(spy).toHaveBeenCalledTimes(3);
              expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
              expect(spy.calls.argsFor(1)).toEqual(SIP_200);
              expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            });

            it("her ua should receive BYE, 488", () => {
              const spy = alice.transportReceiveSpy;
              expect(spy).toHaveBeenCalledTimes(2);
              expect(spy.calls.argsFor(0)).toEqual(SIP_BYE);
              expect(spy.calls.argsFor(1)).toEqual(SIP_488);
            });

            it("her signaling should be closed", () => {
              if (!inviter.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(inviter.dialog.signalingState).toEqual(SignalingState.Closed);
            });

            it("his signaling should be closed", () => {
              if (!invitation.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(invitation.dialog.signalingState).toEqual(SignalingState.Closed);
            });
          });
        });

        describe("Re-INVITE without SDP receive BYE race...", () => {
          describe("Alice invite(), Bob bye()", () => {
            beforeEach(async () => {
              resetSpies();
              invitation.delegate = undefined;
              return inviter
                .invite({ withoutSdp: true })
                .then(() => bob.transport.waitSent())
                .then(() => invitation.bye())
                .then(() => alice.transport.waitSent());
            });

            it("her ua should send INVITE, 200, ACK", () => {
              const spy = alice.transportSendSpy;
              expect(spy).toHaveBeenCalledTimes(3);
              expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
              expect(spy.calls.argsFor(1)).toEqual(SIP_200);
              expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            });

            it("her ua should receive 200, BYE", () => {
              const spy = alice.transportReceiveSpy;
              expect(spy).toHaveBeenCalledTimes(2);
              expect(spy.calls.argsFor(0)).toEqual(SIP_200);
              expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
            });

            it("her signaling should be closed", () => {
              if (!inviter.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(inviter.dialog.signalingState).toEqual(SignalingState.Closed);
            });

            it("his signaling should be closed", () => {
              if (!invitation.dialog) {
                fail("Session dialog undefined");
                return;
              }
              expect(invitation.dialog.signalingState).toEqual(SignalingState.Closed);
            });
          });
        });

        describe("REFER Alice with default handler", () => {
          beforeEach(async () => {
            resetSpies();
            inviter.delegate = undefined;
            const referTo = new URI("sip", "carol", "example.com");
            return invitation
              .refer(referTo)
              .then(() => alice.transport.waitSent()) // 202
              .then(() => alice.transport.waitSent()) // INVITE
              .then(() => bob.transport.waitSent()); // 200
          });

          it("her ua should send 202, INVITE, ACK, NOTIFY", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(4);
            expect(spy.calls.argsFor(0)).toEqual(SIP_202);
            expect(spy.calls.argsFor(1)).toEqual(SIP_INVITE);
            expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(3)).toEqual(SIP_NOTIFY);
          });

          it("her ua should receive REFER, 404, 200", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_REFER);
            expect(spy.calls.argsFor(1)).toEqual(SIP_404); // fake transport wired to Bob (not Carol, and thus the 404)
            expect(spy.calls.argsFor(2)).toEqual(SIP_200); // response to the NOTIFY
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });

        describe("REFER Alice with delegated handler", () => {
          beforeEach(async () => {
            resetSpies();
            inviter.delegate = {
              onRefer(referral: Referral): void {
                referral.accept().then(() => {
                  const refereeInviter = referral.makeInviter();
                  refereeInviter.invite();
                });
              }
            };
            const referTo = new URI("sip", "carol", "example.com");
            return invitation
              .refer(referTo)
              .then(() => alice.transport.waitSent()) // 202
              .then(() => alice.transport.waitSent()) // INVITE
              .then(() => bob.transport.waitSent()); // 200
          });

          it("her ua should send 202, INVITE, ACK, NOTIFY", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(4);
            expect(spy.calls.argsFor(0)).toEqual(SIP_202);
            expect(spy.calls.argsFor(1)).toEqual(SIP_INVITE);
            expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(3)).toEqual(SIP_NOTIFY);
          });

          it("her ua should receive REFER, 404, 200", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_REFER);
            expect(spy.calls.argsFor(1)).toEqual(SIP_404); // fake transport wired to Bob (not Carol, and thus the 404)
            expect(spy.calls.argsFor(2)).toEqual(SIP_200); // response to the NOTIFY
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });

        describe("REFER Bob with default handler", () => {
          beforeEach(async () => {
            resetSpies();
            invitation.delegate = undefined;
            const referTo = new URI("sip", "carol", "example.com");
            return inviter
              .refer(referTo)
              .then(() => bob.transport.waitSent()) // 202
              .then(() => bob.transport.waitSent()) // INVITE
              .then(() => alice.transport.waitSent()); // 200
          });

          it("his ua should send 202, INVITE, ACK, NOTIFY", () => {
            const spy = bob.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(4);
            expect(spy.calls.argsFor(0)).toEqual(SIP_202);
            expect(spy.calls.argsFor(1)).toEqual(SIP_INVITE);
            expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(3)).toEqual(SIP_NOTIFY);
          });

          it("his ua should receive REFER, 404, 200", () => {
            const spy = bob.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_REFER);
            expect(spy.calls.argsFor(1)).toEqual(SIP_404); // fake transport wired to Bob (not Carol, and thus the 404)
            expect(spy.calls.argsFor(2)).toEqual(SIP_200); // response to the NOTIFY
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });

        describe("REFER Bob with delegated handler", () => {
          beforeEach(async () => {
            resetSpies();
            invitation.delegate = {
              onRefer(referral: Referral): void {
                referral.accept().then(() => {
                  const refereeInviter = referral.makeInviter();
                  refereeInviter.invite();
                });
              }
            };
            const referTo = new URI("sip", "carol", "example.com");
            return inviter
              .refer(referTo)
              .then(() => bob.transport.waitSent()) // 202
              .then(() => bob.transport.waitSent()) // INVITE
              .then(() => alice.transport.waitSent()); // 200
          });

          it("his ua should send 202, INVITE, ACK, NOTIFY", () => {
            const spy = bob.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(4);
            expect(spy.calls.argsFor(0)).toEqual(SIP_202);
            expect(spy.calls.argsFor(1)).toEqual(SIP_INVITE);
            expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(3)).toEqual(SIP_NOTIFY);
          });

          it("his ua should receive REFER, 404, 200", () => {
            const spy = bob.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_REFER);
            expect(spy.calls.argsFor(1)).toEqual(SIP_404); // fake transport wired to Bob (not Carol, and thus the 404)
            expect(spy.calls.argsFor(2)).toEqual(SIP_200); // response to the NOTIFY
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });

        describe("MESSAGE with default handler", () => {
          beforeEach(async () => {
            resetSpies();
            inviter.delegate = undefined;
            invitation.delegate = undefined;
            inviter.message();
            await alice.transport.waitSent(); // MESSAGE
          });

          it("her ua should send MESSAGE", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_MESSAGE);
          });

          it("her ua should receive 200", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200); // response to the MESSAGE
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });

        describe("MESSAGE with delegated handler", () => {
          beforeEach(async () => {
            resetSpies();
            inviter.delegate = undefined;
            invitation.delegate = {
              onMessage: (request): Promise<void> => request.accept()
            };
            inviter.message();
            await alice.transport.waitSent(); // MESSAGE
          });

          it("her ua should send MESSAGE", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_MESSAGE);
          });

          it("her ua should receive 200", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200); // response to the MESSAGE
          });

          it("her session state should be `established`", () => {
            expect(inviter.state).toBe(SessionState.Established);
          });

          it("his session state should be `established`", () => {
            expect(invitation.state).toBe(SessionState.Established);
          });
        });
      });
    });
  });

  // This group of tests is probably better covered in conjunction with testing REFER w/Replaces
  describe("INVITE with Replaces...", () => {
    beforeEach(async () => {
      target = bob.uri;
      bob.userAgent.delegate = {
        onInvite: (session): void => {
          invitation = session;
          invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
        }
      };
      inviter = new Inviter(alice.userAgent, target);
      inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
      await soon();
    });

    describe("Alice invite()", () => {
      beforeEach(() => {
        return inviter.invite().then(() => bob.transport.waitSent());
      });

      describe("Bob accept()", () => {
        beforeEach(() => {
          resetSpies();
          return invitation.accept().then(() => alice.transport.waitSent()); // ACK
        });

        it("her state should be `established`", () => {
          expect(inviter.state).toBe(SessionState.Established);
        });

        it("his state should be `established`", () => {
          expect(invitation.state).toBe(SessionState.Established);
        });

        describe("Carol invite() with Replaces to Alice...", () => {
          let carol: UserFake;
          let replacesInviter: Inviter;
          let replacesInvitation: Invitation;

          function resetSpies3(): void {
            resetSpies();
            carol.transportReceiveSpy.calls.reset();
            carol.transportSendSpy.calls.reset();
          }

          beforeEach(async () => {
            carol = await makeUserFake("carol", "example.com", "Carol");
            connectUserFake(alice, carol);
          });

          afterEach(async () => {
            return carol.userAgent.stop().then(() => expect(carol.isShutdown()).toBe(true));
          });

          describe("Replacing unknown session", () => {
            beforeEach(async () => {
              resetSpies3();
              alice.userAgent.delegate = {
                onInvite: (session): void => {
                  replacesInvitation = session;
                }
              };
              const callId = "unknown";
              const remoteTag = invitation.request.fromTag;
              const localTag = invitation.request.toTag;
              const replaces = `${callId};to-tag=${remoteTag};from-tag=${localTag}`;
              const options = {
                extraHeaders: ["Replaces: " + replaces]
              };
              replacesInviter = new Inviter(carol.userAgent, alice.uri, options);
              return replacesInviter.invite().catch(() => {
                return;
              });
            });

            it("Carol ua should send INVITE, ACK", () => {
              const spy = carol.transportSendSpy;
              expect(spy).toHaveBeenCalledTimes(2);
              expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
              expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
            });

            it("Carol ua should receive 100, 481", () => {
              const spy = carol.transportReceiveSpy;
              expect(spy).toHaveBeenCalledTimes(2);
              expect(spy.calls.argsFor(0)).toEqual(SIP_100);
              expect(spy.calls.argsFor(1)).toEqual(SIP_481);
            });

            it("Carol state should be `terminated`", () => {
              expect(replacesInviter.state).toBe(SessionState.Terminated);
            });
          });

          describe("Replacing Bob's session", () => {
            beforeEach(async () => {
              resetSpies3();
              alice.userAgent.delegate = {
                onInvite: (session): void => {
                  replacesInvitation = session;
                }
              };
              const callId = invitation.request.callId;
              const remoteTag = invitation.request.fromTag;
              const localTag = invitation.request.toTag;
              const replaces = `${callId};to-tag=${remoteTag};from-tag=${localTag}`;
              const options = {
                extraHeaders: ["Replaces: " + replaces]
              };
              replacesInviter = new Inviter(carol.userAgent, alice.uri, options);
              return replacesInviter
                .invite()
                .then(() => alice.transport.waitSent()) // provisional response
                .catch(() => {
                  return;
                });
            });

            it("Carol state should be `establishing`", () => {
              expect(replacesInviter.state).toBe(SessionState.Establishing);
            });

            describe("Alice accept()", () => {
              beforeEach(async () => {
                return replacesInvitation.accept().then(() => carol.transport.waitSent()); // ACK
              });

              it("Carol ua should send INVITE, ACK", () => {
                const spy = carol.transportSendSpy;
                expect(spy).toHaveBeenCalledTimes(3);
                expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
                expect(spy.calls.argsFor(1)).toEqual(SIP_404); // To the BYE to Bob, we get a copy
                expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
              });

              it("Carol ua should receive 100, 180, 200", () => {
                const spy = carol.transportReceiveSpy;
                expect(spy).toHaveBeenCalledTimes(4);
                expect(spy.calls.argsFor(0)).toEqual(SIP_100);
                expect(spy.calls.argsFor(1)).toEqual(SIP_180);
                expect(spy.calls.argsFor(2)).toEqual(SIP_200);
                expect(spy.calls.argsFor(3)).toEqual(SIP_BYE); // This is to Bob, but we get a copy
              });

              it("Carol state should be established and stable", () => {
                if (!replacesInviter.dialog) {
                  fail("Session dialog undefined");
                  return;
                }
                expect(replacesInviter.state).toBe(SessionState.Established);
                expect(replacesInviter.dialog.signalingState).toEqual(SignalingState.Stable);
              });

              it("Alice state to be established and stable", () => {
                if (!replacesInvitation.dialog) {
                  fail("Session dialog undefined");
                  return;
                }
                expect(replacesInvitation.state).toBe(SessionState.Established);
                expect(replacesInvitation.dialog.signalingState).toEqual(SignalingState.Stable);
              });

              it("Alice to Bob state should be terminated", () => {
                expect(inviter.state).toBe(SessionState.Terminated);
                expect(invitation.state).toBe(SessionState.Terminated);
              });
            });
          });
        });
      });
    });
  });
});
