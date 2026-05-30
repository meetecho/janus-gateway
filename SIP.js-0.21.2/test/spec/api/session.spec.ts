/* eslint-disable @typescript-eslint/unbound-method */
/* eslint-disable @typescript-eslint/no-use-before-define */
import {
  Invitation,
  Inviter,
  SessionDelegate,
  SessionDescriptionHandler,
  SessionState
} from "../../../lib/api/index.js";
import { URI } from "../../../lib/grammar/index.js";
import {
  Logger,
  OutgoingRequestDelegate,
  SessionState as SessionDialogState,
  SignalingState,
  Timers
} from "../../../lib/core/index.js";
import { EmitterSpy, makeEmitterSpy } from "../../support/api/emitter-spy.js";
import { TransportFake } from "../../support/api/transport-fake.js";
import { connectUserFake, makeUserFake, UserFake } from "../../support/api/user-fake.js";
import { soon } from "../../support/api/utils.js";

const SIP_ACK = [jasmine.stringMatching(/^ACK/)];
const SIP_BYE = [jasmine.stringMatching(/^BYE/)];
const SIP_CANCEL = [jasmine.stringMatching(/^CANCEL/)];
const SIP_INVITE = [jasmine.stringMatching(/^INVITE/)];
const SIP_PRACK = [jasmine.stringMatching(/^PRACK/)];
const SIP_100 = [jasmine.stringMatching(/^SIP\/2.0 100/)];
const SIP_180 = [jasmine.stringMatching(/^SIP\/2.0 180/)];
const SIP_183 = [jasmine.stringMatching(/^SIP\/2.0 183/)];
const SIP_200 = [jasmine.stringMatching(/^SIP\/2.0 200/)];
const SIP_480 = [jasmine.stringMatching(/^SIP\/2.0 480/)];
const SIP_481 = [jasmine.stringMatching(/^SIP\/2.0 481/)];
const SIP_487 = [jasmine.stringMatching(/^SIP\/2.0 487/)];

function terminate(invitation: Invitation): Promise<void> {
  const session = invitation;
  switch (session.state) {
    case SessionState.Initial:
    case SessionState.Establishing:
      return session.reject();
    case SessionState.Established:
      return session.bye().then(() => {
        return;
      });
    case SessionState.Terminating:
    case SessionState.Terminated:
    default:
      return Promise.reject();
  }
}

/**
 * Session Integration Tests
 */

describe("API Session", () => {
  let alice: UserFake;
  let bob: UserFake;
  let target: URI;
  let inviter: Inviter;
  let inviterStateSpy: EmitterSpy<SessionState>;
  let invitation: Invitation;
  let invitationStateSpy: EmitterSpy<SessionState>;

  const invitationDelegateMock = jasmine.createSpyObj<Required<SessionDelegate>>("SessionDelegate", [
    "onAck",
    "onCancel"
  ]);

  const inviterRequestDelegateMock = jasmine.createSpyObj<Required<OutgoingRequestDelegate>>(
    "OutgoingRequestDelegate",
    ["onAccept", "onProgress", "onRedirect", "onReject", "onTrying"]
  );

  function bobAccept(): void {
    beforeEach(async () => {
      resetSpies();
      invitation.accept();
      await bob.transport.waitReceived(); // ACK
    });

    it("her ua should send ACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_ACK);
    });

    it("her ua should receive 200", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_200);
    });

    it("her request delegate should onAccept", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(1);
      expect(spy.onProgress).toHaveBeenCalledTimes(0);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(0);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });

    it("her session state should transition 'established'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Established]);
    });

    it("his session state should transition 'establishing', 'established'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
      expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
    });

    it("her dialog should be 'confirmed' and 'stable'", () => {
      const session = inviter.dialog;
      expect(session && session.sessionState).toBe(SessionDialogState.Confirmed);
      expect(session && session.signalingState).toBe(SignalingState.Stable);
    });

    it("his session delegate onAck", () => {
      const spy = invitationDelegateMock;
      expect(spy.onAck).toHaveBeenCalledTimes(1);
      expect(spy.onCancel).toHaveBeenCalledTimes(0);
    });

    it("his dialog should be 'confirmed' and 'stable'", () => {
      const session = invitation.dialog;
      expect(session && session.sessionState).toBe(SessionDialogState.Confirmed);
      expect(session && session.signalingState).toBe(SignalingState.Stable);
    });
  }

  function bobAccept2x(): void {
    let threw: boolean;

    beforeEach(async () => {
      threw = false;
      resetSpies();
      invitation.accept();
      invitation.accept().catch(() => {
        threw = true;
      });
      await bob.transport.waitReceived(); // ACK
    });

    it("her ua should send ACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_ACK);
    });

    it("her ua should receive 200", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_200);
    });

    it("her request delegate should onAccept", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(1);
      expect(spy.onProgress).toHaveBeenCalledTimes(0);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(0);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });

    it("her session state should transition 'established'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Established]);
    });

    it("his session state should transition 'establishing', 'established'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
      expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
    });

    it("his session delegate onAck", () => {
      const spy = invitationDelegateMock;
      expect(spy.onAck).toHaveBeenCalledTimes(1);
      expect(spy.onCancel).toHaveBeenCalledTimes(0);
    });

    it("her dialog should be 'confirmed' and 'stable'", () => {
      const session = inviter.dialog;
      expect(session && session.sessionState).toBe(SessionDialogState.Confirmed);
      expect(session && session.signalingState).toBe(SignalingState.Stable);
    });

    it("his dialog should be 'confirmed' and 'stable'", () => {
      const session = invitation.dialog;
      expect(session && session.sessionState).toBe(SessionDialogState.Confirmed);
      expect(session && session.signalingState).toBe(SignalingState.Stable);
    });

    it("her second accept() threw an error", () => {
      expect(threw).toBe(true);
    });
  }

  function bobAcceptTerminate(dropAcks: boolean): void {
    // The caller's UA MAY send a BYE for either confirmed or early dialogs,
    // and the callee's UA MAY send a BYE on confirmed dialogs, but MUST NOT
    // send a BYE on early dialogs. However, the callee's UA MUST NOT send a
    // BYE on a confirmed dialog until it has received an ACK for its 2xx
    // response or until the server transaction times out.
    // https://tools.ietf.org/html/rfc3261#section-15

    beforeEach(async () => {
      resetSpies();
      if (dropAcks) {
        bob.transportReceiveSpy.and.returnValue(Promise.resolve()); // drop messages
      }
      invitation.accept();
      await bob.transport.waitSent(); // wait till 2xx sent
      terminate(invitation); // must wait for ACK or timeout before sending BYE
      if (dropAcks) {
        await alice.transport.waitSent(); // wait for first ACK sent (it will not be received)
        await soon(Timers.TIMER_L - 2); // transaction timeout waiting for ACK
        await soon(1); // a tick to let the retranmissions get processed after the clock jump
        await soon(1); // and then send the BYE upon transaction timeout
      } else {
        await inviterStateSpy.wait(SessionState.Terminated);
      }
    });

    if (dropAcks) {
      it("her ua should send ACK (11x), 200", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(12);
        expect(spy.calls.all()[0].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[1].args).toEqual(SIP_ACK); // ACK retransmissions that get dropped
        expect(spy.calls.all()[2].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[3].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[4].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[5].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[6].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[7].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[8].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[9].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[10].args).toEqual(SIP_ACK);
        expect(spy.calls.all()[11].args).toEqual(SIP_200);
      });

      it("her ua should receive 200 (11x), BYE", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(12);
        expect(spy.calls.all()[0].args).toEqual(SIP_200);
        expect(spy.calls.all()[1].args).toEqual(SIP_200); // 200 retransmissions
        expect(spy.calls.all()[2].args).toEqual(SIP_200);
        expect(spy.calls.all()[3].args).toEqual(SIP_200);
        expect(spy.calls.all()[4].args).toEqual(SIP_200);
        expect(spy.calls.all()[5].args).toEqual(SIP_200);
        expect(spy.calls.all()[6].args).toEqual(SIP_200);
        expect(spy.calls.all()[7].args).toEqual(SIP_200);
        expect(spy.calls.all()[8].args).toEqual(SIP_200);
        expect(spy.calls.all()[9].args).toEqual(SIP_200);
        expect(spy.calls.all()[10].args).toEqual(SIP_200);
        expect(spy.calls.all()[11].args).toEqual(SIP_BYE);
      });
    } else {
      it("her ua should send ACK, 200", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
        expect(spy.calls.argsFor(1)).toEqual(SIP_200);
      });

      it("her ua should receive 200, BYE", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
      });

      it("her request delegate should onAccept", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(1);
        expect(spy.onProgress).toHaveBeenCalledTimes(0);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(0);
        expect(spy.onTrying).toHaveBeenCalledTimes(0);
      });
    }

    it("her session state should transition 'established', 'terminated'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Established]);
      expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
    });

    it("his session state should transition 'establishing', 'established', 'terminating', 'terminated'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(4);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
      expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
      expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminating]);
      expect(spy.calls.argsFor(3)).toEqual([SessionState.Terminated]);
    });

    it("his session delegate nothing", () => {
      const spy = invitationDelegateMock;
      expect(spy.onAck).toHaveBeenCalledTimes(0);
      expect(spy.onCancel).toHaveBeenCalledTimes(0);
    });
  }

  function bobProgress(): void {
    beforeEach(async () => {
      resetSpies();
      return invitation.progress();
    });

    it("her ua should receive 180", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_180);
    });

    it("her request delegate onProgress", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(0);
      expect(spy.onProgress).toHaveBeenCalledTimes(1);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(0);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });
  }

  function bobProgress183(): void {
    beforeEach(async () => {
      resetSpies();
      return invitation.progress({ statusCode: 183 });
    });

    it("her ua should receive 183", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_183);
    });

    it("her request delegate onProgress", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(0);
      expect(spy.onProgress).toHaveBeenCalledTimes(1);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(0);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });
  }

  function bobProgress2x(): void {
    beforeEach(async () => {
      resetSpies();
      invitation.progress();
      return invitation.progress();
    });

    it("her ua should receive 180, 180", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual(SIP_180);
      expect(spy.calls.argsFor(1)).toEqual(SIP_180);
    });

    it("her request delegate onProgress, onProgress", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(0);
      expect(spy.onProgress).toHaveBeenCalledTimes(2);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(0);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });
  }

  function bobProgressReliable(): void {
    beforeEach(async () => {
      resetSpies();
      invitation.progress({ rel100: true });
      await bob.transport.waitSent(); // 200 for PRACK
      await alice.transport.waitReceived(); // 200 for PRACK
    });

    it("her ua should receive 183", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual(SIP_183);
      expect(spy.calls.argsFor(1)).toEqual(SIP_200); // PRACK
    });

    it("her ua should send PRACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_PRACK);
    });

    it("her request delegate onProgress", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(0);
      expect(spy.onProgress).toHaveBeenCalledTimes(1);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(0);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });
  }

  function bobProgressReliable2x(): void {
    beforeEach(async () => {
      resetSpies();
      invitation.progress({ rel100: true });
      invitation.progress({ rel100: true }); // This one should be ignored as we are waiting on a PRACK.
      await bob.transport.waitSent(); // 200 for PRACK
      await alice.transport.waitReceived(); // 200 for PRACK
    });

    it("her ua should receive 183", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.calls.argsFor(0)).toEqual(SIP_183);
      expect(spy.calls.argsFor(1)).toEqual(SIP_200); // PRACK
    });

    it("her ua should send PRACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_PRACK);
    });

    it("her request delegate onProgress", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(0);
      expect(spy.onProgress).toHaveBeenCalledTimes(1);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(0);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });
  }

  function bobReject(): void {
    beforeEach(async () => {
      resetSpies();
      invitation.reject();
      await inviterStateSpy.wait(SessionState.Terminated);
    });

    it("her ua should send ACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_ACK);
    });

    it("her ua should receive 480", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_480);
    });

    it("her request delegate onReject", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(0);
      expect(spy.onProgress).toHaveBeenCalledTimes(0);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(1);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });

    it("her session state should transition 'terminated'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
    });

    it("his session state should transition 'terminated'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
    });

    it("his session delegate nothing", () => {
      const spy = invitationDelegateMock;
      expect(spy.onAck).toHaveBeenCalledTimes(0);
      expect(spy.onCancel).toHaveBeenCalledTimes(0);
    });
  }

  function bobReject2x(): void {
    let threw: boolean;

    beforeEach(async () => {
      threw = false;
      resetSpies();
      invitation.reject();
      invitation.reject().catch(() => {
        threw = true;
      });
      await inviterStateSpy.wait(SessionState.Terminated);
    });

    it("her ua should send ACK", () => {
      const spy = alice.transportSendSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_ACK);
    });

    it("her ua should receive 480", () => {
      const spy = alice.transportReceiveSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.mostRecent().args).toEqual(SIP_480);
    });

    it("her request delegate onReject", () => {
      const spy = inviterRequestDelegateMock;
      expect(spy.onAccept).toHaveBeenCalledTimes(0);
      expect(spy.onProgress).toHaveBeenCalledTimes(0);
      expect(spy.onRedirect).toHaveBeenCalledTimes(0);
      expect(spy.onReject).toHaveBeenCalledTimes(1);
      expect(spy.onTrying).toHaveBeenCalledTimes(0);
    });

    it("her session state should transition 'terminated'", () => {
      const spy = inviterStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
    });

    it("his session state should transition 'terminated'", () => {
      const spy = invitationStateSpy;
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
    });

    it("his session delegate nothing", () => {
      const spy = invitationDelegateMock;
      expect(spy.onAck).toHaveBeenCalledTimes(0);
      expect(spy.onCancel).toHaveBeenCalledTimes(0);
    });

    it("his second reject() threw an error", () => {
      expect(threw).toBe(true);
    });
  }

  function bobTerminate(bye = true): void {
    beforeEach(async () => {
      resetSpies();
      terminate(invitation);
      await inviterStateSpy.wait(SessionState.Terminated);
    });

    if (bye) {
      it("her ua should send 200", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_200);
      });

      it("her ua should receive BYE", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_BYE);
      });

      it("her session state should transition 'terminated'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });

      it("his session state should transition 'terminated'", () => {
        const spy = invitationStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });
    } else {
      it("her ua should send ACK", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_ACK);
      });

      it("her ua should receive 480", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_480);
      });

      it("her request delegate onReject", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(0);
        expect(spy.onProgress).toHaveBeenCalledTimes(0);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(1);
        expect(spy.onTrying).toHaveBeenCalledTimes(0);
      });

      it("her session state should transition 'terminated'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });

      it("his session state should transition 'terminated'", () => {
        const spy = invitationStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });
    }
  }

  function bobTerminate2x(bye = true): void {
    let threw: boolean;

    beforeEach(async () => {
      threw = false;
      resetSpies();
      terminate(invitation);
      terminate(invitation).catch(() => {
        threw = true;
      });
      await inviterStateSpy.wait(SessionState.Terminated);
    });

    if (bye) {
      it("her ua should send 200", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_200);
      });

      it("her ua should receive BYE", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_BYE);
      });

      it("her session state should transition 'terminated'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });

      it("his session state should transition 'terminated'", () => {
        const spy = invitationStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });

      it("her second terminate() threw an error", () => {
        expect(threw).toBe(true);
      });
    } else {
      it("her ua should send ACK", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_ACK);
      });

      it("her ua should receive 480", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_480);
      });

      it("her request delegate onReject", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(0);
        expect(spy.onProgress).toHaveBeenCalledTimes(0);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(1);
        expect(spy.onTrying).toHaveBeenCalledTimes(0);
      });

      it("her session state should transition 'terminated'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });

      it("his session state should transition 'terminated'", () => {
        const spy = invitationStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
      });

      it("her second terminate() threw an error", () => {
        expect(threw).toBe(true);
      });
    }
  }

  function inviteSuite(inviteWithoutSdp: boolean): void {
    it("her ua should send nothing", () => {
      expect(alice.transportSendSpy).not.toHaveBeenCalled();
    });

    it("her session state should not change", () => {
      expect(inviter.state).toBe(SessionState.Initial);
      expect(inviterStateSpy).not.toHaveBeenCalled();
    });

    describe("Alice invite(), cancel()", () => {
      beforeEach(async () => {
        resetSpies();
        inviter.invite().catch(() => {
          return;
        });
        inviter.cancel();
        await soon();
        await soon(); // need an extra promise resolution for tests to play out
        await soon(); // need an extra promise resolution for tests to play out
      });

      if (inviteWithoutSdp) {
        it("her ua should send INVITE, CANCEL, ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
          expect(spy.calls.argsFor(1)).toEqual(SIP_CANCEL);
          expect(spy.calls.argsFor(2)).toEqual(SIP_ACK);
        });

        it("her ua should receive 100, 180, 200, 487", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(4);
          expect(spy.calls.argsFor(0)).toEqual(SIP_100);
          expect(spy.calls.argsFor(1)).toEqual(SIP_180);
          expect(spy.calls.argsFor(2)).toEqual(SIP_200);
          expect(spy.calls.argsFor(3)).toEqual(SIP_487);
        });
      } else {
        it("her ua should send nothing", () => {
          expect(alice.transportSendSpy).not.toHaveBeenCalled();
        });
      }

      if (inviteWithoutSdp) {
        it("her session state should transition 'establishing', 'terminating', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminating]);
          expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
        });
      } else {
        it("her session state should transition 'terminating', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminating]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });
      }
    });

    describe("Alice invite(), send fails - Transport Error", () => {
      beforeEach(async () => {
        if (!(alice.userAgent.transport instanceof TransportFake)) {
          throw new Error("Transport not TransportFake");
        }
        alice.userAgent.transport.setConnected(false);
        resetSpies();
        return inviter.invite({ requestDelegate: inviterRequestDelegateMock });
      });

      afterEach(() => {
        if (!(alice.userAgent.transport instanceof TransportFake)) {
          throw new Error("Transport not TransportFake");
        }
        alice.userAgent.transport.setConnected(true);
      });

      it("her ua should send INVITE", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
      });

      it("her request delegate onReject", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(0);
        expect(spy.onProgress).toHaveBeenCalledTimes(0);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(1);
        expect(spy.onTrying).toHaveBeenCalledTimes(0);
      });

      it("her request delegate onReject should receive a 503 (faked)", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onReject.calls.argsFor(0)[0].message.statusCode).toEqual(503);
      });

      it("her session state should transition 'establishing', 'terminated'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
        expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
      });
    });

    describe("Alice invite(), no response - Request Timeout", () => {
      beforeEach(async () => {
        resetSpies();
        bob.transportReceiveSpy.and.returnValue(Promise.resolve()); // drop messages
        inviter.invite({ requestDelegate: inviterRequestDelegateMock });
        await alice.transport.waitSent();
        await soon(Timers.TIMER_B);
      });

      it("her ua should send INVITE", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
      });

      it("her request delegate onReject", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(0);
        expect(spy.onProgress).toHaveBeenCalledTimes(0);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(1);
        expect(spy.onTrying).toHaveBeenCalledTimes(0);
      });

      it("her request delegate onReject should receive a 408 (faked)", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onReject.calls.argsFor(0)[0].message.statusCode).toEqual(408);
      });

      it("her session state should transition 'establishing', 'terminated'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
        expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
      });
    });

    describe("Alice invite(), auto provisional disabled - 100 Trying only", () => {
      beforeEach(async () => {
        resetSpies();
        bob.userAgent.configuration.sendInitialProvisionalResponse = false;
        resetSpies();
        return inviter.invite({ requestDelegate: inviterRequestDelegateMock }).then(() => bob.transport.waitSent());
      });

      it("her ua should send INVITE", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_INVITE);
      });

      it("her ua should receive 100", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_100);
      });

      it("her request delegate onTyring", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(0);
        expect(spy.onProgress).toHaveBeenCalledTimes(0);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(0);
        expect(spy.onTrying).toHaveBeenCalledTimes(1);
      });

      it("her session state should transition 'establishing'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
      });
    });

    describe("Alice invite()", () => {
      beforeEach(async () => {
        resetSpies();
        return inviter.invite({ requestDelegate: inviterRequestDelegateMock }).then(() => bob.transport.waitSent());
      });

      it("her ua should send INVITE", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.mostRecent().args).toEqual(SIP_INVITE);
      });

      it("her ua should receive 100, 180", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_100);
        expect(spy.calls.argsFor(1)).toEqual(SIP_180);
      });

      it("her request delegate onTyring, onProgress", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(0);
        expect(spy.onProgress).toHaveBeenCalledTimes(1);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(0);
        expect(spy.onTrying).toHaveBeenCalledTimes(1);
      });

      it("her session state should transition 'establishing'", () => {
        const spy = inviterStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
      });

      describe("Alice cancel()", () => {
        beforeEach(async () => {
          resetSpies();
          inviter.cancel();
          await inviterStateSpy.wait(SessionState.Terminated);
        });

        it("her ua should send CANCEL, ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_CANCEL);
          expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        });

        it("her ua should receive 200, 487", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          expect(spy.calls.argsFor(1)).toEqual(SIP_487);
        });

        it("her request delegate onReject", () => {
          const spy = inviterRequestDelegateMock;
          expect(spy.onAccept).toHaveBeenCalledTimes(0);
          expect(spy.onProgress).toHaveBeenCalledTimes(0);
          expect(spy.onRedirect).toHaveBeenCalledTimes(0);
          expect(spy.onReject).toHaveBeenCalledTimes(1);
          expect(spy.onTrying).toHaveBeenCalledTimes(0);
        });

        it("her session state should transition 'terminating', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminating]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate onCancel", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(1);
        });
      });

      describe("Alice cancel(), Bob accept() - an async race condition (CANCEL wins)", () => {
        let logger: Logger;
        let acceptResolve: boolean;

        beforeEach(async () => {
          logger = invitation.userAgent.getLogger("sip.Invitation");
          acceptResolve = false;
          resetSpies();
          spyOn(logger, "error").and.callThrough();
          inviter.cancel();
          await invitation.accept().then(() => (acceptResolve = true));
        });

        it("his call to accept() should resolve and log an error", async () => {
          await soon();
          expect(acceptResolve).toBe(true);
          expect(logger.error).toHaveBeenCalled();
        });

        it("her ua should send CANCEL, ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_CANCEL);
          expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        });

        it("her ua should receive 200, 487", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          expect(spy.calls.argsFor(1)).toEqual(SIP_487);
        });

        it("her session state should transition 'terminating', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminating]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate onCancel", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(1);
        });
      });

      describe("Bob accept(), Alice cancel() - a network glare condition (200 wins)", () => {
        // FIXME: HACK: This test was a pain to make happen, but the case SHOULD be tested.
        // While accept() is called first, cancel() will get a CANCEL out before the 200 makes
        // it out first unless it is delayed. I didn't have a good hook to make it wait on after
        // the accept(), so I gave up after a while and just wrapped the cancel() in promise
        // resolutions until the 200 got sent before the CANCEL. On the flip side, if you wait
        // too long the 200 will get handled before cancel() is called. In any event, this should
        // be reworked so that it is deterministic instead of this fragile promise chain hack....
        beforeEach(async () => {
          resetSpies();
          invitation.accept();
          if (inviteWithoutSdp) {
            return Promise.resolve().then(() =>
              Promise.resolve().then(() => Promise.resolve().then(() => Promise.resolve().then(() => inviter.cancel())))
            );
          } else {
            return Promise.resolve().then(() =>
              Promise.resolve().then(() =>
                Promise.resolve().then(() =>
                  Promise.resolve().then(() =>
                    Promise.resolve().then(() => Promise.resolve().then(() => inviter.cancel()))
                  )
                )
              )
            );
          }
        });

        if (inviteWithoutSdp) {
          it("her ua should send CANCEL, ACK, BYE, 481", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(4);
            expect(spy.calls.argsFor(0)).toEqual(SIP_CANCEL);
            expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
            expect(spy.calls.argsFor(3)).toEqual(SIP_481);
          });

          it("her ua should receive 200, 200, BYE, 481", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(4);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200);
            expect(spy.calls.argsFor(1)).toEqual(SIP_200);
            expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
            expect(spy.calls.argsFor(3)).toEqual(SIP_481);
          });
        } else {
          it("her ua should send CANCEL, ACK, BYE", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_CANCEL);
            expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(2)).toEqual(SIP_BYE);
          });

          it("her ua should receive 200, 200, 200", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200);
            expect(spy.calls.argsFor(1)).toEqual(SIP_200);
            expect(spy.calls.argsFor(2)).toEqual(SIP_200);
          });
        }

        it("her session state should transition 'terminating', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminating]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'established', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
          expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate onAck", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(1);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });
      });

      // These only makes sense in INVITE with SDP case.
      if (inviteWithoutSdp) {
        describe("Bob accept(), 200 SDP get fails - SDH Error", () => {
          let acceptReject: boolean;

          beforeEach(async () => {
            acceptReject = false;
            resetSpies();
            {
              // Setup hacky thing to cause undefined body returned once
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              if (typeof (invitation as any).setupSessionDescriptionHandler !== "function") {
                throw new Error("setupSessionDescriptionHandler() undefined.");
              }
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (invitation as any).setupSessionDescriptionHandler();
              if (!invitation.sessionDescriptionHandler) {
                throw new Error("SDH undefined.");
              }
              const sdh = invitation.sessionDescriptionHandler as jasmine.SpyObj<SessionDescriptionHandler>;
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (sdh as any).getDescriptionRejectOnce = true;
            }
            await invitation.accept().catch(() => (acceptReject = true));
          });

          it("his call to accept() should reject", async () => {
            await soon();
            expect(acceptReject).toBe(true);
          });

          it("her ua should send ACK", () => {
            const spy = alice.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
          });

          it("her ua should receive 480", () => {
            const spy = alice.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual(SIP_480);
          });

          it("her request delegate should onReject", () => {
            const spy = inviterRequestDelegateMock;
            expect(spy.onAccept).toHaveBeenCalledTimes(0);
            expect(spy.onProgress).toHaveBeenCalledTimes(0);
            expect(spy.onRedirect).toHaveBeenCalledTimes(0);
            expect(spy.onReject).toHaveBeenCalledTimes(1);
            expect(spy.onTrying).toHaveBeenCalledTimes(0);
          });

          it("her session state should transition 'terminated'", () => {
            const spy = inviterStateSpy;
            expect(spy).toHaveBeenCalledTimes(1);
            expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
          });

          it("his session state should transition 'establishing', 'terminated'", () => {
            const spy = invitationStateSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
            expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
          });

          it("his session delegate nothing", () => {
            const spy = invitationDelegateMock;
            expect(spy.onAck).toHaveBeenCalledTimes(0);
            expect(spy.onCancel).toHaveBeenCalledTimes(0);
          });
        });
      }

      describe("Bob accept(), 200 has no SDP - Invalid 200", () => {
        beforeEach(async () => {
          resetSpies();
          {
            // Setup hacky thing to cause undefined body returned once
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            if (typeof (invitation as any).setupSessionDescriptionHandler !== "function") {
              throw new Error("setupSessionDescriptionHandler() undefined.");
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (invitation as any).setupSessionDescriptionHandler();
            if (!invitation.sessionDescriptionHandler) {
              throw new Error("SDH undefined.");
            }
            const sdh = invitation.sessionDescriptionHandler as jasmine.SpyObj<SessionDescriptionHandler>;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (sdh as any).getDescriptionUndefinedBodyOnce = true;
          }
          return invitation.accept().then(() => bob.transport.waitReceived());
        });

        it("her ua should send ACK, BYE, 481", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
          expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
          expect(spy.calls.argsFor(2)).toEqual(SIP_481);
        });

        it("her ua should receive 200, BYE, 481", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
          expect(spy.calls.argsFor(2)).toEqual(SIP_481);
        });

        it("her request delegate should onAccept", () => {
          const spy = inviterRequestDelegateMock;
          expect(spy.onAccept).toHaveBeenCalledTimes(1);
          expect(spy.onProgress).toHaveBeenCalledTimes(0);
          expect(spy.onRedirect).toHaveBeenCalledTimes(0);
          expect(spy.onReject).toHaveBeenCalledTimes(0);
          expect(spy.onTrying).toHaveBeenCalledTimes(0);
        });

        it("her session state should transition 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'established', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
          expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate onAck", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(1);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });

        it("her dialog should be 'terminated' and 'closed'", () => {
          const session = inviter.dialog;
          expect(session && session.sessionState).toBe(SessionDialogState.Terminated);
          expect(session && session.signalingState).toBe(SignalingState.Closed);
        });

        it("his dialog should be 'terminated' and 'closed'", () => {
          const session = invitation.dialog;
          expect(session && session.sessionState).toBe(SessionDialogState.Terminated);
          expect(session && session.signalingState).toBe(SignalingState.Closed);
        });
      });

      describe("Bob accept(), 200 SDP set fails - SDH Error", () => {
        beforeEach(async () => {
          resetSpies();
          {
            // Setup hacky thing to cause a rejection once
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            if (typeof (inviter as any).setupSessionDescriptionHandler !== "function") {
              throw new Error("setupSessionDescriptionHandler() undefined.");
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (inviter as any).setupSessionDescriptionHandler();
            if (!inviter.sessionDescriptionHandler) {
              throw new Error("SDH undefined.");
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (inviter.sessionDescriptionHandler as any).setDescriptionRejectOnce = true;
          }
          return invitation.accept().then(() => bob.transport.waitReceived()); // ACK
        });

        if (inviteWithoutSdp) {
          it("his ua should send 200, BYE, 481", () => {
            const spy = bob.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200);
            expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
            expect(spy.calls.argsFor(2)).toEqual(SIP_481);
          });

          it("his ua should receive ACK, BYE, 481", () => {
            const spy = bob.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
            expect(spy.calls.argsFor(2)).toEqual(SIP_481);
          });
        } else {
          it("his ua should send 200, 200", () => {
            const spy = bob.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200);
            expect(spy.calls.argsFor(1)).toEqual(SIP_200);
          });

          it("his ua should receive ACK, BYE", () => {
            const spy = bob.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
          });
        }

        it("her request delegate should onAccept", () => {
          const spy = inviterRequestDelegateMock;
          expect(spy.onAccept).toHaveBeenCalledTimes(1);
          expect(spy.onProgress).toHaveBeenCalledTimes(0);
          expect(spy.onRedirect).toHaveBeenCalledTimes(0);
          expect(spy.onReject).toHaveBeenCalledTimes(0);
          expect(spy.onTrying).toHaveBeenCalledTimes(0);
        });

        it("her session state should transition 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'established', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
          expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate onAck", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(1);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });

        it("her dialog should be 'terminated' and 'closed'", () => {
          const session = inviter.dialog;
          expect(session && session.sessionState).toBe(SessionDialogState.Terminated);
          expect(session && session.signalingState).toBe(SignalingState.Closed);
        });

        it("his dialog should be 'terminated' and 'closed'", () => {
          const session = invitation.dialog;
          expect(session && session.sessionState).toBe(SessionDialogState.Terminated);
          expect(session && session.signalingState).toBe(SignalingState.Closed);
        });
      });

      describe("Bob accept(), 200 send fails - Transport Error", () => {
        beforeEach(async () => {
          if (!(bob.userAgent.transport instanceof TransportFake)) {
            throw new Error("Transport not TransportFake");
          }
          bob.userAgent.transport.setConnected(false);
          resetSpies();
          return invitation.accept().then(() => soon(Timers.TIMER_H));
        });

        afterEach(() => {
          if (!(bob.userAgent.transport instanceof TransportFake)) {
            throw new Error("Transport not TransportFake");
          }
          bob.userAgent.transport.setConnected(true);
        });

        it("his ua should send 200, BYE", () => {
          const spy = bob.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(12); // 11 retransmissions of the 200
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          expect(spy.calls.argsFor(11)).toEqual(SIP_BYE);
        });

        it("his session state should transition 'establishing', 'established', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
          expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate nothing", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });
      });

      // These only makes sense in INVITE without SDP case.
      if (inviteWithoutSdp) {
        describe("Bob accept(), ACK has no SDP - Invalid ACK", () => {
          beforeEach(async () => {
            resetSpies();
            {
              // Setup hacky thing to cause undefined body returned once
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              if (typeof (inviter as any).setupSessionDescriptionHandler !== "function") {
                throw new Error("setupSessionDescriptionHandler() undefined.");
              }
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (inviter as any).setupSessionDescriptionHandler();
              if (!inviter.sessionDescriptionHandler) {
                throw new Error("SDH undefined.");
              }
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (inviter.sessionDescriptionHandler as any).getDescriptionUndefinedBodyOnce = true;
            }
            return invitation.accept().then(() => bob.transport.waitReceived()); // ACK
          });

          it("his ua should send 200, BYE", () => {
            const spy = bob.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200);
            expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
          });

          it("his session state should transition 'establishing', 'established', 'terminated'", () => {
            const spy = invitationStateSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
            expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
            expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
          });

          it("his session delegate onAck", () => {
            const spy = invitationDelegateMock;
            expect(spy.onAck).toHaveBeenCalledTimes(1);
            expect(spy.onCancel).toHaveBeenCalledTimes(0);
          });
        });

        describe("Bob accept(), ACK SDP set fails - SDH Error", () => {
          beforeEach(async () => {
            resetSpies();
            {
              // Setup hacky thing to cause a rejection once
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              if (typeof (invitation as any).setupSessionDescriptionHandler !== "function") {
                throw new Error("setupSessionDescriptionHandler() undefined.");
              }
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (invitation as any).setupSessionDescriptionHandler();
              if (!invitation.sessionDescriptionHandler) {
                throw new Error("SDH undefined.");
              }
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (invitation.sessionDescriptionHandler as any).setDescriptionRejectOnce = true;
            }
            return invitation
              .accept()
              .then(() => bob.transport.waitReceived()) // ACK
              .then(() => bob.transport.waitReceived()); // 200
          });

          it("his ua should send 200, BYE", () => {
            const spy = bob.transportSendSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_200);
            expect(spy.calls.argsFor(1)).toEqual(SIP_BYE);
          });

          it("his ua should receive ACK, 200", () => {
            const spy = bob.transportReceiveSpy;
            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
            expect(spy.calls.argsFor(1)).toEqual(SIP_200);
          });

          it("his session state should transition 'establishing', 'established', 'terminated'", () => {
            const spy = invitationStateSpy;
            expect(spy).toHaveBeenCalledTimes(3);
            expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
            expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
            expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
          });

          it("his session delegate onAck", () => {
            const spy = invitationDelegateMock;
            expect(spy.onAck).toHaveBeenCalledTimes(1);
            expect(spy.onCancel).toHaveBeenCalledTimes(0);
          });
        });
      }

      describe("Bob accept(), ACK send fails - Transport Error", () => {
        beforeEach(async () => {
          if (!(alice.userAgent.transport instanceof TransportFake)) {
            throw new Error("Transport not TransportFake");
          }
          alice.userAgent.transport.setConnected(false);
          resetSpies();
          return invitation
            .accept()
            .then(() => alice.transport.waitSent()) // ACK
            .then(() => soon(Timers.TIMER_L));
        });

        afterEach(() => {
          if (!(alice.userAgent.transport instanceof TransportFake)) {
            throw new Error("Transport not TransportFake");
          }
          alice.userAgent.transport.setConnected(true);
        });

        it("his ua should send 200, BYE", () => {
          const spy = bob.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(12); // 11 retransmissions of the 200
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          expect(spy.calls.argsFor(11)).toEqual(SIP_BYE);
        });

        it("her session state should transition 'established', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Established]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'established', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
          expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate nothing", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });
      });

      describe("Bob accept(), ACK never arrives - Request Timeout", () => {
        beforeEach(async () => {
          resetSpies();
          alice.transportReceiveSpy.and.returnValue(Promise.resolve()); // drop messages
          return invitation.accept().then(() => soon(Timers.TIMER_L));
        });

        it("his ua should send 200, BYE", () => {
          const spy = bob.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(12); // 10 retransmissions of the 200
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          expect(spy.calls.argsFor(11)).toEqual(SIP_BYE);
        });

        it("his session state should transition 'establishing', 'established', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Established]);
          expect(spy.calls.argsFor(2)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate nothing", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });
      });

      describe("Bob reject(), ACK send fails - Transport Error", () => {
        beforeEach(async () => {
          if (!(alice.userAgent.transport instanceof TransportFake)) {
            throw new Error("Transport not TransportFake");
          }
          alice.userAgent.transport.setConnected(false);
          resetSpies();
          return invitation
            .reject()
            .then(() => alice.transport.waitSent()) // ACK
            .then(() => soon(Timers.TIMER_H));
        });

        afterEach(() => {
          if (!(alice.userAgent.transport instanceof TransportFake)) {
            throw new Error("Transport not TransportFake");
          }
          alice.userAgent.transport.setConnected(true);
        });

        it("his ua should send 480", () => {
          const spy = bob.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_480);
        });

        it("her session state should transition 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate nothing", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });
      });

      describe("Bob nothing - no answer timeout", () => {
        beforeEach(async () => {
          resetSpies();
          const noAnswerTimeout = 90000;
          if (alice.userAgent.configuration.noAnswerTimeout * 1000 !== noAnswerTimeout) {
            throw new Error("Test is assuming UA configured with 90 second no answer timeout");
          }
          await soon(noAnswerTimeout);
        });

        it("her ua should send ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
        });

        it("her ua should receive 180, 480", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_180); // provisional resend timer generates this at 60 sec
          expect(spy.calls.argsFor(1)).toEqual(SIP_480);
        });

        it("her request delegate onProgress, onReject", () => {
          const spy = inviterRequestDelegateMock;
          expect(spy.onAccept).toHaveBeenCalledTimes(0);
          expect(spy.onProgress).toHaveBeenCalledTimes(1);
          expect(spy.onRedirect).toHaveBeenCalledTimes(0);
          expect(spy.onReject).toHaveBeenCalledTimes(1);
          expect(spy.onTrying).toHaveBeenCalledTimes(0);
        });

        it("her session state should transition 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
        });
      });

      describe("Bob accept()", () => {
        bobAccept();

        describe("Bob terminate()", () => {
          bobTerminate();
        });

        describe("Bob terminate(), terminate()", () => {
          bobTerminate2x();
        });
      });

      describe("Bob accept(), accept()", () => {
        if (inviteWithoutSdp) {
          bobAccept();
        } else {
          bobAccept2x();
        }
      });

      describe("Bob progress(), Alice cancel(), Bob accept() - an async race condition (CANCEL wins)", () => {
        let logger: Logger;
        let progressResolve: boolean;
        let acceptResolve: boolean;

        beforeEach(async () => {
          progressResolve = false;
          acceptResolve = false;
          logger = invitation.userAgent.getLogger("sip.Invitation");
          resetSpies();
          spyOn(logger, "error").and.callThrough();
          invitation.progress().then(() => (progressResolve = true));
          inviter.cancel();
          await invitation.accept().then(() => (acceptResolve = true));
          // await invitationStateSpy.wait(SessionState.Terminated);
          // await soon();
        });

        it("his call to progress(), accept() should resolve and log an error", () => {
          expect(progressResolve).toBe(true);
          expect(acceptResolve).toBe(true);
          expect(logger.error).toHaveBeenCalled();
        });

        it("her ua should send CANCEL, ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_CANCEL);
          expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        });

        it("her ua should receive 180, 200, 487", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual(SIP_180);
          expect(spy.calls.argsFor(1)).toEqual(SIP_200);
          expect(spy.calls.argsFor(2)).toEqual(SIP_487);
        });

        it("her session state should transition 'terminating', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminating]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate onCancel", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(1);
        });
      });

      describe("Bob progress(reliable), Alice cancel(), Bob accept() - an async race condition (CANCEL wins)", () => {
        let logger: Logger;
        let progressResolve: boolean;
        let acceptResolve: boolean;

        beforeEach(async () => {
          logger = invitation.userAgent.getLogger("sip.Invitation");
          progressResolve = false;
          acceptResolve = false;
          resetSpies();
          spyOn(logger, "error").and.callThrough();
          invitation.progress({ rel100: true }).then(() => (progressResolve = true));
          inviter.cancel();
          await invitation.accept().then(() => (acceptResolve = true));
        });

        it("his call to progress(), accept() should resolve and log an error", async () => {
          await soon();
          expect(progressResolve).toBe(true);
          expect(acceptResolve).toBe(true);
          expect(logger.error).toHaveBeenCalled();
        });

        it("her ua should send CANCEL, ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_CANCEL);
          expect(spy.calls.argsFor(1)).toEqual(SIP_ACK);
        });

        it("her ua should receive 200, 487", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
          expect(spy.calls.argsFor(1)).toEqual(SIP_487);
        });

        it("her session state should transition 'terminating', 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminating]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate onCancel", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(1);
        });
      });

      describe("Bob progress(reliable), Bob accept(), Bob dispose() - an async race condition (dispose wins)", () => {
        let logger: Logger;
        let progressReject: boolean;
        let acceptReject: boolean;

        beforeEach(async () => {
          logger = invitation.userAgent.getLogger("sip.Invitation");
          progressReject = false;
          acceptReject = false;
          resetSpies();
          spyOn(logger, "error").and.callThrough();
          invitation.progress({ rel100: true }).catch(() => (progressReject = true));
          invitation.accept().catch(() => (acceptReject = true));
          await invitation.dispose();
          await soon(); // need an extra promise resolution for tests to play out
          await soon(); // need an extra promise resolution for tests to play out
          await soon(); // need an extra promise resolution for tests to play out
        });

        it("his call to progress(), accept() should reject", () => {
          expect(progressReject).toBe(true);
          expect(acceptReject).toBe(true);
        });

        it("her ua should send ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_ACK);
        });

        it("her ua should receive 480", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_480);
        });

        it("her session state should transition 'terminated'", () => {
          const spy = inviterStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Terminated]);
        });

        it("his session state should transition 'establishing', 'terminated'", () => {
          const spy = invitationStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([SessionState.Establishing]);
          expect(spy.calls.argsFor(1)).toEqual([SessionState.Terminated]);
        });

        it("his session delegate nothing", () => {
          const spy = invitationDelegateMock;
          expect(spy.onAck).toHaveBeenCalledTimes(0);
          expect(spy.onCancel).toHaveBeenCalledTimes(0);
        });
      });

      describe("Bob progress()", () => {
        bobProgress();

        describe("Bob accept()", () => {
          bobAccept();
        });

        describe("Bob reject()", () => {
          bobReject();
        });

        describe("Bob progress()", () => {
          bobProgress();

          describe("Bob accept()", () => {
            bobAccept();
          });

          describe("Bob reject()", () => {
            bobReject();
          });
        });
      });

      // Sending offer in unreliable provisional not legal,
      // but should still write test for that case. Punting...
      if (!inviteWithoutSdp) {
        describe("Bob progress(183)", () => {
          bobProgress183();

          describe("Bob accept()", () => {
            bobAccept();
          });

          describe("Bob reject()", () => {
            bobReject();
          });

          describe("Bob progress()", () => {
            bobProgress();

            describe("Bob accept()", () => {
              bobAccept();
            });

            describe("Bob reject()", () => {
              bobReject();
            });
          });
        });
      }

      describe("Bob progress(reliable)", () => {
        bobProgressReliable();

        describe("Bob accept()", () => {
          bobAccept();
        });

        describe("Bob reject()", () => {
          bobReject();
        });

        describe("Bob progress(reliable) ", () => {
          bobProgressReliable();

          describe("Bob accept()", () => {
            bobAccept();
          });

          describe("Bob reject()", () => {
            bobReject();
          });

          describe("Bob progress(reliable) ", () => {
            bobProgressReliable();

            describe("Bob accept()", () => {
              bobAccept();
            });

            describe("Bob reject()", () => {
              bobReject();
            });
          });
        });

        describe("Bob progress()", () => {
          bobProgress();

          describe("Bob accept()", () => {
            bobAccept();
          });

          describe("Bob reject()", () => {
            bobReject();
          });

          describe("Bob progress(reliable) ", () => {
            bobProgressReliable();

            describe("Bob accept()", () => {
              bobAccept();
            });

            describe("Bob reject()", () => {
              bobReject();
            });

            describe("Bob progress(reliable) ", () => {
              bobProgressReliable();

              describe("Bob accept()", () => {
                bobAccept();
              });

              describe("Bob reject()", () => {
                bobReject();
              });
            });
          });
        });
      });

      describe("Bob progress(), progress()", () => {
        bobProgress2x();
      });

      describe("Bob progress(reliable), progress(reliable)", () => {
        bobProgressReliable2x();
      });

      describe("Bob reject()", () => {
        bobReject();
      });

      describe("Bob reject(), reject()", () => {
        bobReject2x();
      });

      describe("Bob terminate()", () => {
        bobTerminate(false);
      });

      describe("Bob terminate(), terminate()", () => {
        bobTerminate2x(false);
      });

      describe("Bob accept(), terminate()", () => {
        bobAcceptTerminate(false);
      });

      describe("Bob accept(), terminate(), no ACK - transaction timeout", () => {
        bobAcceptTerminate(true);
      });
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
    invitationDelegateMock.onAck.calls.reset();
    invitationDelegateMock.onCancel.calls.reset();
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

  describe("Alice constructs a new INVITE targeting Bob with SDP offer", () => {
    beforeEach(async () => {
      target = bob.uri;
      bob.userAgent.delegate = {
        onInvite: (session): void => {
          invitation = session;
          invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
          invitation.delegate = invitationDelegateMock;
        }
      };
      inviter = new Inviter(alice.userAgent, target);
      inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
      await soon();
    });

    inviteSuite(false);
  });

  describe("Alice constructs a new INVITE targeting Bob without SDP offer", () => {
    beforeEach(async () => {
      target = bob.uri;
      bob.userAgent.delegate = {
        onInvite: (session): void => {
          invitation = session;
          invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
          invitation.delegate = invitationDelegateMock;
        }
      };
      inviter = new Inviter(alice.userAgent, target, { inviteWithoutSdp: true });
      inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
      await soon();
    });

    inviteSuite(true);
  });

  describe("Early Media Disabled...", () => {
    beforeEach(async () => {
      target = bob.uri;
      bob.userAgent.delegate = {
        onInvite: (session): void => {
          invitation = session;
          invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
        }
      };
      inviter = new Inviter(alice.userAgent, target, { earlyMedia: false });
      inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
      await soon();
    });

    describe("Alice invite()", () => {
      beforeEach(() => {
        resetSpies();
        return inviter.invite().then(() => bob.transport.waitSent());
      });

      it("her inviter sdh should have called get description once", () => {
        const sdh = inviter.sessionDescriptionHandler;
        if (!sdh) {
          fail("Inviter SDH undefined.");
          return;
        }
        expect(sdh.getDescription).toHaveBeenCalledTimes(1);
        expect(sdh.setDescription).toHaveBeenCalledTimes(0);
      });

      describe("Bob progress(183)", () => {
        beforeEach(() => {
          resetSpies();
          return invitation.progress({ statusCode: 183 });
        });

        it("her inviter sdh should have called get description once", () => {
          const sdh = inviter.sessionDescriptionHandler;
          if (!sdh) {
            fail("Inviter SDH undefined.");
            return;
          }
          expect(sdh.getDescription).toHaveBeenCalledTimes(1);
          expect(sdh.setDescription).toHaveBeenCalledTimes(0);
        });

        describe("Bob accept()", () => {
          beforeEach(() => {
            resetSpies();
            return invitation.accept().then(() => bob.transport.waitReceived());
          });

          it("her inviter sdh should have called get & set description once", () => {
            const sdh = inviter.sessionDescriptionHandler;
            if (!sdh) {
              fail("Inviter SDH undefined.");
              return;
            }
            expect(sdh.getDescription).toHaveBeenCalledTimes(1);
            expect(sdh.setDescription).toHaveBeenCalledTimes(1);
          });
        });

        describe("Bob progress(183)", () => {
          beforeEach(() => {
            resetSpies();
            return invitation.progress({ statusCode: 183 });
          });

          it("her inviter sdh should have called get description once", () => {
            const sdh = inviter.sessionDescriptionHandler;
            if (!sdh) {
              fail("Inviter SDH undefined.");
              return;
            }
            expect(sdh.getDescription).toHaveBeenCalledTimes(1);
            expect(sdh.setDescription).toHaveBeenCalledTimes(0);
          });

          describe("Bob accept()", () => {
            beforeEach(() => {
              resetSpies();
              return invitation.accept().then(() => bob.transport.waitReceived());
            });

            it("her inviter sdh should have called get & set description once", () => {
              const sdh = inviter.sessionDescriptionHandler;
              if (!sdh) {
                fail("Inviter SDH undefined.");
                return;
              }
              expect(sdh.getDescription).toHaveBeenCalledTimes(1);
              expect(sdh.setDescription).toHaveBeenCalledTimes(1);
            });
          });
        });
      });
    });
  });

  describe("Early Media Enabled...", () => {
    beforeEach(async () => {
      target = bob.uri;
      bob.userAgent.delegate = {
        onInvite: (session): void => {
          invitation = session;
          invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
        }
      };
      inviter = new Inviter(alice.userAgent, target, { earlyMedia: true });
      inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
      await soon();
    });

    describe("Alice invite()", () => {
      beforeEach(() => {
        resetSpies();
        return inviter.invite().then(() => bob.transport.waitSent());
      });

      it("her inviter sdh should have called get description once", () => {
        const sdh = inviter.sessionDescriptionHandler;
        if (!sdh) {
          fail("Inviter SDH undefined.");
          return;
        }
        expect(sdh.getDescription).toHaveBeenCalledTimes(1);
        expect(sdh.setDescription).toHaveBeenCalledTimes(0);
      });

      describe("Bob progress(183)", () => {
        beforeEach(() => {
          resetSpies();
          return invitation.progress({ statusCode: 183 });
        });

        it("her inviter sdh should have called get & set description once", () => {
          const sdh = inviter.sessionDescriptionHandler;
          if (!sdh) {
            fail("Inviter SDH undefined.");
            return;
          }
          expect(sdh.getDescription).toHaveBeenCalledTimes(1);
          expect(sdh.setDescription).toHaveBeenCalledTimes(1);
        });

        describe("Bob accept()", () => {
          beforeEach(async () => {
            resetSpies();
            invitation.accept();
            await bob.transport.waitReceived();
          });

          it("her inviter sdh should have called get & set description once", () => {
            const sdh = inviter.sessionDescriptionHandler;
            if (!sdh) {
              fail("Inviter SDH undefined.");
              return;
            }
            expect(sdh.getDescription).toHaveBeenCalledTimes(1);
            expect(sdh.setDescription).toHaveBeenCalledTimes(1);
          });
        });

        describe("Bob progress(183)", () => {
          beforeEach(() => {
            resetSpies();
            return invitation.progress({ statusCode: 183 });
          });

          it("her inviter sdh should have called get & set description once", () => {
            const sdh = inviter.sessionDescriptionHandler;
            if (!sdh) {
              fail("Inviter SDH undefined.");
              return;
            }
            expect(sdh.getDescription).toHaveBeenCalledTimes(1);
            expect(sdh.setDescription).toHaveBeenCalledTimes(1);
          });

          describe("Bob accept()", () => {
            beforeEach(() => {
              resetSpies();
              invitation.accept();
              return bob.transport.waitReceived();
            });

            it("her inviter sdh should have called get & set description once", () => {
              const sdh = inviter.sessionDescriptionHandler;
              if (!sdh) {
                fail("Inviter SDH undefined.");
                return;
              }
              expect(sdh.getDescription).toHaveBeenCalledTimes(1);
              expect(sdh.setDescription).toHaveBeenCalledTimes(1);
            });
          });
        });
      });
    });
  });

  describe("Forking...", () => {
    let bob2: UserFake;
    let invitation2: Invitation;
    let invitationStateSpy2: EmitterSpy<SessionState>;

    function bobsAccept(answerInAck: boolean): void {
      const SIP_ACK_OR_BYE = [jasmine.stringMatching(/^ACK|^BYE/)];

      beforeEach(async () => {
        resetSpies2();
        invitation.accept();
        invitation2.accept();
        await inviterStateSpy.wait(SessionState.Established);
      });

      if (answerInAck) {
        it("her ua should send ACK, BYE, ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(4);
          expect(spy.calls.argsFor(0)).toEqual(SIP_ACK_OR_BYE);
          expect(spy.calls.argsFor(1)).toEqual(SIP_ACK_OR_BYE);
          // expect(spy.calls.argsFor(2)).toEqual(SIP_487);
          expect(spy.calls.argsFor(3)).toEqual(SIP_ACK_OR_BYE);
        });
      } else {
        it("her ua should send ACK, BYE, ACK", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(3);
          expect(spy.calls.argsFor(0)).toEqual(SIP_ACK_OR_BYE);
          expect(spy.calls.argsFor(1)).toEqual(SIP_ACK_OR_BYE);
          expect(spy.calls.argsFor(2)).toEqual(SIP_ACK_OR_BYE);
        });
      }

      it("her session should be 'confirmed' and 'stable'", () => {
        const session = inviter.dialog;
        expect(session && session.sessionState).toBe(SessionDialogState.Confirmed);
        expect(session && session.signalingState).toBe(SignalingState.Stable);
      });
    }

    function bobsProgressReliable(): void {
      beforeEach(async () => {
        resetSpies2();
        invitation.progress({ rel100: true });
        invitation2.progress({ rel100: true });
        await bob.transport.waitSent(); // 200 for PRACK
        await alice.transport.waitReceived(); // 200 for PRACK
      });

      it("her ua should send PRACK, PRACK", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_PRACK);
        expect(spy.calls.argsFor(1)).toEqual(SIP_PRACK);
      });

      it("her request delegate onProgress, onProgress", () => {
        const spy = inviterRequestDelegateMock;
        expect(spy.onAccept).toHaveBeenCalledTimes(0);
        expect(spy.onProgress).toHaveBeenCalledTimes(2);
        expect(spy.onRedirect).toHaveBeenCalledTimes(0);
        expect(spy.onReject).toHaveBeenCalledTimes(0);
        expect(spy.onTrying).toHaveBeenCalledTimes(0);
      });
    }

    function inviteSuiteFork(inviteWithoutSdp: boolean): void {
      it("her ua should send nothing", () => {
        expect(alice.transportSendSpy).not.toHaveBeenCalled();
      });

      describe("Alice invite() fork", () => {
        beforeEach(async () => {
          resetSpies2();
          inviter.invite({ requestDelegate: inviterRequestDelegateMock });
          await bob.transport.waitSent();
          await soon(); // need an extra promise resolution for tests to play out
        });

        it("her ua should send INVITE", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.mostRecent().args).toEqual(SIP_INVITE);
        });

        it("her ua should receive 100, 180", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(4);
          expect(spy.calls.argsFor(0)).toEqual(SIP_100);
          expect(spy.calls.argsFor(1)).toEqual(SIP_180);
          expect(spy.calls.argsFor(2)).toEqual(SIP_100);
          expect(spy.calls.argsFor(3)).toEqual(SIP_180);
        });

        it("her request delegate onTrying, onProgress", () => {
          const spy = inviterRequestDelegateMock;
          expect(spy.onAccept).toHaveBeenCalledTimes(0);
          expect(spy.onProgress).toHaveBeenCalledTimes(2);
          expect(spy.onRedirect).toHaveBeenCalledTimes(0);
          expect(spy.onReject).toHaveBeenCalledTimes(0);
          expect(spy.onTrying).toHaveBeenCalledTimes(2);
        });

        describe("Bob & Bob2 accept()", () => {
          if (inviteWithoutSdp) {
            bobsAccept(true);
          } else {
            bobsAccept(false);
          }
        });

        describe("Bob & Bob2 progress(reliable)", () => {
          bobsProgressReliable();

          describe("Bob & Bob2 accept()", () => {
            bobsAccept(false);
          });
        });
      });
    }

    function resetSpies2(): void {
      resetSpies();
      bob2.transportReceiveSpy.calls.reset();
      bob2.transportSendSpy.calls.reset();
      if (invitationStateSpy2) {
        invitationStateSpy2.calls.reset();
      }
    }

    beforeEach(async () => {
      bob2 = await makeUserFake("bob", "example.com", "Bob2");
      connectUserFake(alice, bob2);
    });

    afterEach(async () => {
      return bob2.userAgent.stop().then(() => expect(bob2.isShutdown()).toBe(true));
    });

    describe("Alice constructs a new INVITE targeting 2 Bobs with SDP offer", () => {
      beforeEach(async () => {
        target = bob.uri;
        bob.userAgent.delegate = {
          onInvite: (session): void => {
            invitation = session;
            invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
          }
        };
        bob2.userAgent.delegate = {
          onInvite: (session): void => {
            invitation2 = session;
            invitationStateSpy2 = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob2"));
          }
        };
        inviter = new Inviter(alice.userAgent, target);
        inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
        await soon();
      });

      inviteSuiteFork(false);
    });

    describe("Alice constructs a new INVITE targeting 2 Bobs without SDP offer", () => {
      beforeEach(async () => {
        target = bob.uri;
        bob.userAgent.delegate = {
          onInvite: (session): void => {
            invitation = session;
            invitationStateSpy = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob"));
          }
        };
        bob2.userAgent.delegate = {
          onInvite: (session): void => {
            invitation2 = session;
            invitationStateSpy2 = makeEmitterSpy(invitation.stateChange, bob.userAgent.getLogger("Bob2"));
          }
        };
        inviter = new Inviter(alice.userAgent, target, { inviteWithoutSdp: true });
        inviterStateSpy = makeEmitterSpy(inviter.stateChange, alice.userAgent.getLogger("Alice"));
        await soon();
      });

      inviteSuiteFork(true);
    });
  });
});
