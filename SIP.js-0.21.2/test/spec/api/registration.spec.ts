import {
  Registerer,
  RegistererRegisterOptions,
  RegistererState,
  RegistererUnregisterOptions
} from "../../../lib/api/index.js";
import { Timers } from "../../../lib/core/index.js";
import { EmitterSpy, makeEmitterSpy } from "../../support/api/emitter-spy.js";
import { TransportFake } from "../../support/api/transport-fake.js";
import { connectUserFake, makeUserFake, UserFake } from "../../support/api/user-fake.js";
import { soon } from "../../support/api/utils.js";

const SIP_REGISTER = [jasmine.stringMatching(/^REGISTER/)];

const SIP_200 = [jasmine.stringMatching(/^SIP\/2.0 200/)];
const SIP_423 = [jasmine.stringMatching(/^SIP\/2.0 423/)];
const SIP_500 = [jasmine.stringMatching(/^SIP\/2.0 500/)];
const SIP_503 = [jasmine.stringMatching(/^SIP\/2.0 503/)];

/**
 * Registration Integration Tests
 */

describe("API Registration", () => {
  let alice: UserFake;
  let registrar: UserFake;
  let registerer: Registerer;
  let registererStateSpy: EmitterSpy<RegistererState>;

  function resetSpies(): void {
    alice.transportReceiveSpy.calls.reset();
    alice.transportSendSpy.calls.reset();
    registererStateSpy.calls.reset();
  }

  beforeEach(async () => {
    jasmine.clock().install();
    alice = await makeUserFake("alice", "example.com", "Alice");
    registrar = await makeUserFake(undefined, "example.com", "Registrar");
    connectUserFake(alice, registrar);
  });

  afterEach(async () => {
    return alice.userAgent
      .stop()
      .then(() => expect(alice.isShutdown()).toBe(true))
      .then(() => registrar.userAgent.stop())
      .then(() => expect(registrar.isShutdown()).toBe(true))
      .then(() => jasmine.clock().uninstall());
  });

  describe("Alice constructs a new Registerer", () => {
    beforeEach(async () => {
      registerer = new Registerer(alice.userAgent);
      registererStateSpy = makeEmitterSpy(registerer.stateChange, alice.userAgent.getLogger("Alice"));
      await soon();
    });

    it("her ua should send nothing", () => {
      expect(alice.transportSendSpy).not.toHaveBeenCalled();
    });

    it("her registerer state should not change", () => {
      expect(registerer.state).toBe(RegistererState.Initial);
      expect(registererStateSpy).not.toHaveBeenCalled();
    });

    describe("Alice dispose()", () => {
      beforeEach(async () => {
        resetSpies();
        return registerer.dispose();
      });

      it("her ua should send nothing", () => {
        expect(alice.transportSendSpy).not.toHaveBeenCalled();
      });

      it("her registerer state should transition 'terminated'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Terminated]);
      });

      it("her registerer should throw if register called", () => {
        expect(() => registerer.register()).toThrow();
      });

      it("her registerer should throw if unregister called", () => {
        expect(() => registerer.unregister()).toThrow();
      });
    });

    describe("Alice dispose(), dispose()", () => {
      beforeEach(() => {
        resetSpies();
        registerer.dispose();
        registerer.dispose();
      });

      it("her ua should send nothing", () => {
        expect(alice.transportSendSpy).not.toHaveBeenCalled();
      });

      it("her registerer state should transition 'terminated'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Terminated]);
      });
    });

    describe("Alice unregister()", () => {
      let statusCode: number | undefined;

      beforeEach(async () => {
        statusCode = undefined;
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            const contact = request.message.parseHeader("contact");
            expect(contact).toBeDefined();
            const expires = contact.getParam("expires");
            expect(expires).toEqual("0");
            request.accept();
          }
        };
        const options: RegistererUnregisterOptions = {
          requestDelegate: {
            onAccept: (response): void => {
              statusCode = response.message.statusCode;
            }
          }
        };
        registerer.unregister(options);
        await alice.transport.waitReceived();
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(statusCode).toEqual(200);
      });

      it("her registerer state should transition 'unregistered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
      });

      describe("Alice dispose()", () => {
        beforeEach(async () => {
          resetSpies();
          return registerer.dispose();
        });

        it("her ua should send nothing", () => {
          expect(alice.transportSendSpy).not.toHaveBeenCalled();
        });

        it("her registerer state should transition 'terminated'", () => {
          const spy = registererStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([RegistererState.Terminated]);
        });
      });
    });

    // TODO: Parser doesn't handle '*' currently
    xdescribe("Alice unregister() ALL", () => {
      beforeEach(async () => {
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            const contact = request.message.parseHeader("contact");
            expect(contact).toEqual("*");
            const expires = request.message.parseHeader("expires");
            expect(expires).toEqual("0");
            request.accept();
          }
        };
        registerer.unregister({
          all: true
        });
        await alice.transport.waitReceived(); // 200
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
      });

      it("her registerer state should transition 'unregistered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
      });
    });

    describe("Alice unregister(), dispose()", () => {
      beforeEach(async () => {
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            request.accept();
          }
        };
        registerer.unregister();
        registerer.dispose();
        await alice.transport.waitReceived(); // 200
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
      });
    });

    describe("Alice unregister(), unregister()", () => {
      let threw: boolean;

      beforeEach(async () => {
        threw = false;
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            request.accept();
          }
        };
        registerer.unregister();
        registerer.unregister().catch(() => {
          threw = true;
        });
        await alice.transport.waitReceived(); // 200
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
      });

      it("her second unregister() should throw an error", () => {
        expect(threw).toBe(true);
      });
    });

    describe("Alice unregister(), send fails - Transport Error", () => {
      let statusCode: number | undefined;

      beforeEach(async () => {
        if (!(alice.userAgent.transport instanceof TransportFake)) {
          throw new Error("Transport not TransportFake");
        }
        alice.userAgent.transport.setConnected(false);
        statusCode = undefined;
        resetSpies();
        const options: RegistererUnregisterOptions = {
          requestDelegate: {
            onReject: (response): void => {
              statusCode = response.message.statusCode;
            }
          }
        };
        return registerer.unregister(options);
      });

      afterEach(() => {
        if (!(alice.userAgent.transport instanceof TransportFake)) {
          throw new Error("Transport not TransportFake");
        }
        alice.userAgent.transport.setConnected(true);
      });

      it("her ua should send REGISTER and receive a 503 (faked)", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        expect(statusCode).toEqual(503);
      });

      it("her registerer state should transition 'unregistered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
      });
    });

    describe("Alice unregister(), no response - Request Timeout", () => {
      let statusCode: number | undefined;

      beforeEach(async () => {
        resetSpies();
        statusCode = undefined;
        registrar.userAgent.delegate = {
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          onRegisterRequest: (request): void => {
            return;
          }
        };
        const options: RegistererUnregisterOptions = {
          requestDelegate: {
            onReject: (response): void => {
              statusCode = response.message.statusCode;
            }
          }
        };
        return registerer.unregister(options);
      });

      it("her ua should send REGISTER and receive a 408 (faked)", async () => {
        await soon(Timers.TIMER_F + 1);
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        expect(statusCode).toEqual(408);
      });

      it("her registerer state should transition 'unregistered'", async () => {
        await soon(Timers.TIMER_F + 1);
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
      });
    });

    describe("Alice register()", () => {
      let cseq: number;
      let expires: string;
      let statusCode: number | undefined;

      beforeEach(async () => {
        statusCode = undefined;
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            const contact = request.message.parseHeader("contact");
            expect(contact).toBeDefined();
            cseq = request.message.cseq;
            expires = contact.getParam("expires");
            expect(expires).toBeDefined();
            request.accept({
              extraHeaders: [`Contact: ${contact}`],
              statusCode: 200
            });
          }
        };
        const options: RegistererRegisterOptions = {
          requestDelegate: {
            onAccept: (response): void => {
              statusCode = response.message.statusCode;
            }
          }
        };
        registerer.register(options);
        await alice.transport.waitReceived();
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(statusCode).toEqual(200);
      });

      it("her registerer state should transition 'registered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Registered]);
      });

      describe("Alice dispose()", () => {
        beforeEach(async () => {
          resetSpies();
          registerer.dispose();
          await alice.transport.waitReceived();
        });

        it("her ua should send REGISTER", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        });

        it("her ua should receive 200", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        });

        it("her registerer state should transition 'unregistered', 'terminated'", () => {
          const spy = registererStateSpy;
          expect(spy).toHaveBeenCalledTimes(2);
          expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
          expect(spy.calls.argsFor(1)).toEqual([RegistererState.Terminated]);
        });
      });

      describe("Alice register(), Registrar responds with 200 Ok", () => {
        beforeEach(async () => {
          resetSpies();
          registrar.userAgent.delegate = {
            onRegisterRequest: (request): void => {
              const contact = request.message.parseHeader("contact");
              expect(contact).toBeDefined();
              cseq++;
              expect(request.message.cseq).toEqual(cseq);
              expires = contact.getParam("expires");
              expect(expires).toBeDefined();
              request.accept({
                extraHeaders: [`Contact: ${contact}`],
                statusCode: 200
              });
            }
          };
          registerer.register();
          await alice.transport.waitReceived();
        });

        it("her ua should send REGISTER", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        });

        it("her ua should receive 200", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        });

        it("her registerer state should not change", () => {
          expect(registerer.state).toBe(RegistererState.Registered);
          expect(registererStateSpy).not.toHaveBeenCalled();
        });
      });

      describe("Alice unregister(), Registrar responds with 200 Ok", () => {
        beforeEach(async () => {
          resetSpies();
          registrar.userAgent.delegate = {
            onRegisterRequest: (request): void => {
              const contact = request.message.parseHeader("contact");
              expect(contact).toBeDefined();
              expires = contact.getParam("expires");
              expect(expires).toEqual("0");
              request.accept({
                extraHeaders: [`Contact: ${contact}`],
                statusCode: 200
              });
            }
          };
          registerer.unregister();
          await alice.transport.waitReceived();
        });

        it("her ua should send REGISTER", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        });

        it("her ua should receive 200", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        });

        it("her registerer state should transition 'unregistered'", () => {
          const spy = registererStateSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
        });
      });

      describe("Alice automatically re-registers before expires time elaspes", () => {
        beforeEach(async () => {
          resetSpies();
          registrar.userAgent.delegate = {
            onRegisterRequest: (request): void => {
              const contact = request.message.parseHeader("contact");
              expect(contact).toBeDefined();
              cseq++;
              expect(request.message.cseq).toEqual(cseq);
              request.accept({
                extraHeaders: [`Contact: ${contact}`],
                statusCode: 200
              });
            }
          };
          await soon((Number(expires) - 1) * 1000);
        });

        it("her ua should send REGISTER", () => {
          const spy = alice.transportSendSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        });

        it("her ua should receive 200", () => {
          const spy = alice.transportReceiveSpy;
          expect(spy).toHaveBeenCalledTimes(1);
          expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        });

        it("her registerer state should not change", () => {
          expect(registerer.state).toBe(RegistererState.Registered);
          expect(registererStateSpy).not.toHaveBeenCalled();
        });
      });
    });

    describe("Alice register(), dispose()", () => {
      let count: number;

      beforeEach(async () => {
        count = 0;
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            const contact = request.message.parseHeader("contact");
            expect(contact).toBeDefined();
            if (count === 0) {
              request.accept({
                extraHeaders: [`Contact: ${contact}`],
                statusCode: 200
              });
            } else {
              request.accept();
            }
          }
        };
        registerer.register();
        registerer.dispose();
        await alice.transport.waitReceived();
        await alice.transport.waitReceived();
      });

      it("her ua should send REGISTER, REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        expect(spy.calls.argsFor(1)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 200, 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
        expect(spy.calls.argsFor(1)).toEqual(SIP_200);
      });

      it("her registerer state should transition 'registered', 'unregistered', 'terminated'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(3);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Registered]);
        expect(spy.calls.argsFor(1)).toEqual([RegistererState.Unregistered]);
        expect(spy.calls.argsFor(2)).toEqual([RegistererState.Terminated]);
      });
    });

    describe("Alice register(), register()", () => {
      let threw: boolean;

      beforeEach(async () => {
        threw = false;
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            const contact = request.message.parseHeader("contact");
            expect(contact).toBeDefined();
            request.accept({
              extraHeaders: [`Contact: ${contact}`],
              statusCode: 200
            });
          }
        };
        registerer.register();
        registerer.register().catch(() => {
          threw = true;
        });
        await alice.transport.waitReceived(); // 200
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_200);
      });

      it("her registerer state should transition 'registered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Registered]);
      });

      it("her second register() should throw an error", () => {
        expect(threw).toBe(true);
      });
    });

    describe("Alice register(), send fails - Transport Error", () => {
      let statusCode: number | undefined;

      beforeEach(async () => {
        if (!(alice.userAgent.transport instanceof TransportFake)) {
          throw new Error("Transport not TransportFake");
        }
        alice.userAgent.transport.setConnected(false);
        statusCode = undefined;
        resetSpies();
        const options: RegistererRegisterOptions = {
          requestDelegate: {
            onReject: (response): void => {
              statusCode = response.message.statusCode;
            }
          }
        };
        return registerer.register(options);
      });

      afterEach(() => {
        if (!(alice.userAgent.transport instanceof TransportFake)) {
          throw new Error("Transport not TransportFake");
        }
        alice.userAgent.transport.setConnected(true);
      });

      it("her ua should send REGISTER and receive a 503 (faked)", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        expect(statusCode).toEqual(503);
      });

      it("her registerer state should transition 'unregistered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
      });
    });

    describe("Alice register(), no response - Request Timeout", () => {
      let statusCode: number | undefined;

      beforeEach(async () => {
        resetSpies();
        statusCode = undefined;
        registrar.userAgent.delegate = {
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          onRegisterRequest: (request): void => {
            return;
          }
        };
        const options: RegistererRegisterOptions = {
          requestDelegate: {
            onReject: (response): void => {
              statusCode = response.message.statusCode;
            }
          }
        };
        return registerer.register(options);
      });

      it("her ua should send REGISTER and receive a 408 (faked)", async () => {
        await soon(Timers.TIMER_F + 1);
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        expect(statusCode).toEqual(408);
      });

      it("her registerer state should transition 'unregistered'", async () => {
        await soon(Timers.TIMER_F + 1);
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
      });
    });

    describe("Alice register(), Registrar responds with 423 Interval Too Brief without Min-Expires", () => {
      beforeEach(async () => {
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            request.reject({ statusCode: 423 });
          }
        };
        registerer.register();
        await alice.transport.waitReceived();
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her registerer state should transition 'unregistered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
      });
    });

    describe("Alice register(), Registrar responds with 423 Interval Too Brief", () => {
      let count: number;
      const minExpires = 60000;

      beforeEach(async () => {
        count = 0;
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            count++;
            if (count === 1) {
              request.reject({
                extraHeaders: [`Min-Expires: ${minExpires}`],
                statusCode: 423
              });
            } else if (count === 2) {
              const contact = request.message.parseHeader("contact");
              expect(contact).toBeDefined();
              const expires = contact.getParam("expires");
              expect(expires).toEqual(`${minExpires}`);
              request.accept({
                extraHeaders: [`Contact: ${contact}`],
                statusCode: 200
              });
            } else {
              const contact = request.message.parseHeader("contact");
              expect(contact).toBeDefined();
              request.accept({
                extraHeaders: [`Contact: ${contact}`],
                statusCode: 200
              });
            }
          }
        };
        registerer.register();
        await alice.transport.waitReceived(); // 423
        await alice.transport.waitReceived(); // 200
      });

      it("her ua should send REGISTER, REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
        expect(spy.calls.argsFor(1)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 423, 200", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy.calls.argsFor(0)).toEqual(SIP_423);
        expect(spy.calls.argsFor(1)).toEqual(SIP_200);
      });

      it("her registerer state should transition 'registered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Registered]);
      });
    });

    describe("Alice register(), Registrar responds with 500 Server Internal Error with Retry-After", () => {
      const retryAfter = 600;
      let retryAfterReceived: number | undefined;

      beforeEach(async () => {
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            request.reject({
              extraHeaders: [`Retry-After: ${retryAfter}`],
              statusCode: 500
            });
          }
        };
        registerer.stateChange.addListener((newState) => {
          if (newState === RegistererState.Unregistered) {
            retryAfterReceived = registerer.retryAfter;
          }
        });
        registerer.register();
        await alice.transport.waitReceived(); // 503
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 500", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_500);
      });

      it("her registerer state should transition 'unregistered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
        expect(registerer.retryAfter).toEqual(undefined);
      });

      it("her registerer retry after should have been set on state transition", () => {
        expect(retryAfterReceived).toEqual(retryAfter);
      });

      it("her registerer retry after should be `undefined'", () => {
        expect(registerer.retryAfter).toEqual(undefined);
      });
    });

    describe("Alice register(), Registrar responds with 503 Service Unavailable with Retry-After", () => {
      const retryAfter = 600;
      let retryAfterReceived: number | undefined;

      beforeEach(async () => {
        resetSpies();
        registrar.userAgent.delegate = {
          onRegisterRequest: (request): void => {
            request.reject({
              extraHeaders: [`Retry-After: ${retryAfter}`],
              statusCode: 503
            });
          }
        };
        registerer.stateChange.addListener((newState) => {
          if (newState === RegistererState.Unregistered) {
            retryAfterReceived = registerer.retryAfter;
          }
        });
        registerer.register();
        await alice.transport.waitReceived(); // 503
      });

      it("her ua should send REGISTER", () => {
        const spy = alice.transportSendSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_REGISTER);
      });

      it("her ua should receive 503", () => {
        const spy = alice.transportReceiveSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual(SIP_503);
      });

      it("her registerer state should transition 'unregistered'", () => {
        const spy = registererStateSpy;
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy.calls.argsFor(0)).toEqual([RegistererState.Unregistered]);
        expect(registerer.retryAfter).toEqual(undefined);
      });

      it("her registerer retry after should have been set on state transition", () => {
        expect(retryAfterReceived).toEqual(retryAfter);
      });

      it("her registerer retry after should be `undefined'", () => {
        expect(registerer.retryAfter).toEqual(undefined);
      });
    });
  });
});
