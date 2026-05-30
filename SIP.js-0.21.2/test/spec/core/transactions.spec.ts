/* eslint-disable @typescript-eslint/unbound-method */
import {
  ClientTransaction,
  ClientTransactionUser,
  IncomingRequestMessage,
  IncomingResponseMessage,
  InviteClientTransaction,
  InviteServerTransaction,
  Levels,
  LoggerFactory,
  NonInviteClientTransaction,
  NonInviteServerTransaction,
  OutgoingRequestMessage,
  ServerTransaction,
  ServerTransactionUser,
  Transaction,
  TransactionState,
  TransactionUser,
  Transport
} from "../../../lib/core/index.js";
import { URI } from "../../../lib/grammar/index.js";

// TODO: Mocking the Requests and Responses isn't ideal and would rather use
// the actual implementations, but the current implementations depend on UA
// and thus drag in basically the entire project which is definately worse.
// So perhaps in the future...

/** Mocked incoming request factory function. */
const makeMockIncomingRequest = (method: string): jasmine.SpyObj<IncomingRequestMessage> => {
  const request = jasmine.createSpyObj<IncomingRequestMessage>("IncomingRequest", ["method", "viaBranch"]);
  request.method = method;
  request.viaBranch = "z9hG4bK" + Math.floor(Math.random() * 10000000);
  return request;
};

/** Mocked incoming response factory function. */
const makeMockIncomingResponse = (statusCode: number, toTag: string): jasmine.SpyObj<IncomingResponseMessage> => {
  const response = jasmine.createSpyObj<IncomingResponseMessage>("IncomingResponse", [
    "statusCode",
    "toTag",
    "getHeader"
  ]);
  response.statusCode = statusCode;
  response.toTag = toTag;
  response.getHeader.and.callFake((name: string) => {
    return `[${name}]`;
  });
  return response;
};

type Mutable<T> = { -readonly [P in keyof T]: T[P] };
const defaultURI = new URI("sip", "example", "onsip.com");

/** Mocked outgoing request factory function. */
const makeMockOutgoingRequest = (ruri: URI = defaultURI): jasmine.SpyObj<OutgoingRequestMessage> => {
  const request = jasmine.createSpyObj<Mutable<OutgoingRequestMessage>>("OutgoingRequest", [
    "callId",
    "cseq",
    "method",
    "ruri",
    "getHeader",
    "setViaHeader",
    "toString"
  ]);
  request.callId = "onsip";
  request.cseq = 42;
  request.method = "METHOD";
  request.ruri = ruri;
  request.toString.and.returnValue("request");
  request.getHeader.and.callFake((name: string) => {
    if (name === "via" && request.headers.via) {
      return request.headers.via[0];
    }
    return `[${name}]`;
  });
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  request.setViaHeader.and.callFake((branch: string, scheme = "WSS") => {
    request.headers.via = [branch];
  });
  request.headers = {};
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
  return request as jasmine.SpyObj<OutgoingRequestMessage>;
};

/** Mocked transaction user factory function. */
const makeTransactionUser = (): jasmine.SpyObj<Required<TransactionUser>> => {
  const user = jasmine.createSpyObj<Required<TransactionUser>>("TransactionUser", [
    "loggerFactory",
    "onTransportError",
    "onStateChange"
  ]);
  const loggerFactory = new LoggerFactory();
  loggerFactory.level = Levels.debug;
  user.loggerFactory = loggerFactory;
  return user;
};

/** Mocked client transaction user factory function. */
const makeClientTransactionUser = (): jasmine.SpyObj<Required<ClientTransactionUser>> => {
  const user = jasmine.createSpyObj<Required<ClientTransactionUser>>("ClientTransactionUser", [
    "loggerFactory",
    "onRequestTimeout",
    "onTransportError",
    "onStateChange",
    "receiveResponse"
  ]);
  const loggerFactory = new LoggerFactory();
  loggerFactory.level = Levels.debug;
  user.loggerFactory = loggerFactory;
  return user;
};

/** Mocked server transaction user factory function. */
const makeServerTransactionUser = (): jasmine.SpyObj<Required<ServerTransactionUser>> => {
  return makeTransactionUser();
};

/** Mocked transport factory function. */
const makeMockTransport = (): jasmine.SpyObj<Transport> => {
  const transport = jasmine.createSpyObj<Transport>("Transport", ["send"]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (transport.protocol as any) = "TEST";
  transport.send.and.returnValue(Promise.resolve());
  return transport;
};

// Helper types for factory functions.
type TransactionFactory = (transport: Transport, user: TransactionUser) => Transaction;
type ClientTransactionFactory = (
  request: OutgoingRequestMessage,
  transport: Transport,
  user: ClientTransactionUser
) => ClientTransaction;
type ServerTransactionFactory = (
  request: IncomingRequestMessage,
  transport: Transport,
  user: ServerTransactionUser
) => ServerTransaction;

// https://tools.ietf.org/html/rfc3261#section-17
describe("Core Transactions", () => {
  const ruri = "sip:example@onsip.com";
  const _1xxStatusCodesToTest = [100, 180, 183];
  const _2xxStatusCodesToTest = [200, 202];
  const _3xxStatusCodesToTest = [300, 301];
  const _4xxStatusCodesToTest = [404, 480];
  const _5xxStatusCodesToTest = [500, 503];
  const _6xxStatusCodesToTest = [603, 699];

  const executeTransactionTests = (transactionFactory: TransactionFactory): void => {
    let transport: jasmine.SpyObj<Transport>;
    let user: jasmine.SpyObj<Required<TransactionUser>>;
    let transaction: Transaction;

    describe("is a Transaction, so after construction it...", () => {
      beforeEach(() => {
        transport = makeMockTransport();
        user = makeTransactionUser();
        transaction = transactionFactory(transport, user);
        spyOn(transaction, "notifyStateChangeListeners");
      });

      afterEach(() => {
        transaction.dispose();
      });

      it("has the correct 'kind' [DEPRECATED]", () => {
        if (transaction instanceof InviteClientTransaction) {
          expect(transaction.kind).toEqual("ict");
        } else if (transaction instanceof NonInviteClientTransaction) {
          expect(transaction.kind).toEqual("nict");
        } else if (transaction instanceof InviteServerTransaction) {
          expect(transaction.kind).toEqual("ist");
        } else if (transaction instanceof NonInviteServerTransaction) {
          expect(transaction.kind).toEqual("nist");
        } else {
          expect(transaction.kind).toEqual("a valid transaction kind");
        }
      });

      it("has its transport", () => {
        expect(transaction.transport).toEqual(transport);
      });

      it("has an id which is a valid branch paramter", () => {
        expect(transaction.id).toMatch(/^z9hG4bK/);
      });

      it("has not notified the transaction user of a state change (emitted nothing)", () => {
        expect(user.onStateChange).not.toHaveBeenCalled();
        expect(transaction.notifyStateChangeListeners).not.toHaveBeenCalled();
      });
    });
  };

  // https://tools.ietf.org/html/rfc3261#section-17.1
  describe("ClientTransactions", () => {
    const executeClientTransactionTests = (clientTransactionFactory: ClientTransactionFactory): void => {
      let request: jasmine.SpyObj<OutgoingRequestMessage>;
      let transport: jasmine.SpyObj<Transport>;
      let user: jasmine.SpyObj<Required<ClientTransactionUser>>;
      let transaction: ClientTransaction;

      describe("is a ClientTransaction, so after construction it...", () => {
        beforeEach(() => {
          request = makeMockOutgoingRequest();
          transport = makeMockTransport();
          user = makeClientTransactionUser();
          transaction = clientTransactionFactory(request, transport, user);
        });

        afterEach(() => {
          transaction.dispose();
        });

        it("has its outgoing request", () => {
          expect(transaction.request).toEqual(request);
        });

        it("has updated the Via header of its outgoing request with the branch parameter and transport", () => {
          expect(request.setViaHeader).toHaveBeenCalledTimes(1);
          expect(request.setViaHeader).toHaveBeenCalledWith(transaction.id, "TEST");
        });

        it("has sent its outgoing request to the transport", () => {
          expect(request.toString).toHaveBeenCalledTimes(1);
          expect(transport.send).toHaveBeenCalledTimes(1);
          expect(transport.send).toHaveBeenCalledWith(request.toString.calls.first().returnValue);
        });
      });

      describe("is a ClientTransaction, so after construction with transport error it...", () => {
        beforeEach((done) => {
          request = makeMockOutgoingRequest();
          transport = makeMockTransport();
          user = makeClientTransactionUser();
          transport.send.and.returnValue(Promise.reject());
          transaction = clientTransactionFactory(request, transport, user);
          // the call to onTransportError is async, so give it some time
          setTimeout(() => done(), 10);
        });

        afterEach(() => {
          transaction.dispose();
        });

        it("has notified transaction user of transport failure", () => {
          expect(user.onTransportError).toHaveBeenCalledTimes(1);
        });
      });
    };

    // https://tools.ietf.org/html/rfc3261#section-17.1.1
    describe("InviteClientTransaction", () => {
      let request: jasmine.SpyObj<OutgoingRequestMessage>;
      let transport: jasmine.SpyObj<Transport>;
      let user: jasmine.SpyObj<Required<ClientTransactionUser>>;
      let transaction: InviteClientTransaction;

      const transactionFactory: TransactionFactory = (t: Transport, u: TransactionUser) => {
        const r = makeMockOutgoingRequest();
        return new InviteClientTransaction(r, t, u);
      };

      const clientTransactionFactory: ClientTransactionFactory = (
        r: OutgoingRequestMessage,
        t: Transport,
        u: ClientTransactionUser
      ) => {
        return new InviteClientTransaction(r, t, u);
      };

      executeTransactionTests(transactionFactory);
      executeClientTransactionTests(clientTransactionFactory);

      // TODO: These tests are weak. They could/should use real ACK messages.
      // https://tools.ietf.org/html/rfc3261#section-17.1.1.3
      const non2xxAckTests = (requestsSent: number): void => {
        it("it MUST generate an ACK and pass it to the transport", () => {
          expect(transport.send).toHaveBeenCalledTimes(requestsSent);
          expect(transport.send.calls.mostRecent().args[0]).toMatch(new RegExp(`^ACK ${ruri} SIP/2.0`));
        });

        it("it MUST generate an ACK with Via that matches original request", () => {
          expect(transport.send.calls.mostRecent().args[0]).toMatch(
            new RegExp(`${request.getHeader("via") ? request.getHeader("via") : "via undef"}`)
          );
        });
      };

      beforeEach(() => {
        request = makeMockOutgoingRequest();
        transport = makeMockTransport();
        user = makeClientTransactionUser();
        transaction = new InviteClientTransaction(request, transport, user);
        spyOn(transaction, "notifyStateChangeListeners");
      });

      afterEach(() => {
        transaction.dispose();
      });

      // https://tools.ietf.org/html/rfc3261#section-17.1.1.2
      describe("after construction", () => {
        it("is in 'calling' state and", () => {
          expect(transaction.state).toBe(TransactionState.Calling);
        });

        // https://tools.ietf.org/html/rfc3261#section-17.1.1.2
        describe("upon a 1xx response in 'calling' state", () => {
          _1xxStatusCodesToTest.forEach((statusCode) => {
            describe(`a ${statusCode} for example`, () => {
              let response: jasmine.SpyObj<IncomingResponseMessage>;

              beforeEach(() => {
                response = makeMockIncomingResponse(statusCode, statusCode === 100 ? "" : "totag");
                transaction.receiveResponse(response);
              });

              it("it MUST pass the response to the transaction user", () => {
                expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(response);
              });

              it("it MUST transition to the 'proceeding' state", () => {
                expect(transaction.state).toBe(TransactionState.Proceeding);
                expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                expect(user.onStateChange).toHaveBeenCalledTimes(1);
                expect(user.onStateChange).toHaveBeenCalledWith(TransactionState.Proceeding);
              });

              // https://tools.ietf.org/html/rfc3261#section-17.1.1.2
              describe("and then upon a 1xx while in 'proceeding' state", () => {
                _1xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    let _response: jasmine.SpyObj<IncomingResponseMessage>;

                    beforeEach(() => {
                      _response = makeMockIncomingResponse(_statusCode, _statusCode === 100 ? "" : "totag");
                      transaction.receiveResponse(_response);
                    });

                    it("it MUST pass the response to the transaction user", () => {
                      expect(user.receiveResponse).toHaveBeenCalledTimes(2);
                      expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(_response);
                    });

                    it("it MUST remain in 'proceeding' state", () => {
                      expect(transaction.state).toBe(TransactionState.Proceeding);
                      expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                      expect(user.onStateChange).toHaveBeenCalledTimes(1);
                    });
                  });
                });
              });

              // https://tools.ietf.org/html/rfc6026#section-8.4
              describe("and then upon a 2xx while in 'proceeding' state", () => {
                _2xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    let _response: jasmine.SpyObj<IncomingResponseMessage>;

                    beforeEach(() => {
                      _response = makeMockIncomingResponse(_statusCode, "totag");
                      transaction.receiveResponse(_response);
                    });

                    it("it MUST NOT generate an ACK to the 2xx response", () => {
                      expect(transport.send).toHaveBeenCalledTimes(1);
                    });

                    it("it MUST pass the response to the transaction user", () => {
                      expect(user.receiveResponse).toHaveBeenCalledTimes(2);
                      expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(_response);
                    });

                    it("it MUST transition to the 'accepted' state", () => {
                      expect(transaction.state).toBe(TransactionState.Accepted);
                      expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(2);
                      expect(user.onStateChange).toHaveBeenCalledTimes(2);
                    });
                  });
                });
              });

              // https://tools.ietf.org/html/rfc6026#section-8.4
              describe("and then upon receiving a 300-699 response in 'proceeding' state", () => {
                _3xxStatusCodesToTest
                  .concat(_4xxStatusCodesToTest)
                  .concat(_5xxStatusCodesToTest)
                  .concat(_6xxStatusCodesToTest)
                  .forEach((_statusCode) => {
                    describe(`a ${_statusCode} for example`, () => {
                      let _response: jasmine.SpyObj<IncomingResponseMessage>;

                      beforeEach(() => {
                        _response = makeMockIncomingResponse(_statusCode, "");
                        transaction.receiveResponse(_response);
                      });

                      non2xxAckTests(2);

                      it("it MUST pass the response to the transaction user", () => {
                        expect(user.receiveResponse).toHaveBeenCalledTimes(2);
                        expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(_response);
                      });

                      it("it MUST transition to the 'completed' state", () => {
                        expect(transaction.state).toBe(TransactionState.Completed);
                      });
                    });
                  });
              });
            });
          });
        });

        // https://tools.ietf.org/html/rfc6026#section-8.4
        describe("upon receiving a 2xx response in 'calling' state", () => {
          _2xxStatusCodesToTest.forEach((statusCode) => {
            describe(`a ${statusCode} for example`, () => {
              let response: jasmine.SpyObj<IncomingResponseMessage>;

              beforeEach(() => {
                response = makeMockIncomingResponse(statusCode, "totag");
                transaction.receiveResponse(response);
              });

              it("it MUST NOT generate an ACK to the 2xx response", () => {
                expect(transport.send).toHaveBeenCalledTimes(1);
              });

              it("it MUST pass the response to the transaction user", () => {
                expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(response);
              });

              it("it MUST transition to the 'accepted' state", () => {
                expect(transaction.state).toBe(TransactionState.Accepted);
                expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                expect(user.onStateChange).toHaveBeenCalledTimes(1);
              });

              // https://tools.ietf.org/html/rfc6026#section-7.2
              describe("and then upon a 1xx while in 'accepted' state", () => {
                _1xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    let _response: jasmine.SpyObj<IncomingResponseMessage>;

                    beforeEach(() => {
                      _response = makeMockIncomingResponse(_statusCode, _statusCode === 100 ? "" : "totag");
                      transaction.receiveResponse(_response);
                    });

                    it("it MUST NOT pass the response to the transaction user", () => {
                      expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                    });

                    it("it MUST remain in 'accepted' state", () => {
                      expect(transaction.state).toBe(TransactionState.Accepted);
                      expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                      expect(user.onStateChange).toHaveBeenCalledTimes(1);
                    });
                  });
                });
              });

              // https://tools.ietf.org/html/rfc6026#section-8.4
              describe("and then upon a 2xx while in 'accepted' state", () => {
                _2xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    let _response: jasmine.SpyObj<IncomingResponseMessage>;

                    beforeEach(() => {
                      _response = makeMockIncomingResponse(_statusCode, "totag2");
                      transaction.receiveResponse(_response);
                    });

                    it("it MUST NOT generate an ACK to the 2xx response", () => {
                      expect(transport.send).toHaveBeenCalledTimes(1);
                    });

                    it("it MUST pass the response to the transaction user", () => {
                      expect(user.receiveResponse).toHaveBeenCalledTimes(2);
                      expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(_response);
                    });

                    it("it MUST remain in 'accepted' state", () => {
                      expect(transaction.state).toBe(TransactionState.Accepted);
                      expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                      expect(user.onStateChange).toHaveBeenCalledTimes(1);
                    });
                  });
                });
              });

              // https://tools.ietf.org/html/rfc6026#section-8.4
              describe("and then upon a 2xx (retransmission) while in 'accepted' state", () => {
                _2xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    let _response: jasmine.SpyObj<IncomingResponseMessage>;

                    beforeEach(() => {
                      _response = makeMockIncomingResponse(_statusCode, "totag");
                      transaction.receiveResponse(_response);
                    });

                    // NOTE: The current implementation caches 2xx ACKs so if an ACK for
                    // the original response was sent it will be sent again at this point.
                    it("it MUST NOT generate an ACK to the 2xx response", () => {
                      // 1 is expected, but would be 2 if ACK for original response was sent
                      expect(transport.send).toHaveBeenCalledTimes(1);
                    });

                    // NOTE: The current implementation caches 2xx ACKs and only passes
                    // the 2xx response to the transaction user once (once per unique to tag).
                    it("it MUST pass the response to the transaction user", () => {
                      // 1 is expected, but would be 2 if to spec
                      expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                    });

                    it("it MUST remain in 'accepted' state", () => {
                      expect(transaction.state).toBe(TransactionState.Accepted);
                      expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                      expect(user.onStateChange).toHaveBeenCalledTimes(1);
                    });
                  });
                });
              });

              // https://tools.ietf.org/html/rfc6026#section-7.2
              describe("and then upon a 300-699 while in 'accepted' state", () => {
                _3xxStatusCodesToTest
                  .concat(_4xxStatusCodesToTest)
                  .concat(_5xxStatusCodesToTest)
                  .concat(_6xxStatusCodesToTest)
                  .forEach((_statusCode) => {
                    describe(`a ${_statusCode} for example`, () => {
                      let _response: jasmine.SpyObj<IncomingResponseMessage>;

                      beforeEach(() => {
                        _response = makeMockIncomingResponse(_statusCode, "");
                        transaction.receiveResponse(_response);
                      });

                      it("it MUST NOT pass the response to the transaction user", () => {
                        expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                      });

                      it("it MUST remain in 'accepted' state", () => {
                        expect(transaction.state).toBe(TransactionState.Accepted);
                        expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                        expect(user.onStateChange).toHaveBeenCalledTimes(1);
                      });
                    });
                  });
              });
            });
          });
        });

        // https://tools.ietf.org/html/rfc6026#section-8.4
        describe("upon receiving a 300-699 response in 'calling' state", () => {
          _3xxStatusCodesToTest
            .concat(_4xxStatusCodesToTest)
            .concat(_5xxStatusCodesToTest)
            .concat(_6xxStatusCodesToTest)
            .forEach((statusCode) => {
              describe(`a ${statusCode} for example`, () => {
                let response: jasmine.SpyObj<IncomingResponseMessage>;

                beforeEach(() => {
                  response = makeMockIncomingResponse(statusCode, "");
                  transaction.receiveResponse(response);
                });

                non2xxAckTests(2);

                it("it MUST pass the response to the transaction user", () => {
                  expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                  expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(response);
                });

                it("it MUST transition to the 'completed' state", () => {
                  expect(transaction.state).toBe(TransactionState.Completed);
                  expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                  expect(user.onStateChange).toHaveBeenCalledTimes(1);
                });

                // https://tools.ietf.org/html/rfc6026#section-7.2
                describe("and then upon a 1xx while in 'completed' state", () => {
                  _1xxStatusCodesToTest.forEach((_statusCode) => {
                    describe(`a ${_statusCode} for example`, () => {
                      let _response: jasmine.SpyObj<IncomingResponseMessage>;

                      beforeEach(() => {
                        _response = makeMockIncomingResponse(_statusCode, _statusCode === 100 ? "" : "totag");
                        transaction.receiveResponse(_response);
                      });

                      it("it MUST NOT pass the response to the transaction user", () => {
                        expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                      });

                      it("it MUST remain in 'completed' state", () => {
                        expect(transaction.state).toBe(TransactionState.Completed);
                        expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                        expect(user.onStateChange).toHaveBeenCalledTimes(1);
                      });
                    });
                  });
                });

                // https://tools.ietf.org/html/rfc6026#section-7.2
                describe("and then upon a 2xx while in 'completed' state", () => {
                  _2xxStatusCodesToTest.forEach((_statusCode) => {
                    describe(`a ${_statusCode} for example`, () => {
                      let _response: jasmine.SpyObj<IncomingResponseMessage>;

                      beforeEach(() => {
                        _response = makeMockIncomingResponse(_statusCode, "totag");
                        transaction.receiveResponse(_response);
                      });

                      it("it MUST NOT pass the response to the transaction user", () => {
                        expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                      });

                      it("it MUST remain in 'completed' state", () => {
                        expect(transaction.state).toBe(TransactionState.Completed);
                        expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                        expect(user.onStateChange).toHaveBeenCalledTimes(1);
                      });
                    });
                  });
                });

                // https://tools.ietf.org/html/rfc6026#section-8.4
                describe("and then upon a 300-699 while in 'completed' state", () => {
                  _3xxStatusCodesToTest
                    .concat(_4xxStatusCodesToTest)
                    .concat(_5xxStatusCodesToTest)
                    .concat(_6xxStatusCodesToTest)
                    .forEach((_statusCode) => {
                      describe(`a ${_statusCode} for example`, () => {
                        let _response: jasmine.SpyObj<IncomingResponseMessage>;

                        beforeEach(() => {
                          _response = makeMockIncomingResponse(_statusCode, "");
                          transaction.receiveResponse(_response);
                        });

                        non2xxAckTests(3);

                        it("it MUST NOT pass the response to the transaction user", () => {
                          expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                        });

                        it("it MUST remain in 'completed' state", () => {
                          expect(transaction.state).toBe(TransactionState.Completed);
                          expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                          expect(user.onStateChange).toHaveBeenCalledTimes(1);
                        });
                      });
                    });
                });
              });
            });
        });
      });
    });

    // https://tools.ietf.org/html/rfc3261#section-17.1.2
    describe("NonInviteClientTransaction", () => {
      let request: jasmine.SpyObj<OutgoingRequestMessage>;
      let transport: jasmine.SpyObj<Transport>;
      let user: jasmine.SpyObj<Required<ClientTransactionUser>>;
      let transaction: NonInviteClientTransaction;

      const transactionFactory: TransactionFactory = (t: Transport, u: TransactionUser) => {
        const r = makeMockOutgoingRequest();
        return new NonInviteClientTransaction(r, t, u);
      };

      const clientTransactionFactory: ClientTransactionFactory = (
        r: OutgoingRequestMessage,
        t: Transport,
        u: ClientTransactionUser
      ) => {
        return new NonInviteClientTransaction(r, t, u);
      };

      executeTransactionTests(transactionFactory);
      executeClientTransactionTests(clientTransactionFactory);

      beforeEach(() => {
        request = makeMockOutgoingRequest();
        transport = makeMockTransport();
        user = makeClientTransactionUser();
        transaction = new NonInviteClientTransaction(request, transport, user);
        spyOn(transaction, "notifyStateChangeListeners");
      });

      afterEach(() => {
        transaction.dispose();
      });

      describe("after construction", () => {
        it("is in state 'trying'", () => {
          expect(transaction.state).toBe(TransactionState.Trying);
        });

        // https://tools.ietf.org/html/rfc3261#section-17.1.2.2
        describe("upon a 1xx response in 'trying' state", () => {
          _1xxStatusCodesToTest.forEach((statusCode) => {
            describe(`a ${statusCode} for example`, () => {
              let response: jasmine.SpyObj<IncomingResponseMessage>;

              beforeEach(() => {
                response = makeMockIncomingResponse(statusCode, statusCode === 100 ? "" : "totag");
                transaction.receiveResponse(response);
              });

              it("it MUST pass the response to the transaction user", () => {
                expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(response);
              });

              it("it MUST transition to the 'proceeding' state", () => {
                expect(transaction.state).toBe(TransactionState.Proceeding);
                expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                expect(user.onStateChange).toHaveBeenCalledTimes(1);
                expect(user.onStateChange).toHaveBeenCalledWith(TransactionState.Proceeding);
              });

              // https://tools.ietf.org/html/rfc3261#section-17.1.2.2
              describe("and then upon a 1xx while in 'proceeding' state", () => {
                _1xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    let _response: jasmine.SpyObj<IncomingResponseMessage>;

                    beforeEach(() => {
                      _response = makeMockIncomingResponse(_statusCode, _statusCode === 100 ? "" : "totag");
                      transaction.receiveResponse(_response);
                    });

                    it("it MUST pass the response to the transaction user", () => {
                      expect(user.receiveResponse).toHaveBeenCalledTimes(2);
                      expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(_response);
                    });

                    it("it MUST remain in 'proceeding' state", () => {
                      expect(transaction.state).toBe(TransactionState.Proceeding);
                      expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                      expect(user.onStateChange).toHaveBeenCalledTimes(1);
                    });
                  });
                });
              });

              // https://tools.ietf.org/html/rfc3261#section-17.1.2.2
              describe("and then upon receiving a 200-699 response in 'proceeding' state", () => {
                _2xxStatusCodesToTest
                  .concat(_3xxStatusCodesToTest)
                  .concat(_4xxStatusCodesToTest)
                  .concat(_5xxStatusCodesToTest)
                  .concat(_6xxStatusCodesToTest)
                  .forEach((_statusCode) => {
                    describe(`a ${_statusCode} for example`, () => {
                      let _response: jasmine.SpyObj<IncomingResponseMessage>;

                      beforeEach(() => {
                        _response = makeMockIncomingResponse(_statusCode, "");
                        transaction.receiveResponse(_response);
                      });

                      it("it MUST pass the response to the transaction user", () => {
                        expect(user.receiveResponse).toHaveBeenCalledTimes(2);
                        expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(_response);
                      });

                      it("it MUST transition to the 'completed' state", () => {
                        expect(transaction.state).toBe(TransactionState.Completed);
                      });
                    });
                  });
              });
            });
          });
        });

        // https://tools.ietf.org/html/rfc3261#section-17.1.2.2
        describe("upon receiving a 300-699 response in 'trying' state", () => {
          _2xxStatusCodesToTest
            .concat(_3xxStatusCodesToTest)
            .concat(_4xxStatusCodesToTest)
            .concat(_5xxStatusCodesToTest)
            .concat(_6xxStatusCodesToTest)
            .forEach((statusCode) => {
              describe(`a ${statusCode} for example`, () => {
                let response: jasmine.SpyObj<IncomingResponseMessage>;

                beforeEach(() => {
                  response = makeMockIncomingResponse(statusCode, "");
                  transaction.receiveResponse(response);
                });

                it("it MUST pass the response to the transaction user", () => {
                  expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                  expect(user.receiveResponse.calls.mostRecent().args[0]).toBe(response);
                });

                it("it MUST transition to the 'completed' state", () => {
                  expect(transaction.state).toBe(TransactionState.Completed);
                  expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                  expect(user.onStateChange).toHaveBeenCalledTimes(1);
                });

                // https://tools.ietf.org/html/rfc3261#section-17.1.2.2
                describe("and then upon a 100-699 while in 'completed' state", () => {
                  _1xxStatusCodesToTest
                    .concat(_2xxStatusCodesToTest)
                    .concat(_3xxStatusCodesToTest)
                    .concat(_4xxStatusCodesToTest)
                    .concat(_5xxStatusCodesToTest)
                    .concat(_6xxStatusCodesToTest)
                    .forEach((_statusCode) => {
                      describe(`a ${_statusCode} for example`, () => {
                        let _response: jasmine.SpyObj<IncomingResponseMessage>;

                        beforeEach(() => {
                          _response = makeMockIncomingResponse(_statusCode, "");
                          transaction.receiveResponse(_response);
                        });

                        it("it MUST NOT pass the response to the transaction user", () => {
                          expect(user.receiveResponse).toHaveBeenCalledTimes(1);
                        });

                        it("it MUST remain in 'completed' state", () => {
                          expect(transaction.state).toBe(TransactionState.Completed);
                          expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                          expect(user.onStateChange).toHaveBeenCalledTimes(1);
                        });
                      });
                    });
                });
              });
            });
        });
      });
    });
  });

  // https://tools.ietf.org/html/rfc3261#section-17.2
  describe("ServerTransactions", () => {
    const executeServerTransactionTests = (serverTransactionFactory: ServerTransactionFactory): void => {
      let request: jasmine.SpyObj<IncomingRequestMessage>;
      let transport: jasmine.SpyObj<Transport>;
      let user: jasmine.SpyObj<Required<ServerTransactionUser>>;
      let transaction: ServerTransaction;

      describe("is a ServerTransaction, so after construction it...", () => {
        beforeEach(() => {
          request = makeMockIncomingRequest("UNKNOWN");
          transport = makeMockTransport();
          user = makeServerTransactionUser();
          transaction = serverTransactionFactory(request, transport, user);
        });

        afterEach(() => {
          transaction.dispose();
        });

        it("has its incoming request", () => {
          expect(transaction.request).toEqual(request);
        });

        it("has its incoming request with branch parameter equal to its transaction id", () => {
          expect(transaction.request.viaBranch).toEqual(transaction.id);
        });
      });
    };

    // https://tools.ietf.org/html/rfc3261#section-17.2.1
    describe("InviteServerTransaction", () => {
      let request: jasmine.SpyObj<IncomingRequestMessage>;
      let transport: jasmine.SpyObj<Transport>;
      let user: jasmine.SpyObj<Required<ServerTransactionUser>>;
      let transaction: InviteServerTransaction;

      const transactionFactory: TransactionFactory = (t: Transport, u: TransactionUser) => {
        const r = makeMockIncomingRequest("INVITE");
        return new InviteServerTransaction(r, t, u);
      };

      const serverTransactionFactory: ServerTransactionFactory = (
        r: IncomingRequestMessage,
        t: Transport,
        u: ServerTransactionUser
      ) => {
        return new InviteServerTransaction(r, t, u);
      };

      executeTransactionTests(transactionFactory);
      executeServerTransactionTests(serverTransactionFactory);

      beforeEach(() => {
        request = makeMockIncomingRequest("INVITE");
        transport = makeMockTransport();
        user = makeClientTransactionUser();
        transaction = new InviteServerTransaction(request, transport, user);
        spyOn(transaction, "notifyStateChangeListeners");
      });

      afterEach(() => {
        transaction.dispose();
      });

      describe("after construction", () => {
        // https://tools.ietf.org/html/rfc3261#section-17.2.1
        it("is in state 'proceeding'", () => {
          expect(transaction.state).toBe(TransactionState.Proceeding);
        });

        // https://tools.ietf.org/html/rfc3261#section-17.2.1
        describe("upon receiving a request retransmission from transport in 'proceeding' state", () => {
          beforeEach(() => {
            transaction.receiveRequest(request);
          });

          it("it MUST retransmit the last response", () => {
            // FIXME: 0 is expected because request.reply is mocked currently (would otherwise expect 1)
            // But regardless, if we don't have a last response to retransmit then we don't have one.
            expect(transport.send).toHaveBeenCalledTimes(0);
          });
        });

        // https://tools.ietf.org/html/rfc3261#section-17.2.1
        describe("upon receiving a 1xx response from the transaction user in 'proceeding' state", () => {
          _1xxStatusCodesToTest.forEach((statusCode) => {
            describe(`a ${statusCode} for example`, () => {
              beforeEach(() => {
                transaction.receiveResponse(statusCode, "response");
              });

              it("it MUST pass the response to the transport", () => {
                expect(transport.send).toHaveBeenCalledTimes(1);
              });

              it("it MUST remain in 'proceeding' state", () => {
                expect(transaction.state).toBe(TransactionState.Proceeding);
                expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(0);
                expect(user.onStateChange).toHaveBeenCalledTimes(0);
              });

              describe("if a transport error occurs in 'proceeding' state", () => {
                beforeEach((done) => {
                  transport.send.and.returnValue(Promise.reject());
                  transaction.receiveRequest(request);
                  // the call to onTransportError is async, so give it some time
                  setTimeout(() => done(), 10);
                });

                it("has notified transaction user of transport failure", () => {
                  expect(user.onTransportError).toHaveBeenCalledTimes(1);
                });
              });

              // https://tools.ietf.org/html/rfc3261#section-17.2.1
              describe("then upon receiving a request retransmission from transport in 'proceeding' state", () => {
                beforeEach(() => {
                  transaction.receiveRequest(request);
                });

                it("it MUST retransmit the last response", () => {
                  expect(transport.send).toHaveBeenCalledTimes(2);
                });
              });
            });
          });
        });

        // https://tools.ietf.org/html/rfc6026#section-8.5
        describe("upon receiving a 2xx response from the transaction user in 'proceeding' state", () => {
          _2xxStatusCodesToTest.forEach((statusCode) => {
            describe(`a ${statusCode} for example`, () => {
              beforeEach(() => {
                transaction.receiveResponse(statusCode, "response");
              });

              it("it MUST pass the response to the transport", () => {
                expect(transport.send).toHaveBeenCalledTimes(1);
              });

              it("it MUST transition to the 'accepted' state", () => {
                expect(transaction.state).toBe(TransactionState.Accepted);
                expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                expect(user.onStateChange).toHaveBeenCalledTimes(1);
              });

              // https://tools.ietf.org/html/rfc6026#section-7.1
              describe("then upon receiving a request retransmission from transport in 'accepted' state", () => {
                beforeEach(() => {
                  transaction.receiveRequest(request);
                });

                it("it MUST absorb the request without changing state", () => {
                  expect(transport.send).toHaveBeenCalledTimes(1);
                  expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                  expect(user.onStateChange).toHaveBeenCalledTimes(1);
                });
              });

              describe("then upon receiving a 1xx response from the transaction user in 'accepted' state", () => {
                _1xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    it("it should throw an error", () => {
                      expect(() => transaction.receiveResponse(_statusCode, "response")).toThrow();
                    });
                  });
                });
              });

              // https://tools.ietf.org/html/rfc6026#section-8.7
              describe("then upon receiving a 2xx response from the transaction user in 'accepted' state", () => {
                _2xxStatusCodesToTest.forEach((_statusCode) => {
                  describe(`a ${_statusCode} for example`, () => {
                    beforeEach(() => {
                      transaction.receiveResponse(_statusCode, "response");
                    });

                    it("it MUST pass the response to the transport", () => {
                      expect(transport.send).toHaveBeenCalledTimes(2);
                    });

                    it("it MUST remain in 'accepted' state", () => {
                      expect(transaction.state).toBe(TransactionState.Accepted);
                      expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                      expect(user.onStateChange).toHaveBeenCalledTimes(1);
                    });
                  });
                });
              });

              describe("then upon receiving a 300-699 response from the transaction user in 'accepted' state", () => {
                _3xxStatusCodesToTest
                  .concat(_4xxStatusCodesToTest)
                  .concat(_5xxStatusCodesToTest)
                  .concat(_6xxStatusCodesToTest)
                  .forEach((_statusCode) => {
                    describe(`a ${_statusCode} for example`, () => {
                      it("it should throw an error", () => {
                        expect(() => transaction.receiveResponse(_statusCode, "response")).toThrow();
                      });
                    });
                  });
              });
            });
          });
        });

        // https://tools.ietf.org/html/rfc3261#section-17.2.1
        describe("upon receiving a 300-699 response from the transaction user in 'proceeding' state", () => {
          _3xxStatusCodesToTest
            .concat(_4xxStatusCodesToTest)
            .concat(_5xxStatusCodesToTest)
            .concat(_6xxStatusCodesToTest)
            .forEach((statusCode) => {
              describe(`a ${statusCode} for example`, () => {
                beforeEach(() => {
                  transaction.receiveResponse(statusCode, "response");
                });

                it("it MUST pass the response to the transport", () => {
                  expect(transport.send).toHaveBeenCalledTimes(1);
                });

                it("it MUST transition to the 'completed' state", () => {
                  expect(transaction.state).toBe(TransactionState.Completed);
                  expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                  expect(user.onStateChange).toHaveBeenCalledTimes(1);
                });

                describe("if a transport error occurs in 'proceeding' state", () => {
                  beforeEach((done) => {
                    transport.send.and.returnValue(Promise.reject());
                    transaction.receiveRequest(request);
                    // the call to onTransportError is async, so give it some time
                    setTimeout(() => done(), 10);
                  });

                  it("has notified transaction user of transport failure", () => {
                    expect(user.onTransportError).toHaveBeenCalledTimes(1);
                  });
                });

                // https://tools.ietf.org/html/rfc3261#section-17.2.1
                describe("then receives a request retransmission from transport in 'completed' state", () => {
                  beforeEach(() => {
                    transaction.receiveRequest(request);
                  });

                  it("it SHOULD pass the response to the transport", () => {
                    expect(transport.send).toHaveBeenCalledTimes(2);
                  });

                  it("it MUST remain in 'completed' state", () => {
                    expect(transaction.state).toBe(TransactionState.Completed);
                    expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                    expect(user.onStateChange).toHaveBeenCalledTimes(1);
                  });
                });

                // https://tools.ietf.org/html/rfc3261#section-17.2.1
                describe("then receives an ACK from transport in 'completed' state", () => {
                  let ack: jasmine.SpyObj<IncomingRequestMessage>;

                  beforeEach(() => {
                    ack = makeMockIncomingRequest("ACK");
                    transaction.receiveRequest(ack);
                  });

                  it("it MUST NOT pass the response to the transport", () => {
                    expect(transport.send).toHaveBeenCalledTimes(1);
                  });

                  it("it MUST transition to the 'confirmed' state", () => {
                    expect(transaction.state).toBe(TransactionState.Confirmed);
                    expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(2);
                    expect(user.onStateChange).toHaveBeenCalledTimes(2);
                  });
                });
              });
            });
        });
      });
    });

    // https://tools.ietf.org/html/rfc3261#section-17.2.2
    describe("NonInviteServerTransaction", () => {
      let request: jasmine.SpyObj<IncomingRequestMessage>;
      let transport: jasmine.SpyObj<Transport>;
      let user: jasmine.SpyObj<Required<ServerTransactionUser>>;
      let transaction: NonInviteServerTransaction;

      const transactionFactory: TransactionFactory = (t: Transport, u: TransactionUser) => {
        const r = makeMockIncomingRequest("OPTIONS");
        return new NonInviteServerTransaction(r, t, u);
      };

      const serverTransactionFactory: ServerTransactionFactory = (
        r: IncomingRequestMessage,
        t: Transport,
        u: ServerTransactionUser
      ) => {
        return new NonInviteServerTransaction(r, t, u);
      };

      executeTransactionTests(transactionFactory);
      executeServerTransactionTests(serverTransactionFactory);

      beforeEach(() => {
        request = makeMockIncomingRequest("OPTIONS");
        transport = makeMockTransport();
        user = makeClientTransactionUser();
        transaction = new NonInviteServerTransaction(request, transport, user);
        spyOn(transaction, "notifyStateChangeListeners");
      });

      afterEach(() => {
        transaction.dispose();
      });

      describe("after construction", () => {
        // https://tools.ietf.org/html/rfc3261#section-17.2.2
        it("is in state 'trying'", () => {
          expect(transaction.state).toBe(TransactionState.Trying);
        });

        // https://tools.ietf.org/html/rfc3261#section-17.2.2
        describe("upon receiving a request retransmission from transport in 'trying' state", () => {
          beforeEach(() => {
            transaction.receiveRequest(request);
          });

          it("it discards the retransmission", () => {
            expect(transport.send).toHaveBeenCalledTimes(0);
          });
        });

        // https://tools.ietf.org/html/rfc4320#section-4.1
        describe("upon receiving non-100 provisional response from the transaction user in 'trying' state", () => {
          it("it should throw an error", () => {
            expect(() => transaction.receiveResponse(180, "response")).toThrow();
          });
        });

        describe("if a transport error occurs in 'trying' state", () => {
          beforeEach((done) => {
            transport.send.and.returnValue(Promise.reject());
            transaction.receiveResponse(100, "response");
            // the call to onTransportError is async, so give it some time
            setTimeout(() => done(), 10);
          });

          it("has notified transaction user of transport failure", () => {
            expect(user.onTransportError).toHaveBeenCalledTimes(1);
          });
        });

        // https://tools.ietf.org/html/rfc3261#section-17.2.2
        describe("upon receiving a 100 response from the transaction user in 'trying' state", () => {
          beforeEach(() => {
            transaction.receiveResponse(100, "response");
          });

          it("it MUST pass the response to the transport", () => {
            expect(transport.send).toHaveBeenCalledTimes(1);
          });

          it("it MUST transition the 'proceeding' state", () => {
            expect(transaction.state).toBe(TransactionState.Proceeding);
            expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
            expect(user.onStateChange).toHaveBeenCalledTimes(1);
            expect(user.onStateChange).toHaveBeenCalledWith(TransactionState.Proceeding);
          });

          // https://tools.ietf.org/html/rfc3261#section-17.2.2
          describe("then upon receiving a request retransmission from transport in 'proceeding' state", () => {
            beforeEach(() => {
              transaction.receiveRequest(request);
            });

            it("it MUST retransmit the last response", () => {
              expect(transport.send).toHaveBeenCalledTimes(2);
            });
          });

          // https://tools.ietf.org/html/rfc4320#section-4.1
          describe("then upon receiving a provisional response from the transaction user in 'proceeding' state", () => {
            it("it should throw an error", () => {
              expect(() => transaction.receiveResponse(180, "response")).toThrow();
            });
          });

          describe("if a transport error occurs in 'proceeding' state", () => {
            beforeEach((done) => {
              transport.send.and.returnValue(Promise.reject());
              transaction.receiveResponse(200, "response");
              // the call to onTransportError is async, so give it some time
              setTimeout(() => done(), 10);
            });

            it("has notified transaction user of transport failure", () => {
              expect(user.onTransportError).toHaveBeenCalledTimes(1);
            });
          });

          // https://tools.ietf.org/html/rfc3261#section-17.2.2
          describe("then upon receiving a 200-699 response from the transaction user in 'proceeding' state", () => {
            _2xxStatusCodesToTest
              .concat(_3xxStatusCodesToTest)
              .concat(_4xxStatusCodesToTest)
              .concat(_5xxStatusCodesToTest)
              .concat(_6xxStatusCodesToTest)
              .forEach((_statusCode) => {
                describe(`a ${_statusCode} for example`, () => {
                  beforeEach(() => {
                    transaction.receiveResponse(_statusCode, "response");
                  });

                  it("it MUST pass the response to the transport", () => {
                    expect(transport.send).toHaveBeenCalledTimes(2);
                  });

                  it("it MUST transition the 'completed' state", () => {
                    expect(transaction.state).toBe(TransactionState.Completed);
                    expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(2);
                    expect(user.onStateChange).toHaveBeenCalledTimes(2);
                    expect(user.onStateChange).toHaveBeenCalledWith(TransactionState.Completed);
                  });

                  // https://tools.ietf.org/html/rfc3261#section-17.2.2
                  describe("then upon receiving a request retransmission from transport in 'completed' state", () => {
                    beforeEach(() => {
                      transaction.receiveRequest(request);
                    });

                    it("it MUST retransmit the last response", () => {
                      expect(transport.send).toHaveBeenCalledTimes(3);
                    });
                  });

                  describe("if a transport error occurs in 'completed' state", () => {
                    beforeEach((done) => {
                      transport.send.and.returnValue(Promise.reject());
                      transaction.receiveRequest(request);
                      // the call to onTransportError is async, so give it some time
                      setTimeout(() => done(), 10);
                    });

                    it("has notified transaction user of transport failure", () => {
                      expect(user.onTransportError).toHaveBeenCalledTimes(1);
                    });
                  });
                });
              });
          });
        });

        // https://tools.ietf.org/html/rfc3261#section-17.2.2
        describe("then receives a 200-699 response from the transaction user in 'trying' state", () => {
          _2xxStatusCodesToTest
            .concat(_3xxStatusCodesToTest)
            .concat(_4xxStatusCodesToTest)
            .concat(_5xxStatusCodesToTest)
            .concat(_6xxStatusCodesToTest)
            .forEach((_statusCode) => {
              describe(`a ${_statusCode} for example`, () => {
                beforeEach(() => {
                  transaction.receiveResponse(_statusCode, "response");
                });

                it("it MUST pass the response to the transport", () => {
                  expect(transport.send).toHaveBeenCalledTimes(1);
                });

                it("it MUST transition the 'completed' state", () => {
                  expect(transaction.state).toBe(TransactionState.Completed);
                  expect(transaction.notifyStateChangeListeners).toHaveBeenCalledTimes(1);
                  expect(user.onStateChange).toHaveBeenCalledTimes(1);
                  expect(user.onStateChange).toHaveBeenCalledWith(TransactionState.Completed);
                });

                // https://tools.ietf.org/html/rfc3261#section-17.2.2
                describe("then receives a request retransmission from transport in 'completed' state", () => {
                  beforeEach(() => {
                    transaction.receiveRequest(request);
                  });

                  it("it MUST retransmit the last response", () => {
                    expect(transport.send).toHaveBeenCalledTimes(2);
                  });
                });
              });
            });
        });
      });
    });
  });
});
