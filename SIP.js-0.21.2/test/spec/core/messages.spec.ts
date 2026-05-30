/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  IncomingRequestMessage as IncomingRequest,
  IncomingResponseMessage as IncomingResponse,
  OutgoingRequestMessage as OutgoingRequest
} from "../../../lib/core/index.js";
import { Grammar, URI } from "../../../lib/grammar/index.js";
import * as Utils from "../../../lib/core/messages/utils.js";

// TODO:
// These old tests were ported from JavaScript to TypesSript verbatim.
// The next time the Messages gets a work over, these should be reviewed.

describe("Core Messages", () => {
  describe("OutgoingRequest", () => {
    let outgoingRequest: OutgoingRequest;
    let method: string;
    let ruri: URI;
    let from: URI;
    let to: URI;

    beforeEach(() => {
      method = "method";
      ruri = new URI("sip", "ruri", "domain");
      from = new URI("sip", "from", "domain");
      to = new URI("sip", "to", "domain");
      outgoingRequest = new OutgoingRequest(method, ruri, from, to);
    });

    it("sets up instance variables", () => {
      outgoingRequest = new OutgoingRequest(method, ruri, from, to);
      expect(outgoingRequest).toBeDefined();
      expect(outgoingRequest.headers).toBeDefined(); // might want to revisit this
      expect(outgoingRequest.ruri).toEqual(ruri);
      // expect(outgoingRequest.body).toBeDefined(); // and this
      // expect(outgoingRequest.extraHeaders).toBe(extraHeaders);
      // grammar.nameAddrHeaderParse got overwritten to make these two lines work
      // expect(outgoingRequest.to).toBeDefined();
      // expect(outgoingRequest.from).toBeDefined();
      expect(outgoingRequest.callId).toBeDefined();
      expect(outgoingRequest.cseq).toBeDefined();
    });

    describe(".setHeader", () => {
      it("sets the headers headerized name property to an array of the value", () => {
        (outgoingRequest.headers as any) = {};
        expect(outgoingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        outgoingRequest.setHeader(name, value);
        expect(outgoingRequest.headers[Utils.headerize(name)]).toEqual([value]);
      });

      it("sets the headers headerized name property to the array passed to it", () => {
        (outgoingRequest.headers as any) = {};
        expect(outgoingRequest.headers).toEqual({});
        const name = "name";
        const value = ["value1", "value2"];
        outgoingRequest.setHeader(name, value);
        expect(outgoingRequest.headers[Utils.headerize(name)]).toEqual(value);
      });
    });

    describe(".getHeader", () => {
      it("returns the header that exists", () => {
        (outgoingRequest.headers as any) = {};
        expect(outgoingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        outgoingRequest.setHeader(name, value);
        expect(outgoingRequest.headers[Utils.headerize(name)]).toEqual([value]);
        expect(outgoingRequest.getHeader(name)).toBe(value);
      });

      it("returns the header from extra headers if it is not in headers", () => {
        outgoingRequest.extraHeaders = [];
        outgoingRequest.extraHeaders.push("Event: " + "extraEvent");
        outgoingRequest.extraHeaders.push("Allow: " + "extraAllow");

        expect(outgoingRequest.getHeader("event")).toBe("extraEvent");
        expect(outgoingRequest.getHeader("Allow")).toBe("extraAllow");
      });

      it("returns undefined if the header does not exist in headers or extraHeaders", () => {
        outgoingRequest.extraHeaders = [];
        outgoingRequest.extraHeaders.push("Event: " + "extraEvent");
        outgoingRequest.extraHeaders.push("Allow: " + "extraAllow");

        expect(outgoingRequest.getHeader("Contact")).toBe(undefined);
      });
    });

    describe(".getHeaders", () => {
      it("returns all of the headers in an array with the given name", () => {
        (outgoingRequest.headers as any) = {};
        expect(outgoingRequest.headers).toEqual({});
        const name = "name";
        const value = ["value1", "value2"];
        outgoingRequest.setHeader(name, value);
        expect(outgoingRequest.headers[Utils.headerize(name)]).toEqual(value);
        expect(outgoingRequest.getHeaders(name)).toEqual(value);
      });

      it("returns all the headers in an array with the given name from extraHeaders if the header is not in headers", () => {
        outgoingRequest.extraHeaders = [];
        outgoingRequest.extraHeaders.push("Event: " + "extraEvent");

        expect(outgoingRequest.getHeaders("event")).toEqual(["extraEvent"]);
      });

      it("returns an empty array if the header is not found in headers and the header is not found in extraHeaders", () => {
        outgoingRequest.extraHeaders = [];
        outgoingRequest.extraHeaders.push("Event: " + "extraEvent");

        expect(outgoingRequest.getHeaders("Contact")).toEqual([]);
      });
    });

    describe(".hasHeader", () => {
      it("returns true if the header exists in headers", () => {
        const name = "name";
        const value = "value";

        outgoingRequest.setHeader(name, value);
        expect(outgoingRequest.hasHeader(name)).toBe(true);
      });

      it("returns true if the header exists in extraHeaders", () => {
        outgoingRequest.extraHeaders = [];
        outgoingRequest.extraHeaders.push("Event: " + "extraEvent");

        expect(outgoingRequest.hasHeader("event")).toBe(true);
      });

      it("returns false if the header does not exist in headers or extraHeaders", () => {
        outgoingRequest.extraHeaders = [];
        outgoingRequest.extraHeaders.push("Event: " + "extraEvent");

        expect(outgoingRequest.hasHeader("Contact")).toBe(false);
      });
    });

    describe(".toString", () => {
      it("calculates the correct Content-lenght for a given body", () => {
        let body = "a";

        let length = Utils.utf8Length(body);
        expect(length).toBe(1);

        body = "ä";
        length = Utils.utf8Length(body);
        expect(length).toBe(2);

        body = "test€";
        length = Utils.utf8Length(body);
        expect(length).toBe(7);

        body = "test€fantasticääüüöööööö€€€";
        length = Utils.utf8Length(body);
        expect(length).toBe(45);
      });
    });
  });

  describe("IncomingRequest", () => {
    let incomingRequest: IncomingRequest;

    beforeEach(() => {
      incomingRequest = new IncomingRequest();
    });

    it("initialize the instance variables", () => {
      expect(incomingRequest.data).toBeUndefined();
      expect(incomingRequest.headers).toBeDefined();
      expect(incomingRequest.method).toBeUndefined();
      expect(incomingRequest.via).toBeUndefined();
      expect(incomingRequest.viaBranch).toBeUndefined();
      expect(incomingRequest.callId).toBeUndefined();
      expect(incomingRequest.cseq).toBeUndefined();
      expect(incomingRequest.from).toBeUndefined();
      expect(incomingRequest.fromTag).toBeUndefined();
      expect(incomingRequest.to).toBeUndefined();
      expect(incomingRequest.toTag).toBeUndefined();
      expect(incomingRequest.body).toBeUndefined();
      expect(incomingRequest.ruri).toBeUndefined();
    });

    describe(".addHeader", () => {
      it("creates the header in the headers object if it does not already exist", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingRequest.addHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
      });

      it("adds the header to the array in the headers object if it already exists", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value1 = "value1";
        incomingRequest.addHeader(name, value1);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }]);
        const value2 = "value2";
        incomingRequest.addHeader(name, value2);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }, { raw: value2 }]);
      });
    });

    describe(".getHeader", () => {
      it("returns undefined if the header does not exist", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        expect(incomingRequest.getHeader(name)).toBeUndefined();
      });
      it("returns the value of the header that exists", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingRequest.addHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
      });
      it("returns the first header value if multiple values exist", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value1 = "value1";
        const value2 = "value2";
        incomingRequest.addHeader(name, value1);
        incomingRequest.addHeader(name, value2);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }, { raw: value2 }]);
        expect(incomingRequest.getHeader(name)).toBe(value1);
        expect(incomingRequest.getHeader(name)).not.toBe(value2);
      });
    });

    describe(".getHeaders", () => {
      it("returns an empty array if the header does not exist", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        expect(incomingRequest.getHeaders(name).length).toEqual(0);
        expect(incomingRequest.getHeaders(name)).toEqual([]);
      });
      it("returns an array with one value if there is only one value for the header provided", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingRequest.addHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        expect(incomingRequest.getHeaders(name).length).toEqual(1);
        expect(incomingRequest.getHeaders(name)).toEqual([value]);
      });

      it("returns an array with all of the values if they exist for the header provided", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value1 = "value1";
        incomingRequest.addHeader(name, value1);
        const value2 = "value2";
        incomingRequest.addHeader(name, value2);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }, { raw: value2 }]);
        expect(incomingRequest.getHeaders(name).length).toEqual(2);
        expect(incomingRequest.getHeaders(name)).toEqual([value1, value2]);
      });
    });

    describe(".hasHeader", () => {
      it("returns true if the header exists", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingRequest.addHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        expect(incomingRequest.hasHeader(name)).toBe(true);
      });
      it("returns false if the header does not exist", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        expect(incomingRequest.hasHeader(name)).toBe(false);
      });
    });

    describe(".parseHeader", () => {
      beforeEach(() => {
        (incomingRequest as any).logger = {};
        (incomingRequest as any).logger.log = jasmine.createSpy("log").and.returnValue("log");
        (incomingRequest as any).logger.warn = jasmine.createSpy("warn").and.returnValue("warn");
        spyOn(Grammar, "parse").and.callThrough();
      });

      it("returns undefined if the header does not exist in the headers object", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        expect(incomingRequest.parseHeader(name)).toBeUndefined();
      });
      it("returns undefined if the idx is greater than the array for the header that exists", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingRequest.addHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        const index = 1;
        expect(incomingRequest.parseHeader(name, index)).toBeUndefined();
        expect(incomingRequest.getHeaders(name).length).toBeGreaterThan(index - 1);
      });

      it("returns the already parsed header if it exists", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "call-ID";
        const value = "hnds3k17jhd1jank84hq";
        incomingRequest.addHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        incomingRequest.parseHeader(name, 0);
        expect((Grammar.parse as any).calls.count()).toEqual(1);
        expect((incomingRequest as any).logger.warn).not.toHaveBeenCalled();
        expect(incomingRequest.headers[Utils.headerize(name)][0].parsed).toBeDefined();
        expect(incomingRequest.parseHeader(name, 0)).toBe(incomingRequest.headers[Utils.headerize(name)][0].parsed);
        expect((Grammar.parse as any).calls.count()).toEqual(1);
      });

      it("returns a newly parsed header and creates a parsed property", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "call-ID";
        const value = "hnds3k17jhd1jank84hq";
        incomingRequest.addHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        expect(incomingRequest.headers[Utils.headerize(name)][0].parsed).toBeUndefined();
        expect(incomingRequest.parseHeader(name, 0)).toBe(value);
        expect(incomingRequest.headers[Utils.headerize(name)][0].parsed).toBe(value);
      });
    });

    describe(".setHeader", () => {
      it("adds the header if it does not alredy exist", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingRequest.setHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
      });
      it("replaces a header that already exists", () => {
        expect(incomingRequest.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingRequest.setHeader(name, value);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        const newValue = "new_value";
        incomingRequest.setHeader(name, newValue);
        expect(incomingRequest.headers[Utils.headerize(name)]).not.toEqual([{ raw: value }]);
        expect(incomingRequest.headers[Utils.headerize(name)]).toEqual([{ raw: newValue }]);
      });
    });

    describe(".toString", () => {
      it("returns the data instance variable", () => {
        const data = "data";
        incomingRequest.data = data;
        expect(incomingRequest.toString()).toBe(data);
        expect(incomingRequest.toString()).toBe(incomingRequest.data);
      });
    });
  });

  describe("IncomingResponse", () => {
    let incomingResponse: IncomingResponse;

    beforeEach(() => {
      incomingResponse = new IncomingResponse();
    });

    it("initialize the instance variables", () => {
      expect(incomingResponse.data).toBeUndefined();
      expect(incomingResponse.headers).toBeDefined();
      expect(incomingResponse.method).toBeUndefined();
      expect(incomingResponse.via).toBeUndefined();
      expect(incomingResponse.viaBranch).toBeUndefined();
      expect(incomingResponse.callId).toBeUndefined();
      expect(incomingResponse.cseq).toBeUndefined();
      expect(incomingResponse.from).toBeUndefined();
      expect(incomingResponse.fromTag).toBeUndefined();
      expect(incomingResponse.to).toBeUndefined();
      expect(incomingResponse.toTag).toBeUndefined();
      expect(incomingResponse.body).toBeUndefined();
      expect(incomingResponse.statusCode).toBeUndefined();
      expect(incomingResponse.reasonPhrase).toBeUndefined();
    });

    describe(".addHeader", () => {
      it("creates the header in the headers object if it does not already exist", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingResponse.addHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
      });

      it("adds the header to the array in the headers object if it already exists", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value1 = "value1";
        incomingResponse.addHeader(name, value1);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }]);
        const value2 = "value2";
        incomingResponse.addHeader(name, value2);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }, { raw: value2 }]);
      });
    });

    describe(".getHeader", () => {
      it("returns undefined if the header does not exist", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        expect(incomingResponse.getHeader(name)).toBeUndefined();
      });
      it("returns the value of the header that exists", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingResponse.addHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
      });
      it("returns the first header value if multiple values exist", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value1 = "value1";
        const value2 = "value2";
        incomingResponse.addHeader(name, value1);
        incomingResponse.addHeader(name, value2);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }, { raw: value2 }]);
        expect(incomingResponse.getHeader(name)).toBe(value1);
        expect(incomingResponse.getHeader(name)).not.toBe(value2);
      });
    });

    describe(".getHeaders", () => {
      it("returns an empty array if the header does not exist", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        expect(incomingResponse.getHeaders(name).length).toEqual(0);
        expect(incomingResponse.getHeaders(name)).toEqual([]);
      });
      it("returns an array with one value if there is only one value for the header provided", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingResponse.addHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        expect(incomingResponse.getHeaders(name).length).toEqual(1);
        expect(incomingResponse.getHeaders(name)).toEqual([value]);
      });

      it("returns an array with all of the values if they exist for the header provided", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value1 = "value1";
        incomingResponse.addHeader(name, value1);
        const value2 = "value2";
        incomingResponse.addHeader(name, value2);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value1 }, { raw: value2 }]);
        expect(incomingResponse.getHeaders(name).length).toEqual(2);
        expect(incomingResponse.getHeaders(name)).toEqual([value1, value2]);
      });
    });

    describe(".hasHeader", () => {
      it("returns true if the header exists", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingResponse.addHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        expect(incomingResponse.hasHeader(name)).toBe(true);
      });
      it("returns false if the header does not exist", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        expect(incomingResponse.hasHeader(name)).toBe(false);
      });
    });

    describe(".parseHeader", () => {
      beforeEach(() => {
        spyOn(Grammar, "parse").and.callThrough();
      });

      it("returns undefined if the header does not exist in the headers object", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        expect(incomingResponse.parseHeader(name)).toBeUndefined();
      });
      it("returns undefined if the idx is greater than the array for the header that exists", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingResponse.addHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        const index = 1;
        expect(incomingResponse.parseHeader(name, index)).toBeUndefined();
        expect(incomingResponse.getHeaders(name).length).toBeGreaterThan(index - 1);
      });

      it("returns the already parsed header if it exists", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "call-ID";
        const value = "hnds3k17jhd1jank84hq";
        incomingResponse.addHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        incomingResponse.parseHeader(name, 0);
        expect((Grammar.parse as any).calls.count()).toEqual(1);
        expect(incomingResponse.headers[Utils.headerize(name)][0].parsed).toBeDefined();
        expect(incomingResponse.parseHeader(name, 0)).toBe(incomingResponse.headers[Utils.headerize(name)][0].parsed);
        expect((Grammar.parse as any).calls.count()).toEqual(1);
      });

      it("returns a newly parsed header and creates a parsed property", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "call-ID";
        const value = "hnds3k17jhd1jank84hq";
        incomingResponse.addHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        expect(incomingResponse.headers[Utils.headerize(name)][0].parsed).toBeUndefined();
        expect(incomingResponse.parseHeader(name, 0)).toBe(value);
        expect(incomingResponse.headers[Utils.headerize(name)][0].parsed).toBe(value);
      });
    });

    describe(".setHeader", () => {
      it("adds the header if it does not alredy exist", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingResponse.setHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
      });
      it("replaces a header that already exists", () => {
        expect(incomingResponse.headers).toEqual({});
        const name = "name";
        const value = "value";
        incomingResponse.setHeader(name, value);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: value }]);
        const newValue = "new_value";
        incomingResponse.setHeader(name, newValue);
        expect(incomingResponse.headers[Utils.headerize(name)]).not.toEqual([{ raw: value }]);
        expect(incomingResponse.headers[Utils.headerize(name)]).toEqual([{ raw: newValue }]);
      });
    });

    describe(".toString", () => {
      it("returns the data instance variable", () => {
        const data = "data";
        incomingResponse.data = data;
        expect(incomingResponse.toString()).toBe(data);
        expect(incomingResponse.toString()).toBe(incomingResponse.data);
      });
    });
  });
});
