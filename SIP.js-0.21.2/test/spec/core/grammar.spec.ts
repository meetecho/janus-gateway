/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { Grammar, NameAddrHeader, URI } from "../../../lib/grammar/index.js";

// TODO:
// These old tests were ported from JavaScript to TypesSript verbatim.
// The next time the Grammar gets a work over, these should be reviewed.

describe("Core Grammar", () => {
  function itHas(objThunk: () => any, property: string, value: any) {
    const testName = "has " + property + ": " + JSON.stringify(value);
    it(testName, () => {
      expect(objThunk()[property]).toEqual(value);
    });
  }

  function itsMethodReturns(objThunk: () => any, methodName: string, methodArg: any, expected: any) {
    const testName = methodName + '("' + methodArg + '") is ' + JSON.stringify(expected);
    it(testName, () => {
      expect(objThunk()[methodName](methodArg)).toEqual(expected);
    });
  }

  const contactString =
    '"Iñaki @ł€" <SIP:+1234@ALIAX.net;Transport=WS>;+sip.Instance="abCD", sip:bob@biloxi.COM;headerParam, <sips:DOMAIN.com:5>';
  describe("Contacts parsed from '" + contactString + "'", () => {
    let contacts: any;

    beforeEach(() => {
      contacts = Grammar.parse(contactString, "Contact");
      expect(contacts.length).toEqual(3);
    });

    describe("first contact", () => {
      let c1: any;

      beforeEach(() => {
        c1 = contacts[0].parsed;
      });

      it("is a NameAddrHeader", () => {
        expect(c1 instanceof NameAddrHeader).toBeTruthy();
      });

      it("has the display name", () => {
        expect(c1.displayName).toEqual("Iñaki @ł€");
      });

      it('has parameter +sip.instance set to "abCD"', () => {
        const paramName = "+sip.instance";
        expect(c1.hasParam(paramName)).toBeTruthy();
        expect(c1.getParam(paramName)).toEqual('"abCD"');
      });

      it("doesn't have parameter nooo", () => {
        const paramName = "nooo";
        expect(c1.hasParam(paramName)).toBeFalsy();
        expect(c1.getParam(paramName)).toBeUndefined();
      });

      describe("its URI", () => {
        const uriThunk = () => c1.uri;
        it("is a URI", () => {
          expect(uriThunk() instanceof URI).toBeTruthy();
        });

        const uriHas = itHas.bind(null, uriThunk);
        const uriReturns = itsMethodReturns.bind(null, uriThunk);

        uriHas("scheme", "sip");
        uriHas("user", "+1234");
        uriHas("host", "aliax.net");
        uriHas("port", undefined);

        uriReturns("getParam", "transport", "ws");
        uriReturns("getParam", "foo", undefined);
        uriReturns("getHeader", "X-Header", undefined);
      });

      it("can alter display name and URI parameters", () => {
        c1.displayName = "€€€";
        expect(c1.displayName).toEqual("€€€");
        c1.uri.user = "+999";
        expect(c1.uri.user).toEqual("+999");
        c1.setParam("+sip.instance", '"zxCV"');
        expect(c1.getParam("+SIP.instance")).toEqual('"zxCV"');
        c1.setParam("New-Param", null);
        expect(c1.hasParam("NEW-param")).toEqual(true);
        c1.uri.setParam("New-Param", null);
        expect(c1.toString()).toEqual(
          '"€€€" <sip:+999@aliax.net;transport=ws;new-param>;+sip.instance="zxCV";new-param'
        );
      });
    });

    describe("second contact", () => {
      let c2: any;

      beforeEach(() => {
        c2 = contacts[1].parsed;
      });

      const c2Thunk = () => c2;
      const c2Has = itHas.bind(null, c2Thunk);
      const c2Returns = itsMethodReturns.bind(null, c2Thunk);

      c2Has("displayName", undefined);

      c2Returns("hasParam", "HEADERPARAM", true);
      c2Returns("toString", null, "<sip:bob@biloxi.com>;headerparam");

      describe("its URI", () => {
        const uriThunk = () => c2.uri;
        it("is a URI", () => {
          expect(uriThunk() instanceof URI).toBeTruthy();
        });

        const uriHas = itHas.bind(null, uriThunk);

        uriHas("scheme", "sip");
        uriHas("user", "bob");
        uriHas("host", "biloxi.com");
        uriHas("port", undefined);

        itsMethodReturns(uriThunk, "hasParam", "headerParam", false);

        it("can alter display name", () => {
          c2.displayName = "@ł€ĸłæß";
          expect(c2.toString()).toEqual('"@ł€ĸłæß" <sip:bob@biloxi.com>;headerparam');
        });
      });
    });

    describe("third contact", () => {
      let c3: any;

      beforeEach(() => {
        c3 = contacts[2].parsed;
      });

      const c3Thunk = () => c3;
      itHas(c3Thunk, "displayName", undefined);
      itsMethodReturns(c3Thunk, "toString", null, "<sips:domain.com:5>");

      describe("its URI", () => {
        const uriThunk = () => c3.uri;
        it("is a URI", () => {
          expect(uriThunk() instanceof URI).toBeTruthy();
        });

        const uriHas = itHas.bind(null, uriThunk);

        uriHas("scheme", "sips");
        uriHas("user", undefined);
        uriHas("host", "domain.com");
        uriHas("port", 5);

        itsMethodReturns(uriThunk, "hasParam", "nooo", false);

        it("can set header params and uri params", () => {
          c3.uri.setParam("newUriParam", "zxCV");
          c3.setParam("newHeaderParam", "zxCV");
          expect(c3.toString()).toEqual("<sips:domain.com:5;newuriparam=zxCV>;newheaderparam=zxCV");
        });
      });
    });
  });

  const viaString = "SIP /  3.0 \r\n / UDP [1:ab::FF]:6060 ;\r\n  BRanch=1234;Param1=Foo;paRAM2;param3=Bar";
  describe('Via parsed from "' + viaString + '"', () => {
    let via: any;

    beforeEach(() => {
      via = Grammar.parse(viaString, "Via");
    });

    const viaHas = itHas.bind(null, () => via);

    viaHas("protocol", "SIP");
    viaHas("transport", "UDP");
    viaHas("host", "[1:ab::FF]");
    viaHas("host_type", "IPv6");
    viaHas("port", 6060);
    viaHas("branch", "1234");
    viaHas("params", { param1: "Foo", param2: undefined, param3: "Bar" });
  });

  const cseqString = "123456  CHICKEN";
  describe('CSeq parsed from "' + cseqString + '"', () => {
    let cseq: any;

    beforeEach(() => {
      cseq = Grammar.parse(cseqString, "CSeq");
    });

    const cseqHas = itHas.bind(null, () => cseq);

    cseqHas("value", 123456);
    cseqHas("method", "CHICKEN");
  });

  // eslint-disable-next-line max-len
  const challengeString =
    'Digest realm =  "[1:ABCD::abc]", nonce =  "31d0a89ed7781ce6877de5cb032bf114", qop="AUTH,autH-INt", algorithm =  md5  ,  stale =  TRUE , opaque = "00000188"';
  describe("challenge parsed from '" + challengeString + "'", () => {
    let challenge: any;

    beforeEach(() => {
      challenge = Grammar.parse(challengeString, "challenge");
    });

    const challengeHas = itHas.bind(null, () => challenge);

    challengeHas("realm", "[1:ABCD::abc]");
    challengeHas("nonce", "31d0a89ed7781ce6877de5cb032bf114");
    challengeHas("qop", ["auth", "auth-int"]);
    challengeHas("algorithm", "MD5");
    challengeHas("stale", true);
    challengeHas("opaque", "00000188");
  });

  const eventString = "Presence.winfo;Param1=QWe;paraM2";
  describe('Event parsed from "' + eventString + '"', () => {
    let evt: any;

    beforeEach(() => {
      evt = Grammar.parse(eventString, "Event");
    });

    const eventHas = itHas.bind(null, () => evt);

    eventHas("event", "presence.winfo");
    eventHas("params", { param1: "QWe", param2: undefined });
  });

  describe("Content-Disposition", () => {
    ["session", "render"].forEach((dispString) => {
      itHas(Grammar.parse.bind(Grammar, dispString, "Content_Disposition"), "type", dispString);
    });
  });

  const uuidString = "f6e15cd0-17ed-11e4-8c21-0800200c9a66";
  describe("parsing a UUID", () => {
    it("returns the input for correct UUIDs", () => {
      expect(Grammar.parse(uuidString, "uuid")).toEqual(uuidString);
    });

    it("returns -1 for incorrect UUIDs", () => {
      expect(Grammar.parse("XXX bad UUID XXX", "uuid")).toEqual(-1);
    });
  });

  describe("Replaces", () => {
    const goods = [
      "98732@sip.example.com\r\n" + "          ;from-tag=r33th4x0r\r\n" + "          ;to-tag=ff87ff",
      "12adf2f34456gs5;to-tag=12345;from-tag=54321;early-only", // early
      "12adf2f34456gs5;baz;to-tag=12345;early-only;from-tag=54321", // early
      "87134@171.161.34.23;to-tag=24796;from-tag=0",
      "87134@171.161.34.23;to-tag=24796;from-tag=0;foo=bar"
    ];

    const goodIds = [
      "98732@sip.example.com",
      "12adf2f34456gs5",
      "12adf2f34456gs5",
      "87134@171.161.34.23",
      "87134@171.161.34.23"
    ];

    const goodFroms = ["r33th4x0r", "54321", "54321", "0", "0"];

    const goodTos = ["ff87ff", "12345", "12345", "24796", "24796"];

    const bads = [
      "12adf2f34456gs5;to-tag1=12345;from-tag=54321;early-only",
      "12adf2f34456gs5;baz;to-tag=12345;from-tag=54321;",
      "87134@171.161.34.23;to-tag=24796;from-tag",
      "87134@171.161.34.23;to-tag;from-tag=0;foo=bar"
    ];

    it("parses the good examples", () => {
      for (let i = 0; i < goods.length; i++) {
        const parsed = Grammar.parse(goods[i], "Replaces");
        expect(parsed).not.toEqual(-1);
        expect(parsed.call_id).toEqual(goodIds[i]);
        expect(parsed.replaces_from_tag).toEqual(goodFroms[i]);
        expect(parsed.replaces_to_tag).toEqual(goodTos[i]);
        expect(parsed.early_only || false).toEqual(i === 1 || i === 2);
      }
    });

    it("rejects the bad examples", () => {
      for (let i = 0; i < bads.length; i++) {
        expect(Grammar.parse(bads[i], "Replaces")).toEqual(-1);
      }
    });
  });
});
