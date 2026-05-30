import { Grammar, URI, equivalentURI } from "../../../lib/grammar/index.js";

// TODO:
// These tests were ported to typescript verbatim.
// The next time the URI class gets a work over, these should be reviewed.

describe("Core URI", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let uri: any;
  let scheme: string;
  let user: string;
  let host: string;
  let port: number;

  beforeEach(() => {
    scheme = "sip";
    user = "alice";
    host = "test.com";
    port = 5060;
    uri = new URI(scheme, user, host, port);
  });

  it("defines parameters", () => {
    expect(uri.parameters).toBeDefined();
  });

  it("defines headers", () => {
    expect(uri.parameters).toBeDefined();
  });

  it("sets the scheme", () => {
    expect(uri.scheme).toBe(scheme || "sip");
  });

  it("sets the user", () => {
    expect(uri.user).toBe(user);
  });

  it("sets the host", () => {
    expect(uri.host).toBe(host);
  });

  it("sets the port", () => {
    expect(uri.port).toBe(port);
  });

  describe(".setParam", () => {
    beforeEach(() => {
      uri.parameters = {};
    });

    it("does not set a parameter with a undefined key", () => {
      uri.setParam(undefined, "value");
      expect(uri.parameters).toEqual({});
    });

    it("sets a parameter with a null value", () => {
      uri.setParam("key", null);
      expect(uri.parameters).toEqual({ key: null });
    });

    it("sets a parameter with a key and value", () => {
      uri.setParam("key", "value");
      expect(uri.parameters).toEqual({ key: "value" });
    });

    it("sets a parameter and make the key lowercase", () => {
      uri.setParam("KEY", "value");
      expect(uri.parameters).toEqual({ key: "value" });
    });

    it("sets a parameter and doesn't change the case", () => {
      uri.setParam("key", "VALUE");
      expect(uri.parameters).toEqual({ key: "VALUE" });
    });
  });

  describe(".getParam", () => {
    beforeEach(() => {
      uri.parameters = {};
    });

    it("does not get a parameter for a undefined key", () => {
      uri.setParam("key", "value");
      expect(uri.getParam(undefined)).toBeUndefined();
    });

    it("gets a parameter for a key", () => {
      uri.setParam("key", "value");
      expect(uri.getParam("key")).toBe("value");
    });

    it("gets a parameter for a key that is uppercase", () => {
      uri.setParam("KEY", "value");
      expect(uri.getParam("KEY")).toBe("value");
    });
  });

  describe(".hasParam", () => {
    beforeEach(() => {
      uri.parameters = { key: "value" };
    });

    it("is false for a undefined key", () => {
      expect(uri.hasParam(undefined)).toBeFalsy();
    });

    it("is false for a parameter that does not exist", () => {
      expect(uri.hasParam("doesNotExist")).toBeFalsy();
    });

    it("is true for a parameter that does exist", () => {
      expect(uri.hasParam("key")).toBeTruthy();
    });

    it("is true for a parameter that does exist regardless of case", () => {
      expect(uri.hasParam("KEY")).toBeTruthy();
    });
  });

  describe(".deleteParam", () => {
    beforeEach(() => {
      uri.parameters = { key: "value", key2: "value2" };
    });

    it("deletes the entry from the parameters list", () => {
      uri.deleteParam("key");
      expect(uri.hasParam("key")).toBeFalsy();
    });

    it("returns the value of the deleted key", () => {
      expect(uri.deleteParam("key")).toEqual("value");
    });

    it("does not delete a key that does not exist", () => {
      uri.deleteParam("does not exist");
      expect(uri.parameters).toEqual({ key: "value", key2: "value2" });
    });

    it("does not return a value if the key does not exist", () => {
      expect(uri.deleteParam("does not exist")).toBeUndefined();
    });
  });

  describe(".clearParams", () => {
    beforeEach(() => {
      uri.parameters = { key: "value", key2: "value2" };
    });

    it("empties the parameter list", () => {
      uri.clearParams();
      expect(uri.parameters).toEqual({});
    });

    it("does not make the parameter list undefined", () => {
      uri.clearParams();
      expect(uri.parameters).toBeDefined();
    });
  });

  describe(".setHeader", () => {
    it("adds the header if it does not exist", () => {
      expect(uri.headers).toEqual({});
      const name = "name";
      const value = "value";
      uri.setHeader(name, value);
      expect(uri.headers).toEqual({ Name: [value] });
    });

    it("replaces the header if it already exists", () => {
      expect(uri.headers).toEqual({});
      const name = "name";
      const value1 = "value1";
      uri.setHeader(name, value1);
      expect(uri.headers).toEqual({ Name: [value1] });
      const value2 = "value2";
      uri.setHeader(name, value2);
      expect(uri.headers).not.toEqual({ Name: [value1] });
      expect(uri.headers).toEqual({ Name: [value2] });
    });
  });

  describe(".getHeader", () => {
    it("returns undefined if the header does not exist", () => {
      expect(uri.headers).toEqual({});
      expect(uri.getHeader("anything")).toBeUndefined();
    });

    it("returns an array of the header that it found", () => {
      expect(uri.headers).toEqual({});
      const name = "name";
      const value = "value";
      uri.setHeader(name, value);
      expect(uri.headers).toEqual({ Name: [value] });
      expect(uri.getHeader(name)).toEqual([value]);
    });
  });

  describe(".hasHeader", () => {
    it("returns true if the header exists", () => {
      expect(uri.headers).toEqual({});
      const name = "name";
      const value = "value";
      uri.setHeader(name, value);
      expect(uri.headers).toEqual({ Name: [value] });
      expect(uri.hasHeader(name)).toBe(true);
    });
    it("returns false if the header does not exist", () => {
      expect(uri.headers).toEqual({});
      expect(uri.hasHeader("anything")).toBe(false);
    });
  });

  describe(".deleteHeader", () => {
    it("deletes the given header from the headers list", () => {
      expect(uri.headers).toEqual({});
      const name1 = "name1";
      const value1 = "value1";
      const name2 = "name2";
      const value2 = "value2";
      uri.setHeader(name1, value1);
      uri.setHeader(name2, value2);
      expect(uri.headers).toEqual({ Name1: [value1], Name2: [value2] });
      uri.deleteHeader(name1);
      expect(uri.headers).not.toEqual({ Name1: [value1], Name2: [value2] });
      expect(uri.headers).toEqual({ Name2: [value2] });
    });

    it("returns the deleted value", () => {
      expect(uri.headers).toEqual({});
      const name1 = "name1";
      const value1 = "value1";
      const name2 = "name2";
      const value2 = "value2";
      uri.setHeader(name1, value1);
      uri.setHeader(name2, value2);
      expect(uri.headers).toEqual({ Name1: [value1], Name2: [value2] });
      expect(uri.deleteHeader(name1)).toEqual([value1]);
      expect(uri.headers).not.toEqual({ Name1: [value1], Name2: [value2] });
      expect(uri.headers).toEqual({ Name2: [value2] });
    });

    it("does not delete anything if it cannot find the header", () => {
      expect(uri.headers).toEqual({});
      const name1 = "name1";
      const value1 = "value1";
      const name2 = "name2";
      const value2 = "value2";
      uri.setHeader(name1, value1);
      uri.setHeader(name2, value2);
      expect(uri.headers).toEqual({ Name1: [value1], Name2: [value2] });
      expect(uri.deleteHeader("name3")).toBeUndefined();
      expect(uri.headers).toEqual({ Name1: [value1], Name2: [value2] });
    });
  });

  describe(".clearHeaders", () => {
    it("should remove all the headers from the headers variable", () => {
      expect(uri.headers).toEqual({});
      const name1 = "name1";
      const value1 = "value1";
      const name2 = "name2";
      const value2 = "value2";
      uri.setHeader(name1, value1);
      uri.setHeader(name2, value2);
      expect(uri.headers).toEqual({ Name1: [value1], Name2: [value2] });
      uri.clearHeaders();
      expect(uri.headers).toEqual({});
    });
  });

  it(".clone: be able to clone itself", () => {
    const clonedURI = uri.clone();

    expect(clonedURI).toBeDefined();

    expect(clonedURI).toEqual(uri);

    expect(clonedURI.scheme).toEqual(uri.scheme);
    expect(clonedURI.user).toEqual(uri.user);
    expect(clonedURI.host).toEqual(uri.host);
    expect(clonedURI.port).toEqual(uri.port);
    expect(clonedURI.parameters).toEqual(uri.parameters);
    expect(clonedURI.headers).toEqual(uri.headers);

    expect(clonedURI._raw.scheme).toEqual(uri._raw.scheme);
    expect(clonedURI._raw.user).toEqual(uri._raw.user);
    expect(clonedURI._raw.host).toEqual(uri._raw.host);
    expect(clonedURI._raw.port).toEqual(uri._raw.port);
  });

  it(".toString: be able to create a string of itself", () => {
    expect(typeof uri.toString()).toEqual("string");
  });

  it("should parse a URI from a valid string", () => {
    const parsedURI = Grammar.URIParse("sip:" + user + "@" + host);

    expect(parsedURI).toBeDefined();

    if (!parsedURI) {
      throw new Error("parsedURI undefined");
    }

    expect(parsedURI.user).toEqual(user);
    expect(parsedURI.user).toEqual(uri.user);

    expect(parsedURI.host).toEqual(host);
    expect(parsedURI.host).toEqual(uri.host);
  });

  it(".parse does not parse a URI from an invalid string", () => {
    const parsedURI = Grammar.URIParse(user + host);

    expect(parsedURI).toBeUndefined();
  });

  const toParse =
    "SIP:%61liCE@versaTICA.Com:6060;TRansport=TCp;Foo=ABc;baz?X-Header-1=AaA1&X-Header-2=BbB&x-header-1=AAA2";

  describe('URI.parse with "' + toParse + '"', () => {
    beforeEach(() => {
      uri = Grammar.URIParse(toParse);
    });

    it("produces a SIP.URI", () => {
      expect(uri instanceof URI).toBe(true);
    });

    function itParses(property: string, expected: string | number): void {
      it("parses the " + property, () => {
        expect(uri[property]).toEqual(expected);
      });
    }

    itParses("scheme", "sip");
    itParses("user", "aliCE");
    itParses("host", "versatica.com");
    itParses("port", 6060);

    it('parses non-undefined parameter "transport"', () => {
      expect(uri.hasParam("transport")).toEqual(true);
      expect(uri.getParam("transport")).toEqual("tcp");
    });

    it('doesn\'t parse missing parameter "nooo"', () => {
      expect(uri.hasParam("nooo")).toEqual(false);
      expect(uri.getParam("nooo")).toEqual(undefined);
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    function itsMethod(testName: string, methodName: string, methodArg: any, expected: any): void {
      it(testName, () => {
        expect(uri[methodName](methodArg)).toEqual(expected);
      });
    }

    itsMethod("parses non-undefined parameter foo", "getParam", "foo", "ABc");
    itsMethod("parses null parameter baz", "getParam", "baz", null);
    itsMethod("parses header list x-header-1", "getHeader", "x-header-1", ["AaA1", "AAA2"]);
    itsMethod("parses header X-HEADER-2", "getHeader", "X-HEADER-2", ["BbB"]);
    itsMethod('doesn\'t parse missing header "nooo"', "getHeader", "nooo", undefined);
    // eslint-disable-next-line max-len
    itsMethod(
      "correctly toString()s itself",
      "toString",
      undefined,
      "sip:aliCE@versatica.com:6060;transport=tcp;foo=ABc;baz?X-Header-1=AaA1&X-Header-1=AAA2&X-Header-2=BbB"
    );
    // eslint-disable-next-line max-len
    itsMethod(
      "correctly toRaw()s itself",
      "toRaw",
      undefined,
      "SIP:aliCE@versaTICA.Com:6060;transport=tcp;foo=ABc;baz?X-Header-1=AaA1&X-Header-1=AAA2&X-Header-2=BbB"
    );

    const newUser = "Iñaki:PASSWD";
    describe('when setting the user to "' + newUser + '"', () => {
      beforeEach(() => {
        uri.user = newUser;
      });

      it("sets the user correctly", () => {
        expect(uri.user).toEqual(newUser);
      });

      it('can delete parameter "foo" and delete header "x-header-1"', () => {
        expect(uri.deleteParam("foo")).toEqual("ABc");
        expect(uri.deleteHeader("x-header-1")).toEqual(["AaA1", "AAA2"]);
        expect(uri.toString()).toEqual("sip:I%C3%B1aki:PASSWD@versatica.com:6060;transport=tcp;baz?X-Header-2=BbB");
      });

      it("can clear parameters and headers, and nullify the port", () => {
        uri.clearParams();
        uri.clearHeaders();
        uri.port = undefined;
        expect(uri.toString()).toEqual("sip:I%C3%B1aki:PASSWD@versatica.com");
      });
    });
  });

  describe("equivalentURI", () => {
    it("equivalent - 1", () => {
      const a = Grammar.URIParse("sip:%61lice@atlanta.com;transport=TCP");
      const b = Grammar.URIParse("sip:alice@AtLanTa.CoM;Transport=tcp");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(true);
      }
    });

    it("equivalent - 2", () => {
      const a = Grammar.URIParse("sip:carol@chicago.com");
      const b = Grammar.URIParse("sip:carol@chicago.com;security=off");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(true);
      }
    });

    it("equivalent - 3", () => {
      const a = Grammar.URIParse("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com");
      const b = Grammar.URIParse("sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(true);
      }
    });

    it("equivalent - 4", () => {
      const a = Grammar.URIParse("sip:alice@atlanta.com?subject=project%20x&priority=urgent");
      const b = Grammar.URIParse("sip:alice@atlanta.com?priority=urgent&subject=project%20x");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(true);
      }
    });

    it("not equivalent - different usernames", () => {
      const a = Grammar.URIParse("SIP:ALICE@AtLanTa.CoM;Transport=udp");
      const b = Grammar.URIParse("sip:alice@AtLanTa.CoM;Transport=UDP");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(false);
      }
    });

    it("not equivalent - can resolve to different ports", () => {
      const a = Grammar.URIParse("sip:bob@biloxi.com");
      const b = Grammar.URIParse("sip:bob@biloxi.com:5060");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(false);
      }
    });

    it("not equivalent - can resolve to different transports", () => {
      const a = Grammar.URIParse("sip:bob@biloxi.com");
      const b = Grammar.URIParse("sip:bob@biloxi.com;transport=udp");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(false);
      }
    });

    it("not equivalent - different header component", () => {
      const a = Grammar.URIParse("sip:carol@chicago.com");
      const b = Grammar.URIParse("sip:carol@chicago.com?Subject=next%20meeting");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(false);
      }
    });

    it("not equivalent - transitive", () => {
      const a = Grammar.URIParse("sip:carol@chicago.com;security=on");
      const b = Grammar.URIParse("sip:carol@chicago.com;security=off");
      expect(a instanceof URI).toBe(true);
      expect(b instanceof URI).toBe(true);
      if (a instanceof URI && b instanceof URI) {
        expect(equivalentURI(a, b)).toEqual(false);
      }
    });
  });
});
