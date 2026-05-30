/* eslint-disable @typescript-eslint/no-explicit-any */
import { Grammar, NameAddrHeader, URI } from "../../../lib/grammar/index.js";

// TODO:
// These old tests were ported from JavaScript to TypesSript verbatim.
// The next time the NameAddrHeader gets a work over, these should be reviewed.

describe("Core NameAddrHeader", () => {
  let name: NameAddrHeader;
  let name2: NameAddrHeader;
  let uri;

  const scheme = "sip";
  const user = "alice";
  const host = "sip.js.net";
  const displayName = "Alice æßð";

  const toStringUri = "<" + scheme + ":" + user + "@" + host + ">";
  const toStringAll = '"' + displayName + '" ' + toStringUri;

  beforeEach(() => {
    uri = new URI(scheme, user, host);
    name = new NameAddrHeader(uri, displayName, {});
  });

  it("has the display name", () => {
    expect(name.displayName).toBe(displayName);
  });

  it("can create a string of itself", () => {
    expect(name.toString()).toEqual(toStringAll);
  });

  it("can set the display name to 0", () => {
    name.displayName = "0";
    expect(name.toString()).toEqual('"0" ' + toStringUri);
  });

  it('can set the display name to ""', () => {
    name.displayName = "";
    expect(name.toString()).toEqual(toStringUri);
  });

  it("has an empty parameters object", () => {
    expect(name.parameters).toEqual({});
  });

  describe("when setting parameter Foo to undefined", () => {
    beforeEach(() => {
      name.setParam("Foo", undefined);
    });

    it("has parameter FOO", () => {
      expect(name.hasParam("FOO")).toBe(true);
    });

    describe("when setting parameter Baz to 123", () => {
      beforeEach(() => {
        name.setParam("Baz", 123);
      });

      it('has parameter baz set to "123"', () => {
        expect(name.getParam("baz")).toEqual("123");
      });

      it("can create a string of itself", () => {
        expect(name.toString()).toEqual(toStringAll + ";foo;baz=123");
      });

      it("can delete parameter bAz", () => {
        expect(name.deleteParam("bAz")).toEqual("123");
      });

      it("can clear its parameters", () => {
        name.clearParams();
        expect(name.toString()).toEqual(toStringAll);
      });
    });
  });

  describe("when cloning itself", () => {
    beforeEach(() => {
      name2 = name.clone();
    });

    it("has the same string representation as its clone", () => {
      expect(name2.toString()).toEqual(name.toString());
    });

    it("can set the display name of the clone", () => {
      const newDisplayName = "@ł€";
      name2.displayName = newDisplayName;
      expect(name2.displayName).toEqual(newDisplayName);
    });

    it("has an undefined user", () => {
      expect((name as any).user).toBeUndefined();
    });
  });

  // eslint-disable-next-line max-len
  const toParse =
    '"Iñaki ðđøþ" <SIP:%61liCE@versaTICA.Com:6060;TRansport=TCp;Foo=ABc;baz?X-Header-1=AaA1&X-Header-2=BbB&x-header-1=AAA2>;QWE=QWE;ASd';

  describe("when calling NameAddrHeader.parse('" + toParse + "')", () => {
    let header: any;

    beforeEach(() => {
      header = Grammar.nameAddrHeaderParse(toParse);
    });

    it("returns a NameAddrHeader", () => {
      expect(header instanceof NameAddrHeader).toBeTruthy();
    });

    it("parses the display name", () => {
      expect(header.displayName).toEqual("Iñaki ðđøþ");
    });

    function itsMethod(testName: string, methodName: string, methodArg: string, expected: any): void {
      it(testName, () => {
        expect(header[methodName](methodArg)).toEqual(expected);
      });
    }

    itsMethod('has parameter "qwe"', "hasParam", "qwe", true);
    itsMethod('gets parameter "qwe" as "QWE"', "getParam", "qwe", "QWE");
    itsMethod('has parameter "asd"', "hasParam", "asd", true);
    itsMethod('gets parameter "asd" as null', "getParam", "asd", null);
    itsMethod('doesn\'t have parameter "nooo"', "hasParam", "nooo", false);

    const newDispName = "Foo Bar";
    it('can set the display name to "' + newDispName + '"', () => {
      header.displayName = newDispName;
      expect(header.displayName).toEqual(newDispName);
    });

    const newDispName2 = undefined;
    it("can set the display name to " + newDispName2, () => {
      header.displayName = newDispName2;
      expect(header.displayName).toEqual(newDispName2);
      // eslint-disable-next-line max-len
      expect(header.toString()).toEqual(
        "<sip:aliCE@versatica.com:6060;transport=tcp;foo=ABc;baz?X-Header-1=AaA1&X-Header-1=AAA2&X-Header-2=BbB>;qwe=QWE;asd"
      );
    });

    describe("its URI:", () => {
      function itsUriParses(property: string, expected: any): void {
        it("parses the " + property, () => {
          expect(header.uri[property]).toEqual(expected);
        });
      }

      itsUriParses("scheme", "sip");
      itsUriParses("user", "aliCE");
      itsUriParses("host", "versatica.com");
      itsUriParses("port", 6060);

      function itsUriMethod(methodName: string, methodArg: string, expected: any): void {
        const testName = methodName + '("' + methodArg + '") is ' + JSON.stringify(expected);
        it(testName, () => {
          expect(header.uri[methodName](methodArg)).toEqual(expected);
        });
      }

      itsUriMethod("hasParam", "transport", true);
      itsUriMethod("getParam", "transport", "tcp");
      itsUriMethod("hasParam", "nooo", false);
      itsUriMethod("getParam", "foo", "ABc");
      itsUriMethod("getParam", "baz", null);
      itsUriMethod("getParam", "noo", undefined);
      itsUriMethod("getHeader", "x-header-1", ["AaA1", "AAA2"]);
      itsUriMethod("getHeader", "X-HEADER-2", ["BbB"]);
      itsUriMethod("getHeader", "nooo", undefined);
    });
  });
});
