import { Grammar } from "../../grammar/grammar.js";
import { NameAddrHeader } from "../../grammar/name-addr-header.js";
import { headerize } from "./utils.js";

/**
 * Incoming message.
 * @public
 */
export class IncomingMessage {
  public viaBranch!: string;
  public method!: string;
  public body!: string;
  public toTag!: string;
  public to!: NameAddrHeader;
  public fromTag!: string;
  public from!: NameAddrHeader;
  public callId!: string;
  public cseq!: number;
  public via!: { host: string; port: number };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public headers: { [name: string]: Array<{ parsed?: any; raw: string }> } = {};
  public referTo: string | undefined;
  public data!: string;

  /**
   * Insert a header of the given name and value into the last position of the
   * header array.
   * @param name - header name
   * @param value - header value
   */
  public addHeader(name: string, value: string): void {
    const header = { raw: value };
    name = headerize(name);

    if (this.headers[name]) {
      this.headers[name].push(header);
    } else {
      this.headers[name] = [header];
    }
  }

  /**
   * Get the value of the given header name at the given position.
   * @param name - header name
   * @returns Returns the specified header, undefined if header doesn't exist.
   */
  public getHeader(name: string): string | undefined {
    const header = this.headers[headerize(name)];

    if (header) {
      if (header[0]) {
        return header[0].raw;
      }
    } else {
      return;
    }
  }

  /**
   * Get the header/s of the given name.
   * @param name - header name
   * @returns Array - with all the headers of the specified name.
   */
  public getHeaders(name: string): Array<string> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const header: Array<any> = this.headers[headerize(name)];
    const result: Array<string> = [];

    if (!header) {
      return [];
    }
    for (const headerPart of header) {
      result.push(headerPart.raw);
    }
    return result;
  }

  /**
   * Verify the existence of the given header.
   * @param name - header name
   * @returns true if header with given name exists, false otherwise
   */
  public hasHeader(name: string): boolean {
    return !!this.headers[headerize(name)];
  }

  /**
   * Parse the given header on the given index.
   * @param name - header name
   * @param idx - header index
   * @returns Parsed header object, undefined if the
   *   header is not present or in case of a parsing error.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public parseHeader(name: string, idx = 0): any | undefined {
    name = headerize(name);

    if (!this.headers[name]) {
      // this.logger.log("header '" + name + "' not present");
      return;
    } else if (idx >= this.headers[name].length) {
      // this.logger.log("not so many '" + name + "' headers present");
      return;
    }

    const header = this.headers[name][idx];
    const value = header.raw;

    if (header.parsed) {
      return header.parsed;
    }

    // substitute '-' by '_' for grammar rule matching.
    const parsed: string | -1 = Grammar.parse(value, name.replace(/-/g, "_"));

    if (parsed === -1) {
      this.headers[name].splice(idx, 1); // delete from headers
      // this.logger.warn('error parsing "' + name + '" header field with value "' + value + '"');
      return;
    } else {
      header.parsed = parsed;
      return parsed;
    }
  }

  /**
   * Message Header attribute selector. Alias of parseHeader.
   * @param name - header name
   * @param idx - header index
   * @returns Parsed header object, undefined if the
   *   header is not present or in case of a parsing error.
   *
   * @example
   * message.s('via',3).port
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public s(name: string, idx = 0): any | undefined {
    return this.parseHeader(name, idx);
  }

  /**
   * Replace the value of the given header by the value.
   * @param name - header name
   * @param value - header value
   */
  public setHeader(name: string, value: string): void {
    this.headers[headerize(name)] = [{ raw: value }];
  }

  public toString(): string {
    return this.data;
  }
}
