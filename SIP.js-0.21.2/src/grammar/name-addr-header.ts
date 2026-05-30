import { Parameters } from "./parameters.js";
import { URI } from "./uri.js";

/**
 * Name Address SIP header.
 * @public
 */
export class NameAddrHeader extends Parameters {
  public uri: URI;

  private _displayName: string;

  /**
   * Constructor
   * @param uri -
   * @param displayName -
   * @param parameters -
   */
  constructor(uri: URI, displayName: string, parameters: { [name: string]: string }) {
    super(parameters);
    this.uri = uri;
    this._displayName = displayName;
  }

  get friendlyName(): string {
    return this.displayName || this.uri.aor;
  }

  get displayName(): string { return this._displayName; }
  set displayName(value: string) {
    this._displayName = value;
  }

  public clone(): NameAddrHeader {
    return new NameAddrHeader(
      this.uri.clone(),
      this._displayName,
      JSON.parse(JSON.stringify(this.parameters)));
  }

  public toString(): string {
    let body: string = (this.displayName || this.displayName === "0") ? '"' + this.displayName + '" ' : "";
    body += "<" + this.uri.toString() + ">";

    for (const parameter in this.parameters) {
      // eslint-disable-next-line no-prototype-builtins
      if (this.parameters.hasOwnProperty(parameter)) {
        body += ";" + parameter;

        if (this.parameters[parameter] !== null) {
          body += "=" + this.parameters[parameter];
        }
      }
    }

    return body;
  }
}
