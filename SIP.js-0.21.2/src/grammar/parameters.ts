/**
 * @internal
 */
export class Parameters {
  public parameters: {[name: string]: string | null} = {};

  constructor(parameters: {[name: string]: string | number | null | undefined}) {
    // for in is required here as the Grammar parser is adding to the prototype chain
    for (const param in parameters) {
      // eslint-disable-next-line no-prototype-builtins
      if (parameters.hasOwnProperty(param)) {
        this.setParam(param, parameters[param]);
      }
    }
  }

  public setParam(key: string, value: string | number | null | undefined): void {
    if (key) {
      this.parameters[key.toLowerCase()] = (typeof value === "undefined" || value === null) ? null : value.toString();
    }
  }

  public getParam(key: string): string | null | undefined {
    if (key) {
      return this.parameters[key.toLowerCase()];
    }
  }

  public hasParam(key: string): boolean {
    return !!(key && this.parameters[key.toLowerCase()] !== undefined);
  }

  public deleteParam(key: string): string | null | undefined {
    key = key.toLowerCase();
    if (this.hasParam(key)) {
      const value = this.parameters[key];
      delete this.parameters[key];
      return value;
    }
  }

  public clearParams(): void {
    this.parameters = {};
  }
}
