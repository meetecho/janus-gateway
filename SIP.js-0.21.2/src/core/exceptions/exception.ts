/**
 * An Exception is considered a condition that a reasonable application may wish to catch.
 * An Error indicates serious problems that a reasonable application should not try to catch.
 * @public
 */
export abstract class Exception extends Error {
  protected constructor(message?: string) {
    super(message); // 'Error' breaks prototype chain here
    Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
  }
}
