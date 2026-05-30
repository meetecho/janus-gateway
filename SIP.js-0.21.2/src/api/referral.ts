import { NameAddrHeader } from "../grammar/name-addr-header.js";
import { IncomingReferRequest } from "../core/messages/methods/refer.js";
import { IncomingRequestMessage } from "../core/messages/incoming-request-message.js";
import { ResponseOptions } from "../core/messages/outgoing-response.js";
import { Inviter } from "./inviter.js";
import { InviterOptions } from "./inviter-options.js";
import { Session } from "./session.js";

/**
 * A request to establish a {@link Session} elsewhere (incoming REFER).
 * @public
 */
export class Referral {
  private inviter: Inviter | undefined;

  /** @internal */
  public constructor(private incomingReferRequest: IncomingReferRequest, private session: Session) {}

  public get referTo(): NameAddrHeader {
    const referTo = this.incomingReferRequest.message.parseHeader("refer-to");
    if (!(referTo instanceof NameAddrHeader)) {
      throw new Error("Failed to parse Refer-To header.");
    }
    return referTo;
  }

  public get referredBy(): string | undefined {
    return this.incomingReferRequest.message.getHeader("referred-by");
  }

  public get replaces(): string | undefined {
    const value = this.referTo.uri.getHeader("replaces");
    if (value instanceof Array) {
      return value[0];
    }
    return value;
  }

  /** Incoming REFER request message. */
  public get request(): IncomingRequestMessage {
    return this.incomingReferRequest.message;
  }

  /** Accept the request. */
  public accept(options: ResponseOptions = { statusCode: 202 }): Promise<void> {
    this.incomingReferRequest.accept(options);
    return Promise.resolve();
  }

  /** Reject the request. */
  public reject(options?: ResponseOptions): Promise<void> {
    this.incomingReferRequest.reject(options);
    return Promise.resolve();
  }

  /**
   * Creates an inviter which may be used to send an out of dialog INVITE request.
   *
   * @remarks
   * This a helper method to create an Inviter which will execute the referral
   * of the `Session` which was referred. The appropriate headers are set and
   * the referred `Session` is linked to the new `Session`. Note that only a
   * single instance of the `Inviter` will be created and returned (if called
   * more than once a reference to the same `Inviter` will be returned every time).
   *
   * @param options - Options bucket.
   * @param modifiers - Session description handler modifiers.
   */
  public makeInviter(options?: InviterOptions): Inviter {
    if (this.inviter) {
      return this.inviter;
    }
    const targetURI = this.referTo.uri.clone();
    targetURI.clearHeaders();
    options = options || {};
    const extraHeaders = (options.extraHeaders || []).slice();
    const replaces = this.replaces;
    if (replaces) {
      // decodeURIComponent is a holdover from 2c086eb4. Not sure that it is actually necessary
      extraHeaders.push("Replaces: " + decodeURIComponent(replaces));
    }
    const referredBy = this.referredBy;
    if (referredBy) {
      extraHeaders.push("Referred-By: " + referredBy);
    }
    options.extraHeaders = extraHeaders;
    this.inviter = this.session.userAgent._makeInviter(targetURI, options);
    this.inviter._referred = this.session;
    this.session._referral = this.inviter;
    return this.inviter;
  }
}
