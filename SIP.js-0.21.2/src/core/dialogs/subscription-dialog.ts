import { NameAddrHeader } from "../../grammar/name-addr-header.js";
import { Logger } from "../log/logger.js";
import { C } from "../messages/methods/constants.js";
import { IncomingRequestMessage } from "../messages/incoming-request-message.js";
import { OutgoingRequestMessage } from "../messages/outgoing-request-message.js";
import { OutgoingSubscribeRequest } from "../messages/methods/subscribe.js";
import { OutgoingSubscribeRequestDelegate } from "../messages/methods/subscribe.js";
import { RequestOptions } from "../messages/outgoing-request.js";
import { Subscription, SubscriptionState } from "../subscription/subscription.js";
import { SubscriptionDelegate } from "../subscription/subscription-delegate.js";
import { Timers } from "../timers.js";
import { AllowedMethods } from "../user-agent-core/allowed-methods.js";
import { UserAgentCore } from "../user-agent-core/user-agent-core.js";
import { NotifyUserAgentServer } from "../user-agents/notify-user-agent-server.js";
import { ReSubscribeUserAgentClient } from "../user-agents/re-subscribe-user-agent-client.js";
import { Dialog } from "./dialog.js";
import { DialogState } from "./dialog-state.js";

/**
 * Subscription Dialog.
 * @remarks
 * SIP-Specific Event Notification
 *
 * Abstract
 *
 *    This document describes an extension to the Session Initiation
 *    Protocol (SIP) defined by RFC 3261.  The purpose of this extension is
 *    to provide an extensible framework by which SIP nodes can request
 *    notification from remote nodes indicating that certain events have
 *    occurred.
 *
 *    Note that the event notification mechanisms defined herein are NOT
 *    intended to be a general-purpose infrastructure for all classes of
 *    event subscription and notification.
 *
 *    This document represents a backwards-compatible improvement on the
 *    original mechanism described by RFC 3265, taking into account several
 *    years of implementation experience.  Accordingly, this document
 *    obsoletes RFC 3265.  This document also updates RFC 4660 slightly to
 *    accommodate some small changes to the mechanism that were discussed
 *    in that document.
 *
 *  https://tools.ietf.org/html/rfc6665
 * @public
 */
export class SubscriptionDialog extends Dialog implements Subscription {
  public delegate: SubscriptionDelegate | undefined;

  private _autoRefresh: boolean;
  private _subscriptionEvent: string;
  private _subscriptionExpires: number;
  private _subscriptionExpiresInitial: number;
  private _subscriptionExpiresLastSet: number;
  private _subscriptionRefresh: number | undefined;
  private _subscriptionRefreshLastSet: number | undefined;
  private _subscriptionState: SubscriptionState;

  private logger: Logger;
  private N: number | undefined;
  private refreshTimer: number | undefined;

  constructor(
    subscriptionEvent: string,
    subscriptionExpires: number,
    subscriptionState: SubscriptionState,
    core: UserAgentCore,
    state: DialogState,
    delegate?: SubscriptionDelegate
  ) {
    super(core, state);
    this.delegate = delegate;
    this._autoRefresh = false;
    this._subscriptionEvent = subscriptionEvent;
    this._subscriptionExpires = subscriptionExpires;
    this._subscriptionExpiresInitial = subscriptionExpires;
    this._subscriptionExpiresLastSet = Math.floor(Date.now() / 1000);
    this._subscriptionRefresh = undefined;
    this._subscriptionRefreshLastSet = undefined;
    this._subscriptionState = subscriptionState;
    this.logger = core.loggerFactory.getLogger("sip.subscribe-dialog");
    this.logger.log(`SUBSCRIBE dialog ${this.id} constructed`);
  }

  /**
   * When a UAC receives a response that establishes a dialog, it
   * constructs the state of the dialog.  This state MUST be maintained
   * for the duration of the dialog.
   * https://tools.ietf.org/html/rfc3261#section-12.1.2
   * @param outgoingRequestMessage - Outgoing request message for dialog.
   * @param incomingResponseMessage - Incoming response message creating dialog.
   */
  public static initialDialogStateForSubscription(
    outgoingSubscribeRequestMessage: OutgoingRequestMessage,
    incomingNotifyRequestMessage: IncomingRequestMessage
  ): DialogState {
    // If the request was sent over TLS, and the Request-URI contained a
    // SIPS URI, the "secure" flag is set to TRUE.
    // https://tools.ietf.org/html/rfc3261#section-12.1.2
    const secure = false; // FIXME: Currently no support for TLS.

    // The route set MUST be set to the list of URIs in the Record-Route
    // header field from the response, taken in reverse order and preserving
    // all URI parameters.  If no Record-Route header field is present in
    // the response, the route set MUST be set to the empty set.  This route
    // set, even if empty, overrides any pre-existing route set for future
    // requests in this dialog.  The remote target MUST be set to the URI
    // from the Contact header field of the response.
    // https://tools.ietf.org/html/rfc3261#section-12.1.2
    const routeSet = incomingNotifyRequestMessage.getHeaders("record-route");
    const contact = incomingNotifyRequestMessage.parseHeader("contact");
    if (!contact) {
      // TODO: Review to make sure this will never happen
      throw new Error("Contact undefined.");
    }
    if (!(contact instanceof NameAddrHeader)) {
      throw new Error("Contact not instance of NameAddrHeader.");
    }
    const remoteTarget = contact.uri;

    // The local sequence number MUST be set to the value of the sequence
    // number in the CSeq header field of the request.  The remote sequence
    // number MUST be empty (it is established when the remote UA sends a
    // request within the dialog).  The call identifier component of the
    // dialog ID MUST be set to the value of the Call-ID in the request.
    // The local tag component of the dialog ID MUST be set to the tag in
    // the From field in the request, and the remote tag component of the
    // dialog ID MUST be set to the tag in the To field of the response.  A
    // UAC MUST be prepared to receive a response without a tag in the To
    // field, in which case the tag is considered to have a value of null.
    //
    //    This is to maintain backwards compatibility with RFC 2543, which
    //    did not mandate To tags.
    //
    // https://tools.ietf.org/html/rfc3261#section-12.1.2
    const localSequenceNumber = outgoingSubscribeRequestMessage.cseq;
    const remoteSequenceNumber = undefined;
    const callId = outgoingSubscribeRequestMessage.callId;
    const localTag = outgoingSubscribeRequestMessage.fromTag;
    const remoteTag = incomingNotifyRequestMessage.fromTag;
    if (!callId) {
      // TODO: Review to make sure this will never happen
      throw new Error("Call id undefined.");
    }
    if (!localTag) {
      // TODO: Review to make sure this will never happen
      throw new Error("From tag undefined.");
    }
    if (!remoteTag) {
      // TODO: Review to make sure this will never happen
      throw new Error("To tag undefined."); // FIXME: No backwards compatibility with RFC 2543
    }

    // The remote URI MUST be set to the URI in the To field, and the local
    // URI MUST be set to the URI in the From field.
    // https://tools.ietf.org/html/rfc3261#section-12.1.2
    if (!outgoingSubscribeRequestMessage.from) {
      // TODO: Review to make sure this will never happen
      throw new Error("From undefined.");
    }
    if (!outgoingSubscribeRequestMessage.to) {
      // TODO: Review to make sure this will never happen
      throw new Error("To undefined.");
    }
    const localURI = outgoingSubscribeRequestMessage.from.uri;
    const remoteURI = outgoingSubscribeRequestMessage.to.uri;

    // A dialog can also be in the "early" state, which occurs when it is
    // created with a provisional response, and then transition to the
    // "confirmed" state when a 2xx final response arrives.
    // https://tools.ietf.org/html/rfc3261#section-12
    const early = false;

    const dialogState: DialogState = {
      id: callId + localTag + remoteTag,
      early,
      callId,
      localTag,
      remoteTag,
      localSequenceNumber,
      remoteSequenceNumber,
      localURI,
      remoteURI,
      remoteTarget,
      routeSet,
      secure
    };
    return dialogState;
  }

  public dispose(): void {
    super.dispose();
    if (this.N) {
      clearTimeout(this.N);
      this.N = undefined;
    }
    this.refreshTimerClear();
    this.logger.log(`SUBSCRIBE dialog ${this.id} destroyed`);
  }

  get autoRefresh(): boolean {
    return this._autoRefresh;
  }

  set autoRefresh(autoRefresh: boolean) {
    this._autoRefresh = true;
    this.refreshTimerSet();
  }

  get subscriptionEvent(): string {
    return this._subscriptionEvent;
  }

  /** Number of seconds until subscription expires. */
  get subscriptionExpires(): number {
    const secondsSinceLastSet = Math.floor(Date.now() / 1000) - this._subscriptionExpiresLastSet;
    const secondsUntilExpires = this._subscriptionExpires - secondsSinceLastSet;
    return Math.max(secondsUntilExpires, 0);
  }

  set subscriptionExpires(expires: number) {
    if (expires < 0) {
      throw new Error("Expires must be greater than or equal to zero.");
    }
    this._subscriptionExpires = expires;
    this._subscriptionExpiresLastSet = Math.floor(Date.now() / 1000);
    if (this.autoRefresh) {
      const refresh = this.subscriptionRefresh;
      if (refresh === undefined || refresh >= expires) {
        this.refreshTimerSet();
      }
    }
  }

  get subscriptionExpiresInitial(): number {
    return this._subscriptionExpiresInitial;
  }

  /** Number of seconds until subscription auto refresh. */
  get subscriptionRefresh(): number | undefined {
    if (this._subscriptionRefresh === undefined || this._subscriptionRefreshLastSet === undefined) {
      return undefined;
    }
    const secondsSinceLastSet = Math.floor(Date.now() / 1000) - this._subscriptionRefreshLastSet;
    const secondsUntilExpires = this._subscriptionRefresh - secondsSinceLastSet;
    return Math.max(secondsUntilExpires, 0);
  }

  get subscriptionState(): SubscriptionState {
    return this._subscriptionState;
  }

  /**
   * Receive in dialog request message from transport.
   * @param message -  The incoming request message.
   */
  public receiveRequest(message: IncomingRequestMessage): void {
    this.logger.log(`SUBSCRIBE dialog ${this.id} received ${message.method} request`);

    // Request within a dialog out of sequence guard.
    // https://tools.ietf.org/html/rfc3261#section-12.2.2
    if (!this.sequenceGuard(message)) {
      this.logger.log(`SUBSCRIBE dialog ${this.id} rejected out of order ${message.method} request.`);
      return;
    }

    // Request within a dialog common processing.
    // https://tools.ietf.org/html/rfc3261#section-12.2.2
    super.receiveRequest(message);

    // Switch on method and then delegate.
    switch (message.method) {
      case C.NOTIFY:
        this.onNotify(message);
        break;
      default:
        this.logger.log(`SUBSCRIBE dialog ${this.id} received unimplemented ${message.method} request`);
        this.core.replyStateless(message, { statusCode: 501 });
        break;
    }
  }

  /**
   * 4.1.2.2.  Refreshing of Subscriptions
   * https://tools.ietf.org/html/rfc6665#section-4.1.2.2
   */
  public refresh(): OutgoingSubscribeRequest {
    const allowHeader = "Allow: " + AllowedMethods.toString();
    const options: RequestOptions = {};
    options.extraHeaders = (options.extraHeaders || []).slice();
    options.extraHeaders.push(allowHeader);
    options.extraHeaders.push("Event: " + this.subscriptionEvent);
    options.extraHeaders.push("Expires: " + this.subscriptionExpiresInitial);
    options.extraHeaders.push("Contact: " + this.core.configuration.contact.toString());
    return this.subscribe(undefined, options);
  }

  /**
   * 4.1.2.2.  Refreshing of Subscriptions
   * https://tools.ietf.org/html/rfc6665#section-4.1.2.2
   * @param delegate - Delegate to handle responses.
   * @param options - Options bucket.
   */
  public subscribe(
    delegate?: OutgoingSubscribeRequestDelegate,
    options: RequestOptions = {}
  ): OutgoingSubscribeRequest {
    if (this.subscriptionState !== SubscriptionState.Pending && this.subscriptionState !== SubscriptionState.Active) {
      // FIXME: This needs to be a proper exception
      throw new Error(
        `Invalid state ${this.subscriptionState}. May only re-subscribe while in state "pending" or "active".`
      );
    }
    this.logger.log(`SUBSCRIBE dialog ${this.id} sending SUBSCRIBE request`);
    const uac = new ReSubscribeUserAgentClient(this, delegate, options);
    // Abort any outstanding timer (as it would otherwise become guaranteed to terminate us).
    if (this.N) {
      clearTimeout(this.N);
      this.N = undefined;
    }
    if (!options.extraHeaders?.includes("Expires: 0")) {
      // When refreshing a subscription, a subscriber starts Timer N, set to
      // 64*T1, when it sends the SUBSCRIBE request.
      // https://tools.ietf.org/html/rfc6665#section-4.1.2.2
      this.N = setTimeout(() => this.timerN(), Timers.TIMER_N);
    }
    return uac;
  }

  /**
   * 4.4.1.  Dialog Creation and Termination
   * A subscription is destroyed after a notifier sends a NOTIFY request
   * with a "Subscription-State" of "terminated", or in certain error
   * situations described elsewhere in this document.
   * https://tools.ietf.org/html/rfc6665#section-4.4.1
   */
  public terminate(): void {
    this.stateTransition(SubscriptionState.Terminated);
    this.onTerminated();
  }

  /**
   * 4.1.2.3.  Unsubscribing
   * https://tools.ietf.org/html/rfc6665#section-4.1.2.3
   */
  public unsubscribe(): OutgoingSubscribeRequest {
    const allowHeader = "Allow: " + AllowedMethods.toString();
    const options: RequestOptions = {};
    options.extraHeaders = (options.extraHeaders || []).slice();
    options.extraHeaders.push(allowHeader);
    options.extraHeaders.push("Event: " + this.subscriptionEvent);
    options.extraHeaders.push("Expires: 0");
    options.extraHeaders.push("Contact: " + this.core.configuration.contact.toString());
    return this.subscribe(undefined, options);
  }

  /**
   * Handle in dialog NOTIFY requests.
   * This does not include the first NOTIFY which created the dialog.
   * @param message - The incoming NOTIFY request message.
   */
  private onNotify(message: IncomingRequestMessage): void {
    // If, for some reason, the event package designated in the "Event"
    // header field of the NOTIFY request is not supported, the subscriber
    // will respond with a 489 (Bad Event) response.
    // https://tools.ietf.org/html/rfc6665#section-4.1.3
    const event: string = message.parseHeader("Event").event;
    if (!event || event !== this.subscriptionEvent) {
      this.core.replyStateless(message, { statusCode: 489 });
      return;
    }

    // In the state diagram, "Re-subscription times out" means that an
    // attempt to refresh or update the subscription using a new SUBSCRIBE
    // request does not result in a NOTIFY request before the corresponding
    // Timer N expires.
    // https://tools.ietf.org/html/rfc6665#section-4.1.2
    if (this.N) {
      clearTimeout(this.N);
      this.N = undefined;
    }

    // NOTIFY requests MUST contain "Subscription-State" header fields that
    // indicate the status of the subscription.
    // https://tools.ietf.org/html/rfc6665#section-4.1.3
    const subscriptionState = message.parseHeader("Subscription-State");
    if (!subscriptionState || !subscriptionState.state) {
      this.core.replyStateless(message, { statusCode: 489 });
      return;
    }
    const state: "pending" | "active" | "terminated" = subscriptionState.state;
    const expires = subscriptionState.expires ? Math.max(subscriptionState.expires, 0) : undefined;

    // Update our state and expiration.
    switch (state) {
      case "pending":
        this.stateTransition(SubscriptionState.Pending, expires);
        break;
      case "active":
        this.stateTransition(SubscriptionState.Active, expires);
        break;
      case "terminated":
        this.stateTransition(SubscriptionState.Terminated, expires);
        break;
      default:
        this.logger.warn("Unrecognized subscription state.");
        break;
    }

    // Delegate remainder of NOTIFY handling.
    const uas = new NotifyUserAgentServer(this, message);
    if (this.delegate && this.delegate.onNotify) {
      this.delegate.onNotify(uas);
    } else {
      uas.accept();
    }
  }

  private onRefresh(request: OutgoingSubscribeRequest): void {
    if (this.delegate && this.delegate.onRefresh) {
      this.delegate.onRefresh(request);
    }
  }

  private onTerminated(): void {
    if (this.delegate && this.delegate.onTerminated) {
      this.delegate.onTerminated();
    }
  }

  private refreshTimerClear(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }

  private refreshTimerSet(): void {
    this.refreshTimerClear();
    if (this.autoRefresh && this.subscriptionExpires > 0) {
      const refresh = this.subscriptionExpires * 900;
      this._subscriptionRefresh = Math.floor(refresh / 1000);
      this._subscriptionRefreshLastSet = Math.floor(Date.now() / 1000);
      this.refreshTimer = setTimeout(() => {
        this.refreshTimer = undefined;
        this._subscriptionRefresh = undefined;
        this._subscriptionRefreshLastSet = undefined;
        this.onRefresh(this.refresh());
      }, refresh);
    }
  }

  private stateTransition(newState: SubscriptionState, newExpires?: number): void {
    // Assert valid state transitions.
    const invalidStateTransition = (): void => {
      this.logger.warn(`Invalid subscription state transition from ${this.subscriptionState} to ${newState}`);
    };

    switch (newState) {
      case SubscriptionState.Initial:
        invalidStateTransition();
        return;
      case SubscriptionState.NotifyWait:
        invalidStateTransition();
        return;
      case SubscriptionState.Pending:
        if (
          this.subscriptionState !== SubscriptionState.NotifyWait &&
          this.subscriptionState !== SubscriptionState.Pending
        ) {
          invalidStateTransition();
          return;
        }
        break;
      case SubscriptionState.Active:
        if (
          this.subscriptionState !== SubscriptionState.NotifyWait &&
          this.subscriptionState !== SubscriptionState.Pending &&
          this.subscriptionState !== SubscriptionState.Active
        ) {
          invalidStateTransition();
          return;
        }
        break;
      case SubscriptionState.Terminated:
        if (
          this.subscriptionState !== SubscriptionState.NotifyWait &&
          this.subscriptionState !== SubscriptionState.Pending &&
          this.subscriptionState !== SubscriptionState.Active
        ) {
          invalidStateTransition();
          return;
        }
        break;
      default:
        invalidStateTransition();
        return;
    }

    // If the "Subscription-State" value is "pending", the subscription has
    // been received by the notifier, but there is insufficient policy
    // information to grant or deny the subscription yet.  If the header
    // field also contains an "expires" parameter, the subscriber SHOULD
    // take it as the authoritative subscription duration and adjust
    // accordingly.  No further action is necessary on the part of the
    // subscriber.  The "retry-after" and "reason" parameters have no
    // semantics for "pending".
    // https://tools.ietf.org/html/rfc6665#section-4.1.3
    if (newState === SubscriptionState.Pending) {
      if (newExpires) {
        this.subscriptionExpires = newExpires;
      }
    }

    // If the "Subscription-State" header field value is "active", it means
    // that the subscription has been accepted and (in general) has been
    // authorized.  If the header field also contains an "expires"
    // parameter, the subscriber SHOULD take it as the authoritative
    // subscription duration and adjust accordingly.  The "retry-after" and
    // "reason" parameters have no semantics for "active".
    // https://tools.ietf.org/html/rfc6665#section-4.1.3
    if (newState === SubscriptionState.Active) {
      if (newExpires) {
        this.subscriptionExpires = newExpires;
      }
    }

    // If the "Subscription-State" value is "terminated", the subscriber
    // MUST consider the subscription terminated.  The "expires" parameter
    // has no semantics for "terminated" -- notifiers SHOULD NOT include an
    // "expires" parameter on a "Subscription-State" header field with a
    // value of "terminated", and subscribers MUST ignore any such
    // parameter, if present.
    if (newState === SubscriptionState.Terminated) {
      this.dispose();
    }

    this._subscriptionState = newState;
  }

  /**
   * When refreshing a subscription, a subscriber starts Timer N, set to
   * 64*T1, when it sends the SUBSCRIBE request.  If this Timer N expires
   * prior to the receipt of a NOTIFY request, the subscriber considers
   * the subscription terminated.  If the subscriber receives a success
   * response to the SUBSCRIBE request that indicates that no NOTIFY
   * request will be generated -- such as the 204 response defined for use
   * with the optional extension described in [RFC5839] -- then it MUST
   * cancel Timer N.
   * https://tools.ietf.org/html/rfc6665#section-4.1.2.2
   */
  private timerN(): void {
    this.logger.warn(`Timer N expired for SUBSCRIBE dialog. Timed out waiting for NOTIFY.`);
    if (this.subscriptionState !== SubscriptionState.Terminated) {
      this.stateTransition(SubscriptionState.Terminated);
      this.onTerminated();
    }
  }
}
