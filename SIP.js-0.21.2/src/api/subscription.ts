import { Logger } from "../core/log/logger.js";
import { Subscription as SubscriptionDialog } from "../core/subscription/subscription.js";
import { Emitter, EmitterImpl } from "./emitter.js";
import { SubscriptionDelegate } from "./subscription-delegate.js";
import { SubscriptionOptions } from "./subscription-options.js";
import { SubscriptionState } from "./subscription-state.js";
import { SubscriptionSubscribeOptions } from "./subscription-subscribe-options.js";
import { SubscriptionUnsubscribeOptions } from "./subscription-unsubscribe-options.js";
import { UserAgent } from "./user-agent.js";

/**
 * A subscription provides {@link Notification} of events.
 *
 * @remarks
 * See {@link Subscriber} for details on establishing a subscription.
 *
 * @public
 */
export abstract class Subscription {
  /**
   * Property reserved for use by instance owner.
   * @defaultValue `undefined`
   */
  public data: unknown;

  /**
   * Subscription delegate. See {@link SubscriptionDelegate} for details.
   * @defaultValue `undefined`
   */
  public delegate: SubscriptionDelegate | undefined;

  /**
   * If the subscription state is SubscriptionState.Subscribed, the associated subscription dialog. Otherwise undefined.
   * @internal
   */
  protected _dialog: SubscriptionDialog | undefined;

  /**
   * Our user agent.
   * @internal
   */
  protected _userAgent: UserAgent;

  private _disposed = false;
  private _logger: Logger;
  private _state: SubscriptionState = SubscriptionState.Initial;
  private _stateEventEmitter: EmitterImpl<SubscriptionState>;

  /**
   * Constructor.
   * @param userAgent - User agent. See {@link UserAgent} for details.
   * @internal
   */
  protected constructor(userAgent: UserAgent, options: SubscriptionOptions = {}) {
    this._logger = userAgent.getLogger("sip.Subscription");
    this._stateEventEmitter = new EmitterImpl<SubscriptionState>();
    this._userAgent = userAgent;
    this.delegate = options.delegate;
  }

  /**
   * Destructor.
   */
  public dispose(): Promise<void> {
    if (this._disposed) {
      return Promise.resolve();
    }
    this._disposed = true;
    this._stateEventEmitter.removeAllListeners();
    return Promise.resolve();
  }

  /**
   * The subscribed subscription dialog.
   */
  public get dialog(): SubscriptionDialog | undefined {
    return this._dialog;
  }

  /**
   * True if disposed.
   * @internal
   */
  public get disposed(): boolean {
    return this._disposed;
  }

  /**
   * Subscription state. See {@link SubscriptionState} for details.
   */
  public get state(): SubscriptionState {
    return this._state;
  }

  /**
   * Emits when the subscription `state` property changes.
   */
  public get stateChange(): Emitter<SubscriptionState> {
    return this._stateEventEmitter;
  }

  /** @internal */
  protected stateTransition(newState: SubscriptionState): void {
    const invalidTransition = (): void => {
      throw new Error(`Invalid state transition from ${this._state} to ${newState}`);
    };

    // Validate transition
    switch (this._state) {
      case SubscriptionState.Initial:
        if (newState !== SubscriptionState.NotifyWait && newState !== SubscriptionState.Terminated) {
          invalidTransition();
        }
        break;
      case SubscriptionState.NotifyWait:
        if (newState !== SubscriptionState.Subscribed && newState !== SubscriptionState.Terminated) {
          invalidTransition();
        }
        break;
      case SubscriptionState.Subscribed:
        if (newState !== SubscriptionState.Terminated) {
          invalidTransition();
        }
        break;
      case SubscriptionState.Terminated:
        invalidTransition();
        break;
      default:
        throw new Error("Unrecognized state.");
    }

    // Guard against duplicate transition
    if (this._state === newState) {
      return;
    }

    // Transition
    this._state = newState;
    this._logger.log(`Subscription ${this._dialog ? this._dialog.id : undefined} transitioned to ${this._state}`);
    this._stateEventEmitter.emit(this._state);

    // Dispose
    if (newState === SubscriptionState.Terminated) {
      this.dispose();
    }
  }

  /**
   * Sends a re-SUBSCRIBE request if the subscription is "active".
   */
  public abstract subscribe(options?: SubscriptionSubscribeOptions): Promise<void>;

  /**
   * Unsubscribe from event notifications.
   *
   * @remarks
   * If the subscription state is SubscriptionState.Subscribed, sends an in dialog SUBSCRIBE request
   * with expires time of zero (an un-subscribe) and terminates the subscription.
   * Otherwise a noop.
   */
  public abstract unsubscribe(options?: SubscriptionUnsubscribeOptions): Promise<void>;
}
