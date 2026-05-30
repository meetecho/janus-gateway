import { IncomingReferRequest } from "../core/messages/methods/refer.js";
import { IncomingRegisterRequest } from "../core/messages/methods/register.js";
import { IncomingSubscribeRequest } from "../core/messages/methods/subscribe.js";
import { Invitation } from "./invitation.js";
import { Message } from "./message.js";
import { Notification } from "./notification.js";
import { Referral } from "./referral.js";
import { Subscription } from "./subscription.js";

/**
 * Delegate for {@link UserAgent}.
 * @public
 */
export interface UserAgentDelegate {
  /**
   * Called upon transport transitioning to connected state.
   */
  onConnect?(): void;

  /**
   * Called upon transport transitioning from connected state.
   * @param error - An error if disconnect triggered by transport. Otherwise undefined.
   */
  onDisconnect?(error?: Error): void;

  /**
   * Called upon receipt of an invitation.
   * @remarks
   * Handler for incoming out of dialog INVITE requests.
   * @param invitation - The invitation.
   */
  onInvite?(invitation: Invitation): void;

  /**
   * Called upon receipt of a message.
   * @remarks
   * Handler for incoming out of dialog MESSAGE requests.
   * @param message - The message.
   */
  onMessage?(message: Message): void;

  /**
   * Called upon receipt of a notification.
   * @remarks
   * Handler for incoming out of dialog NOTIFY requests.
   * @param notification - The notification.
   */
  onNotify?(notification: Notification): void;

  /**
   * @alpha
   * Called upon receipt of a referral.
   * @remarks
   * Handler for incoming out of dialog REFER requests.
   * @param referral - The referral.
   */
  onRefer?(referral: Referral): void;

  /**
   * @alpha
   * Called upon receipt of a registration.
   * @remarks
   * Handler for incoming out of dialog REGISTER requests.
   * @param registration - The registration.
   */
  onRegister?(registration: unknown /* TODO: Registration */): void;

  /**
   * @alpha
   * Called upon receipt of a subscription.
   * @remarks
   * Handler for incoming out of dialog SUBSCRIBE requests.
   * @param subscription - The subscription.
   */
  onSubscribe?(subscription: Subscription): void;

  /**
   * @internal
   * Called upon receipt of an out of dialog REFER. Used by test suite.
   * @param request - The request.
   */
  onReferRequest?(request: IncomingReferRequest): void;

  /**
   * @internal
   * Called upon receipt of a REGISTER request. Used by test suite.
   * @param request - The request.
   */
  onRegisterRequest?(request: IncomingRegisterRequest): void;

  /**
   * @internal
   * Called upon receipt of an out of dialog SUBSCRIBE request. Used by test suite.
   * @param request - The request.
   */
  onSubscribeRequest?(request: IncomingSubscribeRequest): void;
}
