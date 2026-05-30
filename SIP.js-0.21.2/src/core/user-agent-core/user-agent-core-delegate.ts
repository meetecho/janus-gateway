import { IncomingInviteRequest } from "../messages/methods/invite.js";
import { IncomingMessageRequest } from "../messages/methods/message.js";
import { IncomingNotifyRequest } from "../messages/methods/notify.js";
import { IncomingReferRequest } from "../messages/methods/refer.js";
import { IncomingRegisterRequest } from "../messages/methods/register.js";
import { IncomingSubscribeRequest } from "../messages/methods/subscribe.js";

/**
 * User Agent Core delegate.
 * @public
 */
export interface UserAgentCoreDelegate {
  /**
   * Receive INVITE request.
   * @param request - Incoming INVITE request.
   */
  onInvite?(request: IncomingInviteRequest): void;

  /**
   * Receive MESSAGE request.
   * @param request - Incoming MESSAGE request.
   */
  onMessage?(request: IncomingMessageRequest): void;

  /**
   * DEPRECATED. Receive NOTIFY request.
   * @param message - Incoming NOTIFY request.
   */
  onNotify?(request: IncomingNotifyRequest): void;

  /**
   * Receive REFER request.
   * @param request - Incoming REFER request.
   */
  onRefer?(request: IncomingReferRequest): void;

  /**
   * Receive REGISTER request.
   * @param request - Incoming REGISTER request.
   */
  onRegister?(request: IncomingRegisterRequest): void;

  /**
   * Receive SUBSCRIBE request.
   * @param request - Incoming SUBSCRIBE request.
   */
  onSubscribe?(request: IncomingSubscribeRequest): void;
}
