import { URI } from "../grammar/uri.js";
import { SessionDescriptionHandlerModifier, SessionDescriptionHandlerOptions } from "./session-description-handler.js";
import { SessionOptions } from "./session-options.js";

/**
 * Options for {@link Inviter} constructor.
 * @public
 */
export interface InviterOptions extends SessionOptions {
  /** If true, an anonymous call. */
  anonymous?: boolean;
  /**
   * If true, the first answer to the local offer is immediately utilized for media.
   * Requires that the INVITE request MUST NOT fork.
   * Has no effect if `inviteWithoutSdp` is true.
   * Default is false.
   */
  earlyMedia?: boolean;
  /** Array of extra headers added to the INVITE. */
  extraHeaders?: Array<string>;
  /** If true, send INVITE without SDP. Default is false. */
  inviteWithoutSdp?: boolean;
  /** @deprecated TODO: provide alternative. */
  params?: {
    fromDisplayName?: string;
    fromTag?: string;
    fromUri?: string | URI;
    toDisplayName?: string;
    toUri?: string | URI;
  };
  /** @deprecated TODO: provide alternative. */
  renderbody?: string;
  /** @deprecated TODO: provide alternative. */
  rendertype?: string;
  /** Modifiers to pass to SessionDescriptionHandler during the initial INVITE transaction. */
  sessionDescriptionHandlerModifiers?: Array<SessionDescriptionHandlerModifier>;
  /** Options to pass to SessionDescriptionHandler during the initial INVITE transaction. */
  sessionDescriptionHandlerOptions?: SessionDescriptionHandlerOptions;
  /** Modifiers to pass to SessionDescriptionHandler during re-INVITE transactions. */
  sessionDescriptionHandlerModifiersReInvite?: Array<SessionDescriptionHandlerModifier>;
  /** Options to pass to SessionDescriptionHandler during re-INVITE transactions. */
  sessionDescriptionHandlerOptionsReInvite?: SessionDescriptionHandlerOptions;
}
