import { RegistererOptions } from "../../../api/registerer-options.js";
import { UserAgentOptions } from "../../../api/user-agent-options.js";
import { SimpleUserDelegate } from "./simple-user-delegate.js";

/**
 * Media for {@link SimpleUserOptions}.
 * @public
 */
export interface SimpleUserMedia {
  /**
   * Offer/Answer constraints determine if audio and/or video are utilized.
   * If not specified, only audio is utilized (audio is true, video is false).
   * @remarks
   * Constraints are used when creating local media stream.
   * If undefined, defaults to audio true and video false.
   * If audio and video are false, media stream will have no tracks.
   */
  constraints?: SimpleUserMediaConstraints;

  /** HTML elements for local media streams. */
  local?: SimpleUserMediaLocal;

  /** Local HTML media elements. */
  remote?: SimpleUserMediaRemote;
}

/**
 * Constraints for {@link SimpleUserMedia}.
 * @public
 */
export interface SimpleUserMediaConstraints {
  /** If true, offer and answer to send and receive audio. */
  audio: boolean;
  /** If true, offer and answer to send and receive video. */
  video: boolean;
}

/**
 * Local media elements for {@link SimpleUserMedia}.
 * @public
 */
export interface SimpleUserMediaLocal {
  /** The local video media stream is attached to this element. */
  video?: HTMLVideoElement;
}

/**
 * Remote media elements for {@link SimpleUserMedia}.
 * @public
 */
export interface SimpleUserMediaRemote {
  /** The remote audio media stream is attached to this element. */
  audio?: HTMLAudioElement;
  /** The remote video media stream is attached to this element. */
  video?: HTMLVideoElement;
}

/**
 * Options for {@link SimpleUser}.
 * @public
 */
export interface SimpleUserOptions {
  /**
   * User's SIP Address of Record (AOR).
   * @remarks
   * The AOR is registered to receive incoming calls.
   * If not specified, a random anonymous address is created for the user.
   */
  aor?: string;

  /**
   * Delegate for SimpleUser.
   */
  delegate?: SimpleUserDelegate;

  /**
   * Media options.
   */
  media?: SimpleUserMedia;

  /**
   * Maximum number of times to attempt to reconnection.
   * @remarks
   * When the transport connection is lost (WebSocket disconnects),
   * reconnection will be attempted immediately. If that fails,
   * reconnection will be attempted again when the browser indicates
   * the application has come online. See:
   * https://developer.mozilla.org/en-US/docs/Web/API/NavigatorOnLine
   * @defaultValue 3
   */
  reconnectionAttempts?: number;

  /**
   * Seconds to wait between reconnection attempts.
   * @defaultValue 4
   */
  reconnectionDelay?: number;

  /**
   * Options for Registerer.
   */
  registererOptions?: RegistererOptions;

  /**
   * Send DTMF using the session description handler (uses RFC 2833 DTMF).
   * @defaultValue `false`
   */
  sendDTMFUsingSessionDescriptionHandler?: boolean;

  /**
   * Options for UserAgent.
   */
  userAgentOptions?: UserAgentOptions;
}
