import { InvitationAcceptOptions } from "../../../api/invitation-accept-options.js";
import { InviterInviteOptions } from "../../../api/inviter-invite-options.js";
import { InviterOptions } from "../../../api/inviter-options.js";
import { Logger } from "../../../core/log/logger.js";
import { Message } from "../../../api/message.js";
import { RegistererRegisterOptions } from "../../../api/registerer-register-options.js";
import { RegistererUnregisterOptions } from "../../../api/registerer-unregister-options.js";
import { Session } from "../../../api/session.js";
import { SessionManager } from "../session-manager/session-manager.js";
import { SessionManagerOptions } from "../session-manager/session-manager-options.js";
import { SimpleUserDelegate } from "./simple-user-delegate.js";
import { SimpleUserOptions } from "./simple-user-options.js";

/**
 * A simple SIP user class.
 * @remarks
 * While this class is completely functional for simple use cases, it is not intended
 * to provide an interface which is suitable for most (must less all) applications.
 * While this class has many limitations (for example, it only handles a single concurrent session),
 * it is, however, intended to serve as a simple example of using the SIP.js API.
 * @public
 */
export class SimpleUser {
  /** Delegate. */
  public delegate: SimpleUserDelegate | undefined;

  private logger: Logger;
  private options: SimpleUserOptions;
  private session: Session | undefined = undefined;
  private sessionManager: SessionManager;

  /**
   * Constructs a new instance of the `SimpleUser` class.
   * @param server - SIP WebSocket Server URL.
   * @param options - Options bucket. See {@link SimpleUserOptions} for details.
   */
  constructor(server: string, options: SimpleUserOptions = {}) {
    // Delegate
    this.delegate = options.delegate;

    // Copy options
    this.options = { ...options };

    // Session manager options
    const sessionManagerOptions: SessionManagerOptions = {
      aor: this.options.aor,
      delegate: {
        onCallAnswered: () => this.delegate?.onCallAnswered?.(),
        onCallCreated: (session: Session) => {
          this.session = session;
          this.delegate?.onCallCreated?.();
        },
        onCallReceived: () => this.delegate?.onCallReceived?.(),
        onCallHangup: () => {
          this.session = undefined;
          this.delegate?.onCallHangup && this.delegate?.onCallHangup();
        },
        onCallHold: (s: Session, held: boolean) => this.delegate?.onCallHold?.(held),
        onCallDTMFReceived: (s: Session, tone: string, dur: number) => this.delegate?.onCallDTMFReceived?.(tone, dur),
        onMessageReceived: (message: Message) => this.delegate?.onMessageReceived?.(message.request.body),
        onRegistered: () => this.delegate?.onRegistered?.(),
        onUnregistered: () => this.delegate?.onUnregistered?.(),
        onServerConnect: () => this.delegate?.onServerConnect?.(),
        onServerDisconnect: () => this.delegate?.onServerDisconnect?.()
      },
      maxSimultaneousSessions: 1,
      media: this.options.media,
      reconnectionAttempts: this.options.reconnectionAttempts,
      reconnectionDelay: this.options.reconnectionDelay,
      registererOptions: this.options.registererOptions,
      sendDTMFUsingSessionDescriptionHandler: this.options.sendDTMFUsingSessionDescriptionHandler,
      userAgentOptions: this.options.userAgentOptions
    };

    this.sessionManager = new SessionManager(server, sessionManagerOptions);

    // Use the SIP.js logger
    this.logger = this.sessionManager.userAgent.getLogger("sip.SimpleUser");
  }

  /**
   * Instance identifier.
   * @internal
   */
  get id(): string {
    return (this.options.userAgentOptions && this.options.userAgentOptions.displayName) || "Anonymous";
  }

  /** The local media stream. Undefined if call not answered. */
  get localMediaStream(): MediaStream | undefined {
    return this.session && this.sessionManager.getLocalMediaStream(this.session);
  }

  /** The remote media stream. Undefined if call not answered. */
  get remoteMediaStream(): MediaStream | undefined {
    return this.session && this.sessionManager.getRemoteMediaStream(this.session);
  }

  /**
   * The local audio track, if available.
   * @deprecated Use localMediaStream and get track from the stream.
   */
  get localAudioTrack(): MediaStreamTrack | undefined {
    return this.session && this.sessionManager.getLocalAudioTrack(this.session);
  }

  /**
   * The local video track, if available.
   * @deprecated Use localMediaStream and get track from the stream.
   */
  get localVideoTrack(): MediaStreamTrack | undefined {
    return this.session && this.sessionManager.getLocalVideoTrack(this.session);
  }

  /**
   * The remote audio track, if available.
   * @deprecated Use remoteMediaStream and get track from the stream.
   */
  get remoteAudioTrack(): MediaStreamTrack | undefined {
    return this.session && this.sessionManager.getRemoteAudioTrack(this.session);
  }

  /**
   * The remote video track, if available.
   * @deprecated Use remoteMediaStream and get track from the stream.
   */
  get remoteVideoTrack(): MediaStreamTrack | undefined {
    return this.session && this.sessionManager.getRemoteVideoTrack(this.session);
  }

  /**
   * Connect.
   * @remarks
   * Start the UserAgent's WebSocket Transport.
   */
  public connect(): Promise<void> {
    this.logger.log(`[${this.id}] Connecting UserAgent...`);
    return this.sessionManager.connect();
  }

  /**
   * Disconnect.
   * @remarks
   * Stop the UserAgent's WebSocket Transport.
   */
  public disconnect(): Promise<void> {
    this.logger.log(`[${this.id}] Disconnecting UserAgent...`);
    return this.sessionManager.disconnect();
  }

  /**
   * Return true if connected.
   */
  public isConnected(): boolean {
    return this.sessionManager.isConnected();
  }

  /**
   * Start receiving incoming calls.
   * @remarks
   * Send a REGISTER request for the UserAgent's AOR.
   * Resolves when the REGISTER request is sent, otherwise rejects.
   */
  public register(registererRegisterOptions?: RegistererRegisterOptions): Promise<void> {
    this.logger.log(`[${this.id}] Registering UserAgent...`);
    return this.sessionManager.register(registererRegisterOptions);
  }

  /**
   * Stop receiving incoming calls.
   * @remarks
   * Send an un-REGISTER request for the UserAgent's AOR.
   * Resolves when the un-REGISTER request is sent, otherwise rejects.
   */
  public unregister(registererUnregisterOptions?: RegistererUnregisterOptions): Promise<void> {
    this.logger.log(`[${this.id}] Unregistering UserAgent...`);
    return this.sessionManager.unregister(registererUnregisterOptions);
  }

  /**
   * Make an outgoing call.
   * @remarks
   * Send an INVITE request to create a new Session.
   * Resolves when the INVITE request is sent, otherwise rejects.
   * Use `onCallAnswered` delegate method to determine if Session is established.
   * @param destination - The target destination to call. A SIP address to send the INVITE to.
   * @param inviterOptions - Optional options for Inviter constructor.
   * @param inviterInviteOptions - Optional options for Inviter.invite().
   */
  public call(
    destination: string,
    inviterOptions?: InviterOptions,
    inviterInviteOptions?: InviterInviteOptions
  ): Promise<void> {
    this.logger.log(`[${this.id}] Beginning Session...`);
    if (this.session) {
      return Promise.reject(new Error("Session already exists."));
    }
    return this.sessionManager.call(destination, inviterOptions, inviterInviteOptions).then(() => {
      return;
    });
  }

  /**
   * Hangup a call.
   * @remarks
   * Send a BYE request, CANCEL request or reject response to end the current Session.
   * Resolves when the request/response is sent, otherwise rejects.
   * Use `onCallHangup` delegate method to determine if and when call is ended.
   */
  public hangup(): Promise<void> {
    this.logger.log(`[${this.id}] Hangup...`);
    if (!this.session) {
      return Promise.reject(new Error("Session does not exist."));
    }
    return this.sessionManager.hangup(this.session).then(() => {
      this.session = undefined;
    });
  }

  /**
   * Answer an incoming call.
   * @remarks
   * Accept an incoming INVITE request creating a new Session.
   * Resolves with the response is sent, otherwise rejects.
   * Use `onCallAnswered` delegate method to determine if and when call is established.
   * @param invitationAcceptOptions - Optional options for Inviter.accept().
   */
  public answer(invitationAcceptOptions?: InvitationAcceptOptions): Promise<void> {
    this.logger.log(`[${this.id}] Accepting Invitation...`);
    if (!this.session) {
      return Promise.reject(new Error("Session does not exist."));
    }
    return this.sessionManager.answer(this.session, invitationAcceptOptions);
  }

  /**
   * Decline an incoming call.
   * @remarks
   * Reject an incoming INVITE request.
   * Resolves with the response is sent, otherwise rejects.
   * Use `onCallHangup` delegate method to determine if and when call is ended.
   */
  public decline(): Promise<void> {
    this.logger.log(`[${this.id}] rejecting Invitation...`);
    if (!this.session) {
      return Promise.reject(new Error("Session does not exist."));
    }
    return this.sessionManager.decline(this.session);
  }

  /**
   * Hold call
   * @remarks
   * Send a re-INVITE with new offer indicating "hold".
   * Resolves when the re-INVITE request is sent, otherwise rejects.
   * Use `onCallHold` delegate method to determine if request is accepted or rejected.
   * See: https://tools.ietf.org/html/rfc6337
   */
  public hold(): Promise<void> {
    this.logger.log(`[${this.id}] holding session...`);
    if (!this.session) {
      return Promise.reject(new Error("Session does not exist."));
    }
    return this.sessionManager.hold(this.session);
  }

  /**
   * Unhold call.
   * @remarks
   * Send a re-INVITE with new offer indicating "unhold".
   * Resolves when the re-INVITE request is sent, otherwise rejects.
   * Use `onCallHold` delegate method to determine if request is accepted or rejected.
   * See: https://tools.ietf.org/html/rfc6337
   */
  public unhold(): Promise<void> {
    this.logger.log(`[${this.id}] unholding session...`);
    if (!this.session) {
      return Promise.reject(new Error("Session does not exist."));
    }
    return this.sessionManager.unhold(this.session);
  }

  /**
   * Hold state.
   * @remarks
   * True if session is on hold.
   */
  public isHeld(): boolean {
    return this.session ? this.sessionManager.isHeld(this.session) : false;
  }

  /**
   * Mute call.
   * @remarks
   * Disable sender's media tracks.
   */
  public mute(): void {
    this.logger.log(`[${this.id}] disabling media tracks...`);
    return this.session && this.sessionManager.mute(this.session);
  }

  /**
   * Unmute call.
   * @remarks
   * Enable sender's media tracks.
   */
  public unmute(): void {
    this.logger.log(`[${this.id}] enabling media tracks...`);
    return this.session && this.sessionManager.unmute(this.session);
  }

  /**
   * Mute state.
   * @remarks
   * True if sender's media track is disabled.
   */
  public isMuted(): boolean {
    return this.session ? this.sessionManager.isMuted(this.session) : false;
  }

  /**
   * Send DTMF.
   * @remarks
   * Send an INFO request with content type application/dtmf-relay.
   * @param tone - Tone to send.
   */
  public sendDTMF(tone: string): Promise<void> {
    this.logger.log(`[${this.id}] sending DTMF...`);
    if (!this.session) {
      return Promise.reject(new Error("Session does not exist."));
    }
    return this.sessionManager.sendDTMF(this.session, tone);
  }

  /**
   * Send a message.
   * @remarks
   * Send a MESSAGE request.
   * @param destination - The target destination for the message. A SIP address to send the MESSAGE to.
   */
  public message(destination: string, message: string): Promise<void> {
    this.logger.log(`[${this.id}] sending message...`);
    return this.sessionManager.message(destination, message);
  }
}
