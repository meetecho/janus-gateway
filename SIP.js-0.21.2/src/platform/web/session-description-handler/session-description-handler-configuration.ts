/**
 * Configuration for SessionDescriptionHandler.
 * @public
 */
export interface SessionDescriptionHandlerConfiguration {
  /**
   * The maximum duration to wait in ms for ICE gathering to complete.
   * If undefined, implementation dependent.
   * If zero, no timeout.
   */
  iceGatheringTimeout?: number;

  /**
   * Peer connection options.
   */
  peerConnectionConfiguration?: RTCConfiguration;
}
