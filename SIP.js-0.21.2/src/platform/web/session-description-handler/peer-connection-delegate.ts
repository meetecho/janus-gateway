/**
 * Delegate to handle PeerConnection state changes.
 * @public
 */
export interface PeerConnectionDelegate {
  /**
   * This happens whenever the aggregate state of the connection changes.
   * The aggregate state is a combination of the states of all of the
   * individual network transports being used by the connection.
   * @param event - Event.
   */
  onconnectionstatechange?(event: Event): void;

  /**
   * Triggered when an RTCDataChannel is added to the connection by the
   * remote peer calling createDataChannel().
   * @param event - RTCDataChannelEvent.
   */
  ondatachannel?(event: RTCDataChannelEvent): void;

  /**
   * Triggered when a new ICE candidate has been found.
   * @param event - RTCPeerConnectionIceEvent.
   */
  onicecandidate?(event: RTCPeerConnectionIceEvent): void;

  /**
   * Triggered when an error occurred during ICE candidate gathering.
   * @param event - RTCPeerConnectionIceErrorEvent.
   */
  onicecandidateerror?(event: RTCPeerConnectionIceErrorEvent): void;

  /**
   * This happens whenever the local ICE agent needs to deliver a message to
   * the other peer through the signaling server. This lets the ICE agent
   * perform negotiation with the remote peer without the browser itself
   * needing to know any specifics about the technology being used for
   * signalingTriggered when the IceConnectionState changes.
   * @param event - Event.
   */
  oniceconnectionstatechange?(event: Event): void;

  /**
   * Triggered when the ICE gathering state changes.
   * @param event - Event.
   */
  onicegatheringstatechange?(event: Event): void;

  /**
   * Triggered when renegotiation is necessary.
   * @param event - Event.
   */
  onnegotiationneeded?(event: Event): void;

  /**
   * Triggered when the SignalingState changes.
   * @param event - Event.
   */
  onsignalingstatechange?(event: Event): void;

  /**
   * Triggered when a new track is signaled by the remote peer, as a result of setRemoteDescription.
   * @param event - Event.
   */
  ontrack?(event: Event): void;
}
