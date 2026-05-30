/**
 * Function which returns an RTCConfiguration.
 * @public
 */
export function defaultPeerConnectionConfiguration(): RTCConfiguration {
  const configuration: RTCConfiguration = {
    bundlePolicy: "balanced", // Note: max-bundle is not supported by the demo backend currently (5/15/17)
    certificates: undefined,
    iceCandidatePoolSize: 0,
    iceServers: [{ urls: "stun:stun.l.google.com:19302" }], // TURN URL example: "turn:88.88.88.0:3478", "test", "test"
    iceTransportPolicy: "all",
    rtcpMuxPolicy: "require"
  };
  return configuration;
}
