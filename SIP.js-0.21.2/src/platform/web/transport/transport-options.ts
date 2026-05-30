/**
 * Transport options.
 * @public
 */
export interface TransportOptions {
  /**
   * URL of WebSocket server to connect with. For example, "wss://localhost:8080".
   */
  server: string;

  /**
   * Seconds to wait for WebSocket to connect before giving up.
   * @defaultValue `5`
   */
  connectionTimeout?: number;

  /**
   * Keep alive - needs review.
   * @internal
   */
  keepAliveInterval?: number;

  /**
   * Keep alive - needs review.
   * @internal
   */
  keepAliveDebounce?: number;

  /**
   * If true, messages sent and received by the transport are logged.
   * @defaultValue `true`
   */
  traceSip?: boolean;
}
