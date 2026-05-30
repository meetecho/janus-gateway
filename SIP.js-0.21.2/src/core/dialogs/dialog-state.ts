import { URI } from "../../grammar/uri.js";

/**
 * Dialog state.
 * @remarks
 * A dialog contains certain pieces of state needed for further message
 * transmissions within the dialog.  This state consists of the dialog
 * ID, a local sequence number (used to order requests from the UA to
 * its peer), a remote sequence number (used to order requests from its
 * peer to the UA), a local URI, a remote URI, remote target, a boolean
 * flag called "secure", and a route set, which is an ordered list of
 * URIs.  The route set is the list of servers that need to be traversed
 * to send a request to the peer.  A dialog can also be in the "early"
 * state, which occurs when it is created with a provisional response,
 * and then transition to the "confirmed" state when a 2xx final
 * response arrives.  For other responses, or if no response arrives at
 * all on that dialog, the early dialog terminates.
 *
 * https://tools.ietf.org/html/rfc3261#section-12
 * @public
 */
export interface DialogState {
  id: string;
  early: boolean;
  callId: string;
  localTag: string;
  remoteTag: string;
  localSequenceNumber: number | undefined;
  remoteSequenceNumber: number | undefined;
  localURI: URI;
  remoteURI: URI;
  remoteTarget: URI;
  routeSet: Array<string>;
  secure: boolean;
}
