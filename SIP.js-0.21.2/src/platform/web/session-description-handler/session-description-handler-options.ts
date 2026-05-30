import { SessionDescriptionHandlerOptions as SessionDescriptionHandlerOptionsDefinition } from "../../../api/session-description-handler.js";

/**
 * Options for {@link SessionDescriptionHandler}.
 * @public
 */
export interface SessionDescriptionHandlerOptions extends SessionDescriptionHandlerOptionsDefinition {
  /**
   * Answer options to use when creating an answer.
   */
  answerOptions?: RTCAnswerOptions;

  /**
   * Constraints to use when creating local media stream.
   * @remarks
   * If undefined, defaults to audio true and video false.
   * If audio and video are false, media stream will have no tracks.
   */
  constraints?: MediaStreamConstraints;

  /**
   * If true, create a data channel when making initial offer.
   */
  dataChannel?: boolean;

  /**
   * A human-readable name to use when creating the data channel.
   */
  dataChannelLabel?: string;

  /**
   * Configuration options for creating the data channel.
   */
  dataChannelOptions?: RTCDataChannelInit;

  /**
   * If true, offer and answer directions will be set to place peer on hold.
   */
  hold?: boolean;

  /**
   * The maximum duration to wait in ms for ICE gathering to complete.
   * No timeout if undefined or zero.
   */
  iceGatheringTimeout?: number;

  /**
   * Offer options to use when creating an offer.
   */
  offerOptions?: RTCOfferOptions;

  /**
   * Called upon creating a data channel.
   */
  onDataChannel?: (dataChannel: RTCDataChannel) => void;
}
