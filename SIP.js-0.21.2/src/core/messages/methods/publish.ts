/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming PUBLISH request.
 * @public
 */
export interface IncomingPublishRequest extends IncomingRequest {}

/**
 * Incoming PUBLISH response.
 * @public
 */
export interface IncomingPublishResponse extends IncomingResponse {}

/**
 * Outgoing PUBLISH request.
 * @public
 */
export interface OutgoingPublishRequest extends OutgoingRequest {}
