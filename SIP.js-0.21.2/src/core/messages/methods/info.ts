/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming INFO request.
 * @public
 */
export interface IncomingInfoRequest extends IncomingRequest {}

/**
 * Incoming INFO response.
 * @public
 */
export interface IncomingInfoResponse extends IncomingResponse {}

/**
 * Outgoing INFO request.
 * @public
 */
export interface OutgoingInfoRequest extends OutgoingRequest {}
