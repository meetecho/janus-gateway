/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming REFER request.
 * @public
 */
export interface IncomingReferRequest extends IncomingRequest {}

/**
 * Incoming REFER response.
 * @public
 */
export interface IncomingReferResponse extends IncomingResponse {}

/**
 * Outgoing REFER request.
 * @public
 */
export interface OutgoingReferRequest extends OutgoingRequest {}
