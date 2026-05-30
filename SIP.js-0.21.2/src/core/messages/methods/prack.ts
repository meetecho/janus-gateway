/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming PRACK request.
 * @public
 */
export interface IncomingPrackRequest extends IncomingRequest {}

/**
 * Incoming PRACK response.
 * @public
 */
export interface IncomingPrackResponse extends IncomingResponse {}

/**
 * Outgoing PRACK request.
 * @public
 */
export interface OutgoingPrackRequest extends OutgoingRequest {}
