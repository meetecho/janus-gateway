/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming BYE request.
 * @public
 */
export interface IncomingByeRequest extends IncomingRequest {}

/**
 * Incoming BYE response.
 * @public
 */
export interface IncomingByeResponse extends IncomingResponse {}

/**
 * Outgoing BYE request.
 * @public
 */
export interface OutgoingByeRequest extends OutgoingRequest {}
