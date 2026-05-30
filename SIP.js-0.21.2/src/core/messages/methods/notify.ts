/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming NOTIFY request.
 * @public
 */
export interface IncomingNotifyRequest extends IncomingRequest {}

/**
 * Incoming NOTIFY response.
 * @public
 */
export interface IncomingNotifyResponse extends IncomingResponse {}

/**
 * Outgoing NOTIFY request.
 * @public
 */
export interface OutgoingNotifyRequest extends OutgoingRequest {}
