/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming MESSAGE request.
 * @public
 */
export interface IncomingMessageRequest extends IncomingRequest {}

/**
 * Incoming MESSAGE response.
 * @public
 */
export interface IncomingMessageResponse extends IncomingResponse {}

/**
 * Outgoing MESSAGE request.
 * @public
 */
export interface OutgoingMessageRequest extends OutgoingRequest {}
