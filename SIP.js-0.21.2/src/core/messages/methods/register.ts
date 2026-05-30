/* eslint-disable @typescript-eslint/no-empty-interface */
import { IncomingRequest } from "../incoming-request.js";
import { IncomingResponse } from "../incoming-response.js";
import { OutgoingRequest } from "../outgoing-request.js";

/**
 * Incoming REGISTER request.
 * @public
 */
export interface IncomingRegisterRequest extends IncomingRequest {}

/**
 * Incoming REGISTER response.
 * @public
 */
export interface IncomingRegisterResponse extends IncomingResponse {}

/**
 * Outgoing REGISTER request.
 * @public
 */
export interface OutgoingRegisterRequest extends OutgoingRequest {}
