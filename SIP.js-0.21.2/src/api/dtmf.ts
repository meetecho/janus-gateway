import { IncomingInfoRequest } from "../core/messages/methods/info.js";
import { Info } from "./info.js";

/**
 * A DTMF signal (incoming INFO).
 * @deprecated Use `Info`.
 * @internal
 */
export class DTMF extends Info {
  private _tone: string;
  private _duration: number;

  /** @internal */
  public constructor(incomingInfoRequest: IncomingInfoRequest, tone: string, duration: number) {
    super(incomingInfoRequest);
    this._tone = tone;
    this._duration = duration;
  }

  public get tone(): string {
    return this._tone;
  }

  public get duration(): number {
    return this._duration;
  }
}
