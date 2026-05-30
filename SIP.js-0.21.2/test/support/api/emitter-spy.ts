import { Emitter } from "../../../lib/api/index.js";
import { Logger } from "../../../lib/core/index.js";

type ResolveFunction = () => void;
type RejectFunction = (reason: Error) => void;

export interface EmitterSpy<T> extends jasmine.Spy {
  wait(value?: T): Promise<void>;
}

export function makeEmitterSpy<T>(emitter: Emitter<T>, logger: Logger): EmitterSpy<T> {
  let waitingForEmitPromise: Promise<void> | undefined;
  let waitingForEmitResolve: ResolveFunction | undefined;
  let waitingForEmitReject: RejectFunction | undefined;
  let waitingForEmit: T | undefined;

  const emit = {
    listener: (value: T): boolean => {
      const v = String(value);
      logger.log(`Emitted ${v}`);
      if (!waitingForEmitResolve) {
        return false;
      }
      if (waitingForEmit !== undefined && waitingForEmit !== value) {
        return false;
      }
      waitingForEmitResolve();
      waitingForEmitPromise = undefined;
      waitingForEmitResolve = undefined;
      waitingForEmitReject = undefined;
      waitingForEmit = undefined;
      return true;
    }
  };

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const emitTimeout = (): void => {
    if (waitingForEmitReject) {
      waitingForEmitReject(new Error("Timed out waiting for emit."));
    }
    waitingForEmitPromise = undefined;
    waitingForEmitResolve = undefined;
    waitingForEmitReject = undefined;
    waitingForEmit = undefined;
  };

  const spy = Object.assign(spyOn(emit, "listener").and.callThrough(), {
    wait: async (value?: T): Promise<void> => {
      if (waitingForEmitPromise) {
        throw new Error("Already waiting for emit.");
      }
      waitingForEmitPromise = new Promise<void>((resolve, reject) => {
        waitingForEmitResolve = resolve;
        waitingForEmitReject = reject;
      });
      waitingForEmit = value;
      return waitingForEmitPromise;
    }
  });

  emitter.on(emit.listener);

  return spy;
}
