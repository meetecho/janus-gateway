import { Emitter, EmitterImpl, Transport, TransportState } from "../../../lib/api/index.js";
import { Logger } from "../../../lib/core/index.js";

type ResolveFunction = () => void;
type RejectFunction = (reason: Error) => void;

export class TransportFake implements Transport {
  public onConnect: (() => void) | undefined;
  public onDisconnect: ((error?: Error) => void) | undefined;
  public onMessage: ((message: string) => void) | undefined;

  private _id = "";
  private peers: Array<TransportFake> = [];
  private waitingForSendPromise: Promise<void> | undefined;
  private waitingForSendResolve: ResolveFunction | undefined;
  private waitingForSendReject: RejectFunction | undefined;
  private waitingForReceivePromise: Promise<void> | undefined;
  private waitingForReceiveResolve: ResolveFunction | undefined;
  private waitingForReceiveReject: RejectFunction | undefined;

  private _receiveDropOnce = false;
  private _state: TransportState = TransportState.Disconnected;
  private _stateEventEmitter = new EmitterImpl<TransportState>();

  constructor(private logger: Logger) {}

  public set id(id: string) {
    this._id = id;
  }

  public get protocol(): string {
    return "FAKE";
  }

  public get state(): TransportState {
    return this._state;
  }

  public get stateChange(): Emitter<TransportState> {
    return this._stateEventEmitter;
  }

  public connect(): Promise<void> {
    return this._connect();
  }

  public disconnect(): Promise<void> {
    return this._disconnect();
  }

  public dispose(): Promise<void> {
    return Promise.resolve();
  }

  public send(message: string): Promise<void> {
    return this._send(message).then(() => {
      return;
    });
  }

  public isConnected(): boolean {
    return this._state === TransportState.Connected;
  }

  public setConnected(connected: boolean): void {
    this._state = connected ? TransportState.Connected : TransportState.Disconnected;
  }

  public addPeer(peer: TransportFake): void {
    this.peers.push(peer);
  }

  public receive(msg: string): void {
    /*
    let message = "";
    message += this._id ? `${this._id} ` : "";
    message += `Receiving...\n${msg}`;
    this.logger.log(message);
    */
    if (this._receiveDropOnce) {
      this._receiveDropOnce = false;
      this.logger.warn((this._id ? `${this._id} ` : "") + "Dropped message");
    } else if (this.onMessage) {
      this.onMessage(msg);
    }
    this.receiveHappened();
  }

  public receiveDropOnce(): void {
    this._receiveDropOnce = true;
  }

  public async waitSent(): Promise<void> {
    if (this.waitingForSendPromise) {
      throw new Error("Already waiting for send.");
    }
    this.waitingForSendPromise = new Promise<void>((resolve, reject) => {
      this.waitingForSendResolve = resolve;
      this.waitingForSendReject = reject;
    });
    return this.waitingForSendPromise;
  }

  public async waitReceived(): Promise<void> {
    if (this.waitingForReceivePromise) {
      throw new Error("Already waiting for receive.");
    }
    this.waitingForReceivePromise = new Promise<void>((resolve, reject) => {
      this.waitingForReceiveResolve = resolve;
      this.waitingForReceiveReject = reject;
    });
    return this.waitingForReceivePromise;
  }

  private _connect(): Promise<void> {
    switch (this._state) {
      case TransportState.Connecting:
        this.transitionState(TransportState.Connected);
        break;
      case TransportState.Connected:
        break;
      case TransportState.Disconnecting:
        this.transitionState(TransportState.Connecting);
        this.transitionState(TransportState.Connected);
        break;
      case TransportState.Disconnected:
        this.transitionState(TransportState.Connecting);
        this.transitionState(TransportState.Connected);
        break;
      default:
        throw new Error("Unknown state.");
    }
    return Promise.resolve();
  }

  private _disconnect(): Promise<void> {
    switch (this._state) {
      case TransportState.Connecting:
        this.transitionState(TransportState.Disconnecting);
        this.transitionState(TransportState.Disconnected);
        break;
      case TransportState.Connected:
        this.transitionState(TransportState.Disconnecting);
        this.transitionState(TransportState.Disconnected);
        break;
      case TransportState.Disconnecting:
        this.transitionState(TransportState.Disconnected);
        break;
      case TransportState.Disconnected:
        break;
      default:
        throw new Error("Unknown state.");
    }
    return Promise.resolve();
  }

  private _send(msg: string): Promise<{ msg: string; overrideEvent?: boolean }> {
    if (!this.isConnected()) {
      return Promise.resolve().then(() => {
        this.sendHappened();
        throw new Error("Not connected.");
      });
    }
    let message = "";
    message += this._id ? `${this._id} ` : "";
    message += `Sending...\n${msg}`;
    this.logger.log(message);
    return Promise.resolve().then(() => {
      this.peers.forEach((peer) => {
        // console.warn("Passing");
        peer.onReceived(msg);
      });
      this.sendHappened();
      return { msg };
    });
  }

  private onReceived(msg: string): void {
    Promise.resolve().then(() => {
      this.receive(msg);
    });
  }

  private sendHappened(): void {
    if (this.waitingForSendResolve) {
      this.waitingForSendResolve();
    }
    this.waitingForSendPromise = undefined;
    this.waitingForSendResolve = undefined;
    this.waitingForSendReject = undefined;
  }

  private sendTimeout(): void {
    if (this.waitingForSendReject) {
      this.waitingForSendReject(new Error("Timed out waiting for send."));
    }
    this.waitingForSendPromise = undefined;
    this.waitingForSendResolve = undefined;
    this.waitingForSendReject = undefined;
  }

  private receiveHappened(): void {
    if (this.waitingForReceiveResolve) {
      this.waitingForReceiveResolve();
    }
    this.waitingForReceivePromise = undefined;
    this.waitingForReceiveResolve = undefined;
    this.waitingForReceiveReject = undefined;
  }

  private receiveTimeout(): void {
    if (this.waitingForReceiveReject) {
      this.waitingForReceiveReject(new Error("Timed out waiting for receive."));
    }
    this.waitingForReceivePromise = undefined;
    this.waitingForReceiveResolve = undefined;
    this.waitingForReceiveReject = undefined;
  }

  /**
   * Transition transport state.
   * @internal
   */
  private transitionState(newState: TransportState, error?: Error): void {
    const invalidTransition = (): void => {
      throw new Error(`Invalid state transition from ${this._state} to ${newState}`);
    };

    // Validate state transition
    switch (this._state) {
      case TransportState.Connecting:
        if (
          newState !== TransportState.Connected &&
          newState !== TransportState.Disconnecting &&
          newState !== TransportState.Disconnected
        ) {
          invalidTransition();
        }
        break;
      case TransportState.Connected:
        if (newState !== TransportState.Disconnecting && newState !== TransportState.Disconnected) {
          invalidTransition();
        }
        break;
      case TransportState.Disconnecting:
        if (newState !== TransportState.Connecting && newState !== TransportState.Disconnected) {
          invalidTransition();
        }
        break;
      case TransportState.Disconnected:
        if (newState !== TransportState.Connecting) {
          invalidTransition();
        }
        break;
      default:
        throw new Error("Unknown state.");
    }

    // Update state
    const oldState = this._state;
    this._state = newState;
    this.logger.log(`Transitioned from ${oldState} to ${this._state}`);
    this._stateEventEmitter.emit(this._state);

    //  Transition to Connected
    if (newState === TransportState.Connected) {
      if (this.onConnect) {
        this.onConnect();
      }
    }

    //  Transition from Connected
    if (oldState === TransportState.Connected) {
      if (this.onDisconnect) {
        if (error) {
          this.onDisconnect(error);
        } else {
          this.onDisconnect();
        }
      }
    }
  }
}
