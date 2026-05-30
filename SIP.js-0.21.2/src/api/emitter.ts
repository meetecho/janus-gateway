/**
 * Generic observable.
 * @public
 */
export interface Emitter<T> {
  /**
   * Sets up a function that will be called whenever the target changes.
   * @param listener - Callback function.
   * @param options - An options object that specifies characteristics about the listener.
   *                  If once true, indicates that the listener should be invoked at most once after being added.
   *                  If once true, the listener would be automatically removed when invoked.
   */
  addListener(listener: (data: T) => void, options?: { once?: boolean }): void;
  /**
   * Removes from the listener previously registered with addListener.
   * @param listener - Callback function.
   */
  removeListener(listener: (data: T) => void): void;
  /**
   * Registers a listener.
   * @param listener - Callback function.
   * @deprecated Use addListener.
   */
  on(listener: (data: T) => void): void;
  /**
   * Unregisters a listener.
   * @param listener - Callback function.
   * @deprecated Use removeListener.
   */
  off(listener: (data: T) => void): void;
  /**
   * Registers a listener then unregisters the listener after one event emission.
   * @param listener - Callback function.
   * @deprecated Use addListener.
   */
  once(listener: (data: T) => void): void;
}

/**
 * An {@link Emitter} implementation.
 * @internal
 */
export class EmitterImpl<T> implements Emitter<T> {
  private listeners = new Array<(data: T) => void>();

  /**
   * Sets up a function that will be called whenever the target changes.
   * @param listener - Callback function.
   * @param options - An options object that specifies characteristics about the listener.
   *                  If once true, indicates that the listener should be invoked at most once after being added.
   *                  If once true, the listener would be automatically removed when invoked.
   */
  public addListener(listener: (data: T) => void, options?: { once?: boolean }): void {
    const onceWrapper = (data: T): void => {
      this.removeListener(onceWrapper);
      listener(data);
    };
    options?.once === true ? this.listeners.push(onceWrapper) : this.listeners.push(listener);
  }

  /**
   * Emit change.
   * @param data - Data to emit.
   */
  public emit(data: T): void {
    this.listeners.slice().forEach((listener) => listener(data));
  }

  /**
   * Removes all listeners previously registered with addListener.
   */
  public removeAllListeners(): void {
    this.listeners = [];
  }

  /**
   * Removes a listener previously registered with addListener.
   * @param listener - Callback function.
   */
  public removeListener(listener: (data: T) => void): void {
    this.listeners = this.listeners.filter((l) => l !== listener);
  }

  /**
   * Registers a listener.
   * @param listener - Callback function.
   * @deprecated Use addListener.
   */
  public on(listener: (data: T) => void): void {
    return this.addListener(listener);
  }

  /**
   * Unregisters a listener.
   * @param listener - Callback function.
   * @deprecated Use removeListener.
   */
  public off(listener: (data: T) => void): void {
    return this.removeListener(listener);
  }

  /**
   * Registers a listener then unregisters the listener after one event emission.
   * @param listener - Callback function.
   * @deprecated Use addListener.
   */
  public once(listener: (data: T) => void): void {
    return this.addListener(listener, { once: true });
  }
}
