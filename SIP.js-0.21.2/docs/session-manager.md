# SessionManager

## Overview

The `SessionManager` class provides an easy simplified interface for making audio and video calls in a web page.

While not intended for all use cases, `SessionManager` is intended to be suitable for many single page web browser applications.

If requirements are more advanced, working directly with the [API](./api.md) which `SessionManager` is built on top of provides more flexiblity.

## Reference Documentation

* [SessionManager Class Reference](./session-manager/sip.js.md)

## Getting Started

The interface provdied by `SessionManager` supports multiple concurrent calls, but otherwise generally mirrors the interface provided by `SimpleUser`.

1. Start with [SimpleUser](./simple-user.md).
2. If `SimpleUser` suffices, then stop.
3. If `SimpleUser` would suffice if only it handled concurrent calls, then `SessionManager` may be for you.
4. If `SimpleUser` does not suffice for the single call case and/or `SessionManager` does not suffice for the multiple concurrent call case, then you may need to utilize the [API](./api.md) direclty.

## Example

The `SimpleUser` class source code provides a working example of how one might utilize the `SessionManager` class.
