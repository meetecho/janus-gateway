# Core Library

## Overview

This library provides an implementation of the core Session Initiation Protocol (SIP) constructs required by user agents (implementation of constructs needed by proxy servers is largely absent).

The library is intended to provide an implemenation the RFC specification details usable as building blocks for a "higher level" interface. All but the most advanced applications should find the "higher level" [API](./api.md) framework which is built on top of this core library to be a sufficient integration point. Many applications may find the even higher level abstraction provided by the [SimpleUser](./simple-user.md) class to be optimial.

## Reference Documentation

* [Core Library Reference](./core/sip.js.md)

## Getting Started

First, read the [RFC](https://tools.ietf.org/html/rfc3261). Then look at the source code.

The `UserAgentCore` class provides the primary external interface with the SIP core.

The `Session` interface represents a SIP Session and is the result of a successful INVITE request.

The `Subscription` interface represents a SIP Subscription and is the result of a successful SUBSCRIBE request.

Start by taking a look at `UserAgentCore` & `UserAgentCoreDelegate` which provide the highest level interfaces for sending and receiving SIP request messages and the main integration point (creating a new `UserAgentCore` is step one). Next take a look at `Session` & `SessionDelegate` which are products of a successful INVITE request and provide the interfaces for sending and receiving in dialog requests (BYE, for example) as well as for dealing with the offer/answer exchange.


## Interfaces and Implementations

Within the `src/core/` directory...

### `./dialogs`
- `Dialog` implementation (https://tools.ietf.org/html/rfc3261#section-12)
- `SessionDialog` extension (https://tools.ietf.org/html/rfc3261#section-13)
- `SubscriptionDialog` extension (https://tools.ietf.org/html/rfc6665)

### `./messages`
- `IncomingRequest` interface (https://tools.ietf.org/html/rfc3261#section-7.1)
- `IncomingResponse` interface (https://tools.ietf.org/html/rfc3261#section-7.2)
- `OutgoingRequest` interface (https://tools.ietf.org/html/rfc3261#section-7.1)
- `OutgoingResponse` interface (https://tools.ietf.org/html/rfc3261#section-7.2)
- Method specific extensions 

### `./transactions`
- `Transaction` implementation (https://tools.ietf.org/html/rfc3261#section-17)
- `ClientTransaction` extension (https://tools.ietf.org/html/rfc3261#section-17.1)
- `InviteClientTransaction` extension (https://tools.ietf.org/html/rfc3261#section-17.1.1)
- `NonInviteClientTransaction` extension (https://tools.ietf.org/html/rfc3261#section-17.1.2)
- `ServerTransaction` extension (https://tools.ietf.org/html/rfc3261#section-17.2)
- `InviteServerTransaction` extension (https://tools.ietf.org/html/rfc3261#section-17.2.1)
- `NonInviteServerTransaction` extension (https://tools.ietf.org/html/rfc3261#section-17.2.2)

### `./session`
- `Session` interface (https://tools.ietf.org/html/rfc3261#section-13)
- `SessionDelegate` interface (https://tools.ietf.org/html/rfc3261#section-13)

### `./subscription`
- `Subscription` interface (https://tools.ietf.org/html/rfc6665)
- `SubscriptionDelegate` interface (https://tools.ietf.org/html/rfc6665)

### `./timers`
- `Timers` constants (https://tools.ietf.org/html/rfc3261#page-265)

### `./transport`
- `Transport` interface (https://tools.ietf.org/html/rfc3261#section-18)

### `./user-agent-core`
- `UserAgentCore` UAC & UAS core implementations (https://tools.ietf.org/html/rfc3261#section-5)
- `UserAgentCoreDelegate` UAC & UAS core implementations (https://tools.ietf.org/html/rfc3261#section-5)

### `./user-agents`
- `UserAgentClient` implementation (https://tools.ietf.org/html/rfc3261#section-8.1)
- `UserAgentServer` implementation (https://tools.ietf.org/html/rfc3261#section-8.2)
- Method specific extensions 
