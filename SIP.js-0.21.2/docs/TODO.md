# Release Road Map

## Next Release

- review and remove everything that was deprecated
- complete more work in progress
- more documentation
- more tests
- bug fixes
- 1.0 prep

# Work in Progress

## Dev Dependencies

### api-extractor

- issue updating @microsoft/api-extractor past 7.7.11 where _2 gets added to class names which match globals (Notification, Transport, etc.)
  - https://github.com/microsoft/rushstack/issues/1830 
  - potential workaround https://github.com/microsoft/rushstack/issues/2895#issuecomment-943533628

## Tests

- _Unit_ tests are being written for low level "core" components (i.e. Transaction, Transport)
- _Integration_ tests are being written high level "api" components (i.e. Session, Subscription)
  - Need to write more integration tests: Publisher, UserAgent, SimpleUser, etc

## Source

### API - Miscellaneous

- UserAgent: The `contact` should be configurable. Related to URI and Grammar work. Issue #791.
- UserAgent: Should support multiple servers (or multiple Transports). Issue #706.
- Registerer: There is no good way to know if there is a request in progress (currently throws exception). Perhaps Registering/Unregistering state?
- Review all deprecated to make sure an alternative is provided that is something other than TBD.
- Review Allowed Methods and Allow header so configurable/variable in more reasonable fashion.
- Need alternatives for all hacks like `hackViaTcp`.
- Make sure all options buckets are deep copied.

### Core - Miscellaneous

- Dialog UACs are creating messages while non-dialog UACs are being handed message in most cases,
  but not all cases; MessageUserAgentClient is used for both out of dialog and in dialog.
  It would be worth it to have the constructor interface be consistent.
- Dialog UASs are created using a "dialog or core" in some cases when the request can be in dialog
  or out of dialog but this is not being done consistently. See Message vs Notify vs ReferUAS, etc.
- I believe all in and out of dialog requests should be able to be authenticated (confirm this).
  Currently only INVITE and re-INVITE work. There needs to be a small refactor to make it work for everything.
- Messages (IncomingMessage, OutgoingRequestMessage) could use a make over (tied to Grammar work)
- Timers and some associated timer code doesn't support unreliable transports (UDP for example)
- Extra headers array approach is error prone

### Grammar & URI - Refresh

- grammar.ts has everything typed as any
- parsed URIs are not able to always be matched to configured URI because of typing issues
- Cleanup URI class, should not default to "sip" scheme, get rid of useless type checking
- URI constructor doesn't allow user of type undefined, but grammar passed undefined is no user parsed
- URI should be strongly typed (currently using any for constructor params)
- URI allows "" for user and 0 for port which is confusing and should probably be undefined instead
- URI toString() can and does throw. Issue #286.
  - This is an issue with the URI class. The new API requires a URI instance be passed as an options, so that's
    indirectly no longer an issue. But the URI class should not be implemented in a fashion where toString()
    depends on decodeURIComponent which can (and does) throw URIError: URI malformed. The short is the URI
    class needs to be modified and this is also somewhat related to how the parser utilizes URI.
- IncomingMessage class has public properties that may not be set (!), internally generated 408 for example
- Handling incoming REGISTER, "Contact: \*" header fails to parse - there's a test written for it

#### Quick research on TypeScript parsers (from James Criscuolo)

Non-exhaustive research on these parsers, generally it seems like there is nothing both popular and well-typed:

- _ts-pegjs_: we currently use this on top of peggy (it's not separate). It used to use pegjs, but pegjs got replaced by peggy. I don't know how far typing can go, but it'd be the lowest work.
- _antlr4ts_: antlr4 is a fairly well-used grammar parser, and they built a separate ts project (don't know if its typescript from the ground up). What I don't like is it incurs a runtime dependency.
- _tspeg_: this one has very few users, but if it were popular, it would be exactly what we want. It is currently maintained (has been since it was made about 1.25 years ago), is strongly typed throughout, and outputs classes and interfaces.

### SessionDescriptionHandler - Miscellaneous

- Redesign the way options and modifiers are passed to SDH via `Session` as it is currently confusing at best
- Trickle ICE Support: https://tools.ietf.org/html/draft-ietf-mmusic-trickle-ice-sip-18
- Hold SDP offer too large for UDP

### Session Timers - Issue #18

- There is an old branch for it which perhaps can be pulled forward.

### Transport - TCP Support

- Support for "stream-oriented" transports: https://tools.ietf.org/html/rfc3261#section-18.3
- This current Transport interface only supports "message-oriented" transports. Issue #818.

## GRUU and Outbound - would be good to make sure we are compliant (tests)

### RFC5626: Managing Client-Initiated Connections (Outbound)
### RFC5627: Obtaining and Using Globally Routable User Agent URIs (GRUUs)

- MUST include the outbound option tag in a Supported header field in a REGISTER request.
- The UAC MUST support the Path header [RFC3327] mechanism, and
   indicate its support by including the 'path' option-tag in a
   Supported header field value in its REGISTER requests.  Other than
   optionally examining the Path vector in the response, this is all
   that is required of the UAC to support Path.
- UAs that support this specification SHOULD include the outbound
   option tag in a Supported header field in a request that is not a
   REGISTER request.
- support +sip.instance and reg-id
- support for multiple web sockets


## REFER handling - it has evolved over time and we are out of date

### The Session Initiation Protocol (SIP) Refer Method (2003)

https://tools.ietf.org/html/rfc3515
Abstract

This document defines the REFER method. This Session Initiation
Protocol (SIP) extension requests that the recipient REFER to a
resource provided in the request. It provides a mechanism allowing
the party sending the REFER to be notified of the outcome of the
referenced request. This can be used to enable many applications,
including call transfer.

### Multiple Dialog Usages in the Session Initiation Protocol (2007)

https://tools.ietf.org/html/rfc5057
Abstract

Several methods in the Session Initiation Protocol (SIP) can create
an association between endpoints known as a dialog. Some of these
methods can also create a different, but related, association within
an existing dialog. These multiple associations, or dialog usages,
require carefully coordinated processing as they have independent
life-cycles, but share common dialog state. Processing multiple
dialog usages correctly is not completely understood. What is
understood is difficult to implement.

This memo argues that multiple dialog usages should be avoided. It
discusses alternatives to their use and clarifies essential behavior
for elements that cannot currently avoid them.

### Session Initiation Protocol (SIP) Call Control - Transfer (2009)

https://tools.ietf.org/html/rfc5589
Abstract

This document describes providing Call Transfer capabilities in the
Session Initiation Protocol (SIP). SIP extensions such as REFER and
Replaces are used to provide a number of transfer services including
blind transfer, consultative transfer, and attended transfer. This
work is part of the SIP multiparty call control framework.

### SIP-Specific Event Notification (2012)

https://tools.ietf.org/html/rfc6665
Abstract

This document describes an extension to the Session Initiation
Protocol (SIP) defined by RFC 3261. The purpose of this extension is
to provide an extensible framework by which SIP nodes can request
notification from remote nodes indicating that certain events have
occurred.

### Explicit Subscriptions for the REFER Method (2015)

https://tools.ietf.org/html/rfc7614
Abstract

The Session Initiation Protocol (SIP) REFER request, as defined by
RFC 3515, triggers an implicit SIP-Specific Event Notification
framework subscription. Conflating the start of the subscription
with handling the REFER request makes negotiating SUBSCRIBE
extensions impossible and complicates avoiding SIP dialog sharing.
This document defines extensions to REFER that remove the implicit
subscription and, if desired, replace it with an explicit one.

### Clarifications for the Use of REFER with RFC 6665 (2015)

https://tools.ietf.org/html/rfc7647
Abstract

The SIP REFER method relies on the SIP-Specific Event Notification
framework. That framework was revised by RFC 6665. This document
highlights the implications of the requirement changes in RFC 6665,
and updates the definition of the REFER method described in RFC 3515
to clarify and disambiguate the impact of those changes.

### Clarifications for When to Use the name-addr Production in SIP Messages (2017)

https://tools.ietf.org/html/rfc8217
Abstract

RFC 3261 constrained several SIP header fields whose grammar contains
the "name-addr / addr-spec" alternative to use name-addr when certain
characters appear. Unfortunately, it expressed the constraints with
prose copied into each header field definition, and at least one
header field was missed. Further, the constraint has not been copied
into documents defining extension headers whose grammar contains the
alternative.
