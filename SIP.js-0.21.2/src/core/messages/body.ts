import { IncomingRequestMessage } from "./incoming-request-message.js";
import { IncomingResponseMessage } from "./incoming-response-message.js";
import { OutgoingRequestMessage } from "./outgoing-request-message.js";

// If the Content-Disposition header field is missing, bodies of
// Content-Type application/sdp imply the disposition "session", while
// other content types imply "render".
// https://tools.ietf.org/html/rfc3261#section-13.2.1
function contentTypeToContentDisposition(contentType: string): string {
  if (contentType === "application/sdp") {
    return "session";
  } else {
    return "render";
  }
}

/**
 * Message body.
 * @remarks
 * https://tools.ietf.org/html/rfc3261#section-7.4
 * @public
 */
export interface Body {
  /**
   * If the Content-Disposition header field is missing, bodies of
   * Content-Type application/sdp imply the disposition "session", while
   * other content types imply "render".
   * https://tools.ietf.org/html/rfc3261#section-13.2.1
   * For backward-compatibility, if the Content-Disposition header field
   * is missing, the server SHOULD assume bodies of Content-Type
   * application/sdp are the disposition "session", while other content
   * types are "render".
   * https://tools.ietf.org/html/rfc3261#section-20.11
   */
  contentDisposition: string;

  /**
   * The Content-Type header field indicates the media type of the
   * message-body sent to the recipient.  The Content-Type header field
   * MUST be present if the body is not empty.  If the body is empty,
   * and a Content-Type header field is present, it indicates that the body
   * of the specific type has zero length (for example, an empty audio file).
   * https://tools.ietf.org/html/rfc3261#section-20.15
   */
  contentType: string;

  /**
   * Requests, including new requests defined in extensions to this
   * specification, MAY contain message bodies unless otherwise noted.
   * The interpretation of the body depends on the request method.
   * For response messages, the request method and the response status
   * code determine the type and interpretation of any message body.  All
   * responses MAY include a body.
   * https://tools.ietf.org/html/rfc3261#section-7.4
   */
  content: string;
}

/**
 * Create a Body given a legacy body type.
 * @param bodyLegacy - Body Object
 * @internal
 */
export function fromBodyLegacy(bodyLegacy: string | { body: string; contentType: string }): Body {
  const content = typeof bodyLegacy === "string" ? bodyLegacy : bodyLegacy.body;
  const contentType = typeof bodyLegacy === "string" ? "application/sdp" : bodyLegacy.contentType;
  const contentDisposition = contentTypeToContentDisposition(contentType);
  const body: Body = { contentDisposition, contentType, content };
  return body;
}

/**
 * User-Defined Type Guard for Body.
 * @param body - Body to check.
 * @internal
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function isBody(body: any): body is Body {
  return body &&
    typeof body.content === "string" &&
    typeof body.contentType === "string" &&
    body.contentDisposition === undefined
    ? true
    : typeof body.contentDisposition === "string";
}

/**
 * Given a message, get a normalized body.
 * The content disposition is inferred if not set.
 * @param message - The message.
 * @internal
 */
export function getBody(
  message: IncomingRequestMessage | IncomingResponseMessage | OutgoingRequestMessage | Body
): Body | undefined {
  let contentDisposition: string | undefined;
  let contentType: string | undefined;
  let content: string | undefined;

  // We're in UAS role, receiving incoming request
  if (message instanceof IncomingRequestMessage) {
    if (message.body) {
      // FIXME: Parsing needs typing
      const parse = message.parseHeader("Content-Disposition");
      contentDisposition = parse ? parse.type : undefined;
      contentType = message.parseHeader("Content-Type");
      content = message.body;
    }
  }

  // We're in UAC role, receiving incoming response
  if (message instanceof IncomingResponseMessage) {
    if (message.body) {
      // FIXME: Parsing needs typing
      const parse = message.parseHeader("Content-Disposition");
      contentDisposition = parse ? parse.type : undefined;
      contentType = message.parseHeader("Content-Type");
      content = message.body;
    }
  }

  // We're in UAC role, sending outgoing request
  if (message instanceof OutgoingRequestMessage) {
    if (message.body) {
      contentDisposition = message.getHeader("Content-Disposition");
      contentType = message.getHeader("Content-Type");
      if (typeof message.body === "string") {
        // FIXME: OutgoingRequest should not allow a "string" body without a "Content-Type" header.
        if (!contentType) {
          throw new Error("Header content type header does not equal body content type.");
        }
        content = message.body;
      } else {
        // FIXME: OutgoingRequest should not allow the "Content-Type" header not to match th body content type
        if (contentType && contentType !== message.body.contentType) {
          throw new Error("Header content type header does not equal body content type.");
        }
        contentType = message.body.contentType;
        content = message.body.body;
      }
    }
  }

  // We're in UAS role, sending outgoing response
  if (isBody(message)) {
    contentDisposition = message.contentDisposition;
    contentType = message.contentType;
    content = message.content;
  }

  // No content, no body.
  if (!content) {
    return undefined;
  }

  if (contentType && !contentDisposition) {
    contentDisposition = contentTypeToContentDisposition(contentType);
  }
  if (!contentDisposition) {
    throw new Error("Content disposition undefined.");
  }
  if (!contentType) {
    throw new Error("Content type undefined.");
  }

  return {
    contentDisposition,
    contentType,
    content
  };
}
