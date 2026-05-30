import { Grammar } from "../grammar/grammar.js";
import { URI } from "../grammar/uri.js";
import { Body } from "../core/messages/body.js";
import { C } from "../core/messages/methods/constants.js";
import { Logger } from "../core/log/logger.js";
import { OutgoingRequestMessage } from "../core/messages/outgoing-request-message.js";
import { MessagerMessageOptions } from "./messager-message-options.js";
import { MessagerOptions } from "./messager-options.js";
import { UserAgent } from "./user-agent.js";

/**
 * A messager sends a {@link Message} (outgoing MESSAGE).
 * @public
 */
export class Messager {
  private logger: Logger;
  private request: OutgoingRequestMessage;
  private userAgent: UserAgent;

  /**
   * Constructs a new instance of the `Messager` class.
   * @param userAgent - User agent. See {@link UserAgent} for details.
   * @param targetURI - Request URI identifying the target of the message.
   * @param content - Content for the body of the message.
   * @param contentType - Content type of the body of the message.
   * @param options - Options bucket. See {@link MessagerOptions} for details.
   */
  public constructor(
    userAgent: UserAgent,
    targetURI: URI,
    content: string,
    contentType = "text/plain",
    options: MessagerOptions = {}
  ) {
    // Logger
    this.logger = userAgent.getLogger("sip.Messager");

    // Default options params
    options.params = options.params || {};

    // URIs
    let fromURI: URI | undefined = userAgent.userAgentCore.configuration.aor;
    if (options.params.fromUri) {
      fromURI =
        typeof options.params.fromUri === "string" ? Grammar.URIParse(options.params.fromUri) : options.params.fromUri;
    }
    if (!fromURI) {
      throw new TypeError("Invalid from URI: " + options.params.fromUri);
    }
    let toURI: URI | undefined = targetURI;
    if (options.params.toUri) {
      toURI = typeof options.params.toUri === "string" ? Grammar.URIParse(options.params.toUri) : options.params.toUri;
    }
    if (!toURI) {
      throw new TypeError("Invalid to URI: " + options.params.toUri);
    }

    // Message params
    const params = options.params ? { ...options.params } : {};

    // Extra headers
    const extraHeaders = (options.extraHeaders || []).slice();

    // Body
    const contentDisposition = "render";
    const body: Body = {
      contentDisposition,
      contentType,
      content
    };

    // Build the request
    this.request = userAgent.userAgentCore.makeOutgoingRequestMessage(
      C.MESSAGE,
      targetURI,
      fromURI,
      toURI,
      params,
      extraHeaders,
      body
    );

    // User agent
    this.userAgent = userAgent;
  }

  /**
   * Send the message.
   */
  public message(options: MessagerMessageOptions = {}): Promise<void> {
    this.userAgent.userAgentCore.request(this.request, options.requestDelegate);
    return Promise.resolve();
  }
}
