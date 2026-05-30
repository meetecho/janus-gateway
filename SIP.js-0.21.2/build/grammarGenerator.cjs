"use strict";
const fs = require("fs"),
    pegjs = require("peggy"),
    tspegjs = require("ts-pegjs");

const thisFolder = "./src/grammar/pegjs",
    inputFile = thisFolder + "/src/grammar.pegjs",
    outputFolder = thisFolder + "/dist",
    outputFile = outputFolder + "/grammar.ts";

const grammarContents = fs.readFileSync(inputFile, "utf8");

const parser = pegjs.generate(grammarContents, {
  allowedStartRules: [
    "Contact",
    "Name_Addr_Header",
    "Record_Route",
    "Request_Response",
    "SIP_URI",
    "Subscription_State",
    "Supported",
    "Require",
    "Via",
    "absoluteURI",
    "Call_ID",
    "Content_Disposition",
    "Content_Length",
    "Content_Type",
    "CSeq",
    "displayName",
    "Event",
    "From",
    "host",
    "Max_Forwards",
    "Min_SE",
    "Proxy_Authenticate",
    "quoted_string",
    "Refer_To",
    "Replaces",
    "Session_Expires",
    "stun_URI",
    "To",
    "turn_URI",
    "uuid",
    "WWW_Authenticate",
    "challenge",
    "sipfrag",
    "Referred_By"
  ],
  output: "source",
  optimize: "size",
  plugins: [tspegjs],
  "tspegjs": {
    "tslintIgnores": "interface-name, trailing-comma, object-literal-sort-keys, max-line-length, only-arrow-functions, one-variable-per-declaration, no-consecutive-blank-lines, align, radix, quotemark, semicolon, object-literal-shorthand, variable-name, no-var-keyword, whitespace, curly, prefer-const, object-literal-key-quotes, no-string-literal, one-line, no-unused-expression, space-before-function-paren, arrow-return-shorthand",
    "customHeader": "import { NameAddrHeader } from \"../../name-addr-header.js\";\nimport { URI } from \"../../uri.js\";"
  },
  "returnTypes": {
    Contact: "URI | NameAddrHeader",
    Name_Addr_Header: "NameAddrHeader",
    Record_Route: "NameAddrHeader",
    Request_Response: "string",
    SIP_URI: "URI",
    Subscription_State: "string",
    Supported: "Array<string>",
    Require: "Array<string>",
    Via: "string",
    absoluteURI: "string",
    Call_ID: "string",
    Content_Disposition: "string",
    Content_Length: "number",
    Content_Type: "string",
    CSeq: "number",
    displayName: "string",
    Event: "string",
    From: "string",
    host: "string",
    Max_Forwards: "number",
    Min_SE: "number",
    Proxy_Authenticate: "string",
    quoted_string: "string",
    Refer_To: "string",
    Replaces: "string",
    Session_Expires: "number",
    stun_URI: "string",
    To: "string",
    turn_URI: "string",
    uuid: "string",
    WWW_Authenticate: "string",
    challenge: "string",
    sipfrag: "string",
    Referred_By: "string"
  }
});

if (!fs.existsSync(outputFolder)){
  fs.mkdirSync(outputFolder);
}

fs.writeFile(outputFile, parser, err => {
  if (err) {
    console.log(err);
  } else {
    console.log("Grammar successfully generated.");
  }
});
