{
  options.data = {}; // Object to which header attributes will be assigned during parsing

  function list(head: string, tail: Array<string>) {
    return [head].concat(tail);
  }
}

// ABNF BASIC

CRLF    = "\r\n"
DIGIT   = [0-9]
ALPHA   = [a-zA-Z]
HEXDIG  = [0-9a-fA-F]
WSP     = SP / HTAB
OCTET   = [\u0000-\u00FF]
DQUOTE  = ["]
SP      = " "
HTAB    = "\t"


// BASIC RULES

alphanum    = [a-zA-Z0-9]
reserved    = ";" / "/" / "?" / ":" / "@" / "&" / "=" / "+" / "$" / ","
unreserved  = alphanum / mark
mark        = "-" / "_" / "." / "!" / "~" / "*" / "'" / "(" / ")"
escaped     = $ ("%" HEXDIG HEXDIG)

/* RFC3261 25: A recipient MAY replace any linear white space with a single SP
 * before interpreting the field value or forwarding the message downstream
 */
LWS = ( WSP* CRLF )? WSP+ {return " "; }

SWS = LWS?

HCOLON  = ( SP / HTAB )* ":" SWS {return ':'; }

TEXT_UTF8_TRIM  = $( TEXT_UTF8char+ ( LWS* TEXT_UTF8char)* )

TEXT_UTF8char   = [\x21-\x7E] / UTF8_NONASCII

UTF8_NONASCII   = [\u0080-\uFFFF]

UTF8_CONT       = [\x80-\xBF]

LHEX            = DIGIT / [\x61-\x66]

token           = $ (alphanum / "-" / "." / "!" / "%" / "*"
                  / "_" / "+" / "`" / "'" / "~" )+

token_nodot     = $ ( alphanum / "-"  / "!" / "%" / "*"
                  / "_" / "+" / "`" / "'" / "~" )+

separators      = "(" / ")" / "<" / ">" / "@" / "," / ";" / ":" / "\\"
                  / DQUOTE / "/" / "[" / "]" / "?" / "=" / "{" / "}"
                  / SP / HTAB

word            = $ (alphanum / "-" / "." / "!" / "%" / "*" /
                  "_" / "+" / "`" / "'" / "~" /
                  "(" / ")" / "<" / ">" /
                  ":" / "\\" / DQUOTE /
                  "/" / "[" / "]" / "?" /
                  "{" / "}" )+

STAR        = SWS "*" SWS   {return "*"; }
SLASH       = SWS "/" SWS   {return "/"; }
EQUAL       = SWS "=" SWS   {return "="; }
LPAREN      = SWS "(" SWS   {return "("; }
RPAREN      = SWS ")" SWS   {return ")"; }
RAQUOT      = ">" SWS       {return ">"; }
LAQUOT      = SWS "<"       {return "<"; }
COMMA       = SWS "," SWS   {return ","; }
SEMI        = SWS ";" SWS   {return ";"; }
COLON       = SWS ":" SWS   {return ":"; }
LDQUOT      = SWS DQUOTE    {return "\""; }
RDQUOT      = DQUOTE SWS    {return "\""; }

comment     = LPAREN (ctext / quoted_pair / comment)* RPAREN

ctext       = [\x21-\x27] / [\x2A-\x5B] / [\x5D-\x7E] / UTF8_NONASCII / LWS

quoted_string = $( SWS DQUOTE ( qdtext / quoted_pair )* DQUOTE )

quoted_string_clean = SWS DQUOTE contents: $( qdtext / quoted_pair )* DQUOTE {
                        return contents; }

qdtext  = LWS / "\x21" / [\x23-\x5B] / [\x5D-\x7E] / UTF8_NONASCII

quoted_pair = "\\" ( [\x00-\x09] / [\x0B-\x0C] / [\x0E-\x7F] )


//=======================
// SIP URI
//=======================

SIP_URI_noparams  = uri_scheme ":"  userinfo ? hostport {
                        options = options || { data: {}};
                        options.data.uri = new URI(options.data.scheme, options.data.user, options.data.host, options.data.port);
                        delete options.data.scheme;
                        delete options.data.user;
                        delete options.data.host;
                        delete options.data.host_type;
                        delete options.data.port;
                      }

SIP_URI         = uri_scheme ":"  userinfo ? hostport uri_parameters headers ? {
                        options = options || { data: {}};
                        options.data.uri = new URI(options.data.scheme, options.data.user, options.data.host, options.data.port, options.data.uri_params, options.data.uri_headers);
                        delete options.data.scheme;
                        delete options.data.user;
                        delete options.data.host;
                        delete options.data.host_type;
                        delete options.data.port;
                        delete options.data.uri_params;

                        if (options.startRule === 'SIP_URI') { options.data = options.data.uri;}
                      }

uri_scheme      = uri_scheme:  ( "sips"i / "sip"i ) {
                    options = options || { data: {}};
                    options.data.scheme = uri_scheme; }

userinfo        = user (":" password)? "@" {
                    options = options || { data: {}};
                    options.data.user = decodeURIComponent(text().slice(0, -1));}

user            = ( unreserved / escaped / user_unreserved )+

user_unreserved = "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"

password        = ( unreserved / escaped / "&" / "=" / "+" / "$" / "," )* {
                    options = options || { data: {}};
                    options.data.password = text(); }

hostport        = host ( ":" port )?

host            = ( hostname / IPv4address / IPv6reference ) {
                    options = options || { data: {}};
                    options.data.host = text();
                    return options.data.host; }

hostname        = ( domainlabel "." )* toplabel  "." ? {
                  options = options || { data: {}};
                  options.data.host_type = 'domain';
                  return text(); }

domainlabel     = domainlabel: ( [a-zA-Z0-9_-]+ )

toplabel        = toplabel: ( [a-zA-Z][a-zA-Z0-9-]* )

IPv6reference   = "[" IPv6address "]" {
                    options = options || { data: {}};
                    options.data.host_type = 'IPv6';
                    return text(); }

IPv6address     = ( h16 ":" h16 ":" h16 ":" h16 ":" h16 ":" h16 ":" ls32
                  / "::" h16 ":" h16 ":" h16 ":" h16 ":" h16 ":" ls32
                  / "::" h16 ":" h16 ":" h16 ":" h16 ":" ls32
                  / "::" h16 ":" h16 ":" h16 ":" ls32
                  / "::" h16 ":" h16 ":" ls32
                  / "::" h16 ":" ls32
                  / "::" ls32
                  / "::" h16
                  / h16 "::" h16 ":" h16 ":" h16 ":" h16 ":" ls32
                  / h16 (":" h16)? "::" h16 ":" h16 ":" h16 ":" ls32
                  / h16 (":" h16)? (":" h16)? "::" h16 ":" h16 ":" ls32
                  / h16 (":" h16)? (":" h16)? (":" h16)? "::" h16 ":" ls32
                  / h16 (":" h16)? (":" h16)? (":" h16)? (":" h16)? "::" ls32
                  / h16 (":" h16)? (":" h16)? (":" h16)? (":" h16)? (":" h16)? "::" h16
                  / h16 (":" h16)? (":" h16)? (":" h16)? (":" h16)? (":" h16)? (":" h16)? "::"
                  ) {
                  options = options || { data: {}};
                  options.data.host_type = 'IPv6';
                  return text(); }


h16             = HEXDIG HEXDIG? HEXDIG? HEXDIG?

ls32            = ( h16 ":" h16 ) / IPv4address


IPv4address     = dec_octet "." dec_octet "." dec_octet "." dec_octet {
                    options = options || { data: {}};
                    options.data.host_type = 'IPv4';
                    return text(); }

dec_octet       = "25" [\x30-\x35]          // 250-255
                / "2" [\x30-\x34] DIGIT     // 200-249
                / "1" DIGIT DIGIT           // 100-199
                / [\x31-\x39] DIGIT         // 10-99
                / DIGIT                     // 0-9

port            = port: (DIGIT ? DIGIT ? DIGIT ? DIGIT ? DIGIT ?) {
                    options = options || { data: {}};
                    port = parseInt(port.join(''));
                    options.data.port = port;
                    return port; }

// URI PARAMETERS

uri_parameters    = ( ";" uri_parameter)*

uri_parameter     = transport_param / user_param / method_param
                    / ttl_param / maddr_param / lr_param / other_param

transport_param   = "transport="i transport: ( "udp"i / "tcp"i / "sctp"i
                    / "tls"i / other_transport) {
                      options = options || { data: {}};
                      if(!options.data.uri_params) options.data.uri_params={};
                      options.data.uri_params['transport'] = transport.toLowerCase(); }

other_transport   = token

user_param        = "user="i user:( "phone"i / "ip"i / other_user) {
                      options = options || { data: {}};
                      if(!options.data.uri_params) options.data.uri_params={};
                      options.data.uri_params['user'] = user.toLowerCase(); }

other_user        = token

method_param      = "method="i method: Method {
                      options = options || { data: {}};
                      if(!options.data.uri_params) options.data.uri_params={};
                      options.data.uri_params['method'] = method; }

ttl_param         = "ttl="i ttl: ttl {
                      options = options || { data: {}};
                      if(!options.data.params) options.data.params={};
                      options.data.params['ttl'] = ttl; }

maddr_param       = "maddr="i maddr: host {
                      options = options || { data: {}};
                      if(!options.data.uri_params) options.data.uri_params={};
                      options.data.uri_params['maddr'] = maddr; }

lr_param          = "lr"i ('=' token)? {
                      options = options || { data: {}};
                      if(!options.data.uri_params) options.data.uri_params={};
                      options.data.uri_params['lr'] = undefined; }

other_param       = param: pname value: ( "=" pvalue )? {
                      options = options || { data: {}};
                      if(!options.data.uri_params) options.data.uri_params = {};
                      if (value === null){
                        value = undefined;
                      }
                      else {
                        value = value[1];
                      }
                      options.data.uri_params[param.toLowerCase()] = value;}

pname             = $ paramchar +

pvalue            = $ paramchar +

paramchar         = param_unreserved / unreserved / escaped

param_unreserved  = "[" / "]" / "/" / ":" / "&" / "+" / "$"


// HEADERS

headers           = "?" header ( "&" header )*

header            = hname: hname "=" hvalue: hvalue  {
                      hname = hname.join('').toLowerCase();
                      hvalue = hvalue.join('');
                      options = options || { data: {}};
                      if(!options.data.uri_headers) options.data.uri_headers = {};
                      if (!options.data.uri_headers[hname]) {
                        options.data.uri_headers[hname] = [hvalue];
                      } else {
                        options.data.uri_headers[hname].push(hvalue);
                      }}

hname             = ( hnv_unreserved / unreserved / escaped )+

hvalue            = ( hnv_unreserved / unreserved / escaped )*

hnv_unreserved    = "[" / "]" / "/" / "?" / ":" / "+" / "$"


// FIRST LINE

Request_Response  = Status_Line / Request_Line


// REQUEST LINE

Request_Line      = Method SP Request_URI SP SIP_Version

Request_URI       = SIP_URI / absoluteURI

absoluteURI       = scheme ":" ( hier_part / opaque_part )
                    {
                      options = options || { data: {}};
                      // lots of tests fail if this isn't guarded...
                      if (options.startRule === 'Refer_To') {
                        options.data.uri = new URI(options.data.scheme, options.data.user, options.data.host, options.data.port, options.data.uri_params, options.data.uri_headers);
                        delete options.data.scheme;
                        delete options.data.user;
                        delete options.data.host;
                        delete options.data.host_type;
                        delete options.data.port;
                        delete options.data.uri_params;
                      }
                    }

hier_part         = ( net_path / abs_path ) ( "?" query )?

net_path          = "//" authority  abs_path ?

abs_path          = "/" path_segments

opaque_part       = uric_no_slash uric *

uric              = reserved / unreserved / escaped

uric_no_slash     = unreserved / escaped / ";" / "?" / ":" / "@" / "&" / "="
                    / "+" / "$" / ","

path_segments     = segment ( "/" segment )*

segment           = pchar * ( ";" param )*

param             = pchar *

pchar             = unreserved / escaped /
                    ":" / "@" / "&" / "=" / "+" / "$" / ","

scheme            = ( ALPHA ( ALPHA / DIGIT / "+" / "-" / "." )* ){
                    options = options || { data: {}};
                    options.data.scheme= text(); }

authority         = srvr / reg_name

srvr              = ( ( userinfo "@" )? hostport )?

reg_name          = ( unreserved / escaped / "$" / ","
                    / ";" / ":" / "@" / "&" / "=" / "+" )+

query             = uric *

SIP_Version       = "SIP"i "/" DIGIT + "." DIGIT + {
                    options = options || { data: {}};
                    options.data.sip_version = text(); }

// SIP METHODS

INVITEm           = "\x49\x4E\x56\x49\x54\x45" // INVITE in caps

ACKm              = "\x41\x43\x4B" // ACK in caps

PRACKm            = "\x56\x58\x41\x43\x48" // PRACK in caps

OPTIONSm          = "\x4F\x50\x54\x49\x4F\x4E\x53" // OPTIONS in caps

BYEm              = "\x42\x59\x45" // BYE in caps

CANCELm           = "\x43\x41\x4E\x43\x45\x4C" // CANCEL in caps

REGISTERm         = "\x52\x45\x47\x49\x53\x54\x45\x52" // REGISTER in caps

SUBSCRIBEm        = "\x53\x55\x42\x53\x43\x52\x49\x42\x45" // SUBSCRIBE in caps

NOTIFYm           = "\x4E\x4F\x54\x49\x46\x59" // NOTIFY in caps

REFERm            = "\x52\x45\x46\x45\x52" // REFER in caps

PUBLISHm          = "\x50\x55\x42\x4c\x49\x53\x48" // PUBLISH in caps

Method            = ( INVITEm / ACKm / OPTIONSm / BYEm / CANCELm / REGISTERm
                    / SUBSCRIBEm / PUBLISHm / NOTIFYm / REFERm / extension_method ){

                    options = options || { data: {}};
                    options.data.method = text();
                    return options.data.method; }

extension_method  = token


// STATUS LINE

Status_Line     = SIP_Version SP Status_Code SP Reason_Phrase

Status_Code     = status_code: extension_code {
                  options = options || { data: {}};
                  options.data.status_code = parseInt(status_code.join('')); }

extension_code  = DIGIT DIGIT DIGIT

Reason_Phrase   = (reserved / unreserved / escaped
                  / UTF8_NONASCII / UTF8_CONT / SP / HTAB)* {
                  options = options || { data: {}};
                  options.data.reason_phrase = text(); }


//=======================
// HEADERS
//=======================

// Allow-Events

Allow_Events = event_type (COMMA event_type)*


// CALL-ID

Call_ID  =  word ( "@" word )? {
              options = options || { data: {}};
              options.data = text(); }

// CONTACT

Contact             = ( STAR / (contact_param (COMMA contact_param)*) ) {
                        var idx, length;
                        options = options || { data: {}};
                        length = options.data.multi_header.length;
                        for (idx = 0; idx < length; idx++) {
                          if (options.data.multi_header[idx].parsed === null) {
                            options.data = null;
                            break;
                          }
                        }
                        if (options.data !== null) {
                          options.data = options.data.multi_header;
                        } else {
                          options.data = -1;
                        }}

contact_param       = (addr_spec / name_addr) (SEMI contact_params)* {
                        var header;
                        options = options || { data: {}};
                        if(!options.data.multi_header) options.data.multi_header = [];
                        try {
                          header = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
                          delete options.data.uri;
                          delete options.data.displayName;
                          delete options.data.params;
                        } catch(e) {
                          header = null;
                        }
                        options.data.multi_header.push( { 'position': peg$currPos,
                                                  'offset': location().start.offset,
                                                  'parsed': header
                                                });}

name_addr           = ( displayName )? LAQUOT SIP_URI RAQUOT

addr_spec           = SIP_URI_noparams

displayName        = displayName: (token ( LWS token )* / quoted_string) {
                        displayName = text().trim();
                        if (displayName[0] === '\"') {
                          displayName = displayName.substring(1, displayName.length-1);
                        }
                        options = options || { data: {}};
                        options.data.displayName = displayName; }
                        // The previous rule is corrected from RFC3261

contact_params      = c_p_q / c_p_expires / contact_extension

c_p_q               = "q"i EQUAL q: qvalue {
                        options = options || { data: {}};
                        if(!options.data.params) options.data.params = {};
                        options.data.params['q'] = q; }

c_p_expires         = "expires"i EQUAL expires: delta_seconds {
                        options = options || { data: {}};
                        if(!options.data.params) options.data.params = {};
                        options.data.params['expires'] = expires; }

contact_extension   = generic_param

delta_seconds       = delta_seconds: DIGIT+ {
                        return parseInt(delta_seconds.join('')); }

qvalue              = "0" ( "." DIGIT? DIGIT? DIGIT? )? {
                        return parseFloat(text()); }

generic_param       = param: token  value: ( EQUAL gen_value )? {
                        options = options || { data: {}};
                        if(!options.data.params) options.data.params = {};
                        if (value === null){
                          value = undefined;
                        }
                        else {
                          value = value[1];
                        }
                        options.data.params[param.toLowerCase()] = value;}

gen_value           = token / host / quoted_string


// CONTENT-DISPOSITION

Content_Disposition     = disp_type ( SEMI disp_param )*

disp_type               = ("render"i / "session"i / "icon"i / "alert"i / disp_extension_token)
                          {
                            options = options || { data: {}};
                            if (options.startRule === 'Content_Disposition') {
                              options.data.type = text().toLowerCase();
                            }
                          }

disp_param              = handling_param / generic_param

handling_param          = "handling"i EQUAL ( "optional"i / "required"i / other_handling )

other_handling          = token

disp_extension_token    = token


// CONTENT-ENCODING

Content_Encoding    = content_coding (COMMA content_coding)*

content_coding      = token


// CONTENT-LENGTH

Content_Length      = length: (DIGIT +) {
                        options = options || { data: {}};
                        options.data = parseInt(length.join('')); }

// CONTENT-TYPE

Content_Type        = media_type {
                        options = options || { data: {}};
                        options.data = text(); }

media_type          = m_type SLASH m_subtype (SEMI m_parameter)*

m_type              = discrete_type / composite_type

discrete_type       = "text"i / "image"i / "audio"i / "video"i / "application"i
                    / extension_token

composite_type      = "message"i / "multipart"i / extension_token

extension_token     = ietf_token / x_token

ietf_token          = token

x_token             = "x-"i token

m_subtype           = extension_token / iana_token

iana_token          = token

m_parameter         = m_attribute EQUAL m_value

m_attribute         = token

m_value             = token / quoted_string


// CSEQ

CSeq          = CSeq_value LWS CSeq_method

CSeq_value    = cseq_value: DIGIT + {
                  options = options || { data: {}};
                  options.data.value=parseInt(cseq_value.join('')); }

CSeq_method   = Method


// EXPIRES

Expires     = expires: delta_seconds {options = options || { data: {}}; options.data = expires; }


Event             = event_type: event_type ( SEMI event_param )* {
                       options = options || { data: {}};
                       options.data.event = event_type.toLowerCase(); }

event_type        = $( event_package ( "." event_template )* )

event_package     = token_nodot

event_template    = token_nodot

event_param       = generic_param

// FROM

From        = ( addr_spec / name_addr ) ( SEMI from_param )* {
                options = options || { data: {}};
                var tag = options.data.tag;
                  options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
                  if (tag) {options.data.setParam('tag',tag)}
                }

from_param  = tag_param / generic_param

tag_param   = "tag"i EQUAL tag: token {options = options || { data: {}};options.data.tag = tag; }


//MAX-FORWARDS

Max_Forwards  = forwards: DIGIT+ {
                  options = options || { data: {}};
                  options.data = parseInt(forwards.join('')); }


// MIN-EXPIRES

Min_Expires  = min_expires: delta_seconds {options = options || { data: {}}; options.data = min_expires; }

// Name_Addr

Name_Addr_Header =  ( displayName )* LAQUOT SIP_URI RAQUOT ( SEMI generic_param )* {
                        options = options || { data: {}};
                        options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
                      }

// PROXY-AUTHENTICATE

Proxy_Authenticate  = proxy_authenticate: challenge

challenge           = ("Digest"i LWS digest_cln (COMMA digest_cln)*)
                      / other_challenge

other_challenge     = auth_scheme LWS auth_param (COMMA auth_param)*

auth_scheme         = token

auth_param          = auth_param_name EQUAL ( token / quoted_string )

auth_param_name     = token

digest_cln          = realm / domain / nonce / opaque / stale / algorithm
                      / qop_options / auth_param

realm               = "realm"i EQUAL realm_value

realm_value         = realm: quoted_string_clean { options = options || { data: {}}; options.data.realm = realm; }

domain              = "domain"i EQUAL LDQUOT URI ( SP+ URI )* RDQUOT

URI                 = absoluteURI / abs_path

nonce               = "nonce"i EQUAL nonce_value

nonce_value         = nonce: quoted_string_clean { options = options || { data: {}}; options.data.nonce=nonce; }

opaque              = "opaque"i EQUAL opaque: quoted_string_clean { options = options || { data: {}}; options.data.opaque=opaque; }

stale               = "stale"i EQUAL ( "true"i { options = options || { data: {}}; options.data.stale=true; } / "false"i { options = options || { data: {}}; options.data.stale=false; } )

algorithm           = "algorithm"i EQUAL algorithm: ( "MD5"i / "MD5-sess"i
                      / token ) {
                      options = options || { data: {}};
                      options.data.algorithm=algorithm.toUpperCase(); }

qop_options         = "qop"i EQUAL LDQUOT (qop_value ("," qop_value)*) RDQUOT

qop_value           = qop_value: ( "auth-int"i / "auth"i / token ) {
                        options = options || { data: {}};
                        options.data.qop || (options.data.qop=[]);
                        options.data.qop.push(qop_value.toLowerCase()); }

// PUBLISH ETag

SIP_ETag       = token

SIP_If_Match   = token

// PROXY-REQUIRE

Proxy_Require  = option_tag (COMMA option_tag)*

option_tag     = token


// RAck

RAck          = RAck_value LWS RAck_value LWS RAck_method

RAck_value    = rack_value: DIGIT + {
                  options = options || { data: {}};
                  options.data.value=parseInt(rack_value.join('')); }

RAck_method   = Method


// RECORD-ROUTE

Record_Route  = rec_route (COMMA rec_route)* {
                  var idx, length;
                  options = options || { data: {}};
                  length = options.data.multi_header.length;
                  for (idx = 0; idx < length; idx++) {
                    if (options.data.multi_header[idx].parsed === null) {
                      options.data = null;
                      break;
                    }
                  }
                  if (options.data !== null) {
                    options.data = options.data.multi_header;
                  } else {
                    options.data = -1;
                  }}

rec_route     = name_addr ( SEMI rr_param )* {
                  var header;
                  options = options || { data: {}};
                  if(!options.data.multi_header) options.data.multi_header = [];
                  try {
                    header = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
                    delete options.data.uri;
                    delete options.data.displayName;
                    delete options.data.params;
                  } catch(e) {
                    header = null;
                  }
                  options.data.multi_header.push( { 'position': peg$currPos,
                                            'offset': location().start.offset,
                                            'parsed': header
                                          });}

rr_param      = generic_param

// REFER-TO

Refer_To = ( addr_spec / name_addr / LAQUOT? absoluteURI RAQUOT? ) ( SEMI r_param )* {
              options = options || { data: {}};
              options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
            }

r_param = generic_param

// REPLACES

Replaces          = replaces_call_id ( SEMI replaces_params )* {
                      options = options || { data: {}};
                      if (!(options.data.replaces_from_tag && options.data.replaces_to_tag)) {
                        options.data = -1;
                      }
                    }

replaces_call_id  = Call_ID {
                      options = options || { data: {}};
                      options.data = {
                        call_id: options.data
                      };
                    }

replaces_params   = "from-tag"i EQUAL from_tag: token {
                      options = options || { data: {}};
                      options.data.replaces_from_tag = from_tag;
                    }
                  / "to-tag"i EQUAL to_tag: token {
                      options = options || { data: {}};
                      options.data.replaces_to_tag = to_tag;
                    }
                  / "early-only"i {
                      options = options || { data: {}};
                      options.data.early_only = true;
                    }
                  / generic_param

// REQUIRE

Require   =  value:(
                head:option_tag
                tail:(COMMA r:option_tag {return r;})*
                { return list(head, tail); }
              )?
              {
                options = options || { data: {}};
                if (options.startRule === 'Require') {
                  options.data = value || [];
                }
              }


// ROUTE

Route        = route_param (COMMA route_param)*

route_param  = name_addr ( SEMI rr_param )*

// RSEQ

RSeq    = rseq_value: DIGIT + {
                  options = options || { data: {}};
                  options.data.value=parseInt(rseq_value.join('')); }


// SUBSCRIPTION-STATE

Subscription_State   = substate_value ( SEMI subexp_params )*

substate_value       = ( "active"i / "pending"i / "terminated"i
                       / extension_substate ) {
                        options = options || { data: {}};
                        options.data.state = text(); }

extension_substate   = token

subexp_params        = "reason"i EQUAL reason: event_reason_value {
                        options = options || { data: {}};
                        if (typeof reason !== 'undefined') options.data.reason = reason; }
                       / "expires"i EQUAL expires: delta_seconds {
                        options = options || { data: {}};
                        if (typeof expires !== 'undefined') options.data.expires = expires; }
                       / "retry_after"i EQUAL retry_after: delta_seconds {
                        options = options || { data: {}};
                        if (typeof retry_after !== 'undefined') options.data.retry_after = retry_after; }
                       / generic_param

event_reason_value   = "deactivated"i
                       / "probation"i
                       / "rejected"i
                       / "timeout"i
                       / "giveup"i
                       / "noresource"i
                       / "invariant"i
                       / event_reason_extension

event_reason_extension = token


// SUBJECT

Subject  = ( TEXT_UTF8_TRIM )?


// SUPPORTED

Supported  =  value:(
                head:option_tag
                tail:(COMMA r:option_tag {return r;})*
                { return list(head, tail); }
              )?
              {
                options = options || { data: {}};
                if (options.startRule === 'Supported') {
                  options.data = value || [];
                }
              }


// TO

To         = ( addr_spec / name_addr ) ( SEMI to_param )* {
              options = options || { data: {}};
              var tag = options.data.tag;
                options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
                if (tag) {options.data.setParam('tag',tag)}
              }

to_param   = tag_param / generic_param

// VIA

Via               = via_parm (COMMA via_parm)*

via_parm          = sent_protocol LWS sent_by ( SEMI via_params )*

via_params        = via_ttl / via_maddr / via_received / via_branch / response_port / via_extension

via_ttl           = "ttl"i EQUAL via_ttl_value: ttl {
                      options = options || { data: {}};
                      options.data.ttl = via_ttl_value; }

via_maddr         = "maddr"i EQUAL via_maddr: host {
                      options = options || { data: {}};
                      options.data.maddr = via_maddr; }

via_received      = "received"i EQUAL via_received: (IPv4address / IPv6address / IPv6reference) {
                      options = options || { data: {}};
                      options.data.received = via_received; }

via_branch        = "branch"i EQUAL via_branch: token {
                      options = options || { data: {}};
                      options.data.branch = via_branch; }

response_port     = "rport"i EQUAL response_port:(DIGIT*) {
                      options = options || { data: {}};
                      if(typeof response_port !== 'undefined')
                        options.data.rport = response_port.join(''); }

via_extension     = generic_param

sent_protocol     = protocol_name SLASH protocol_version SLASH transport

protocol_name     = via_protocol: ( "SIP"i / token ) {
                      options = options || { data: {}};
                      options.data.protocol = via_protocol; }

protocol_version  = token

transport         = via_transport: ("UDP"i / "TCP"i / "TLS"i / "SCTP"i / other_transport) {
                      options = options || { data: {}};
                      options.data.transport = via_transport; }

sent_by           = viaHost ( COLON via_port )?

viaHost          = ( hostname / IPv4address / IPv6reference ) {
                      options = options || { data: {}};
                      options.data.host = text(); }

via_port          = via_sent_by_port: (DIGIT ? DIGIT ? DIGIT ? DIGIT ? DIGIT ?) {
                      options = options || { data: {}};
                      options.data.port = parseInt(via_sent_by_port.join('')); }

ttl               = ttl: (DIGIT DIGIT ? DIGIT ?) {
                      return parseInt(ttl.join('')); }


// WWW-AUTHENTICATE

WWW_Authenticate  = www_authenticate: challenge


// RFC 4028

Session_Expires   = deltaSeconds:delta_seconds (SEMI se_params)*
                    {
                      options = options || { data: {}};
                      if (options.startRule === 'Session_Expires') {
                        options.data.deltaSeconds = deltaSeconds;
                      }
                    }

se_params         = refresher_param / generic_param

refresher_param   = "refresher" EQUAL endpoint:("uas" / "uac")
                    {
                      options = options || { data: {}};
                      if (options.startRule === 'Session_Expires') {
                        options.data.refresher = endpoint;
                      }
                    }

Min_SE            = deltaSeconds:delta_seconds (SEMI generic_param)*
                    {
                      options = options || { data: {}};
                      if (options.startRule === 'Min_SE') {
                        options.data = deltaSeconds;
                      }
                    }

// EXTENSION-HEADER

extension_header  = extension_header: header_name HCOLON header_value: header_value

header_name       = token

header_value      = (TEXT_UTF8char / UTF8_CONT / LWS)*

message_body      = OCTET*


// STUN URI (draft-nandakumar-rtcweb-stun-uri)

stun_URI          = stun_scheme ":" stun_host_port

stun_scheme       = scheme: ("stuns"i / "stun"i) {
                      options = options || { data: {}};options.data.scheme = scheme; }

stun_host_port    = stun_host ( ":" port )?

stun_host         = host: (IPv4address / IPv6reference / reg_name) {
                      options = options || { data: {}};
                      options.data.host = host; }

stun_unreserved   = ALPHA / DIGIT / "-" / "." / "_" / "~"

sub_delims        = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="


// TURN URI (draft-petithuguenin-behave-turn-uris)

turn_URI          = turn_scheme ":" stun_host_port ( "?transport=" transport )?

turn_scheme       = scheme: ("turns"i / "turn"i) {
                      options = options || { data: {}};options.data.scheme = scheme; }

turn_transport    = transport: ("udp"i / "tcp"i / unreserved*) {
                      options = options || { data: {}};options.data.transport = transport; }

// UUID URI
uuid          = hex8 "-" hex4 "-" hex4 "-" hex4 "-" hex12 {
                  options = options || { data: {}};options.data = text(); }
hex4          = HEXDIG HEXDIG HEXDIG HEXDIG
hex8          = hex4 hex4
hex12         = hex4 hex4 hex4

// RFC 3420 (message/sipfrag)

sipfrag = Request_Response header* (CRLF message_body)?

// RFC 3892 (Referred-By)

Referred_By = ("Referred-By" / "b")  HCOLON  referrer_uri ( SEMI (referredby_id_param / generic_param))*

referrer_uri = (name_addr / addr_spec)

referredby_id_param = "cid" EQUAL sip_clean_msg_id

sip_clean_msg_id = LDQUOT mark "@" (mark / host) RDQUOT
