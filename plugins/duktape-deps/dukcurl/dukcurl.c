#include "dukcurl.h"


// Create a global array refs in the heap stash.
void duv_ref_setup(duk_context *ctx) {
  duk_push_heap_stash(ctx);

  // Create a new array with one `0` at index `0`.
  duk_push_array(ctx);
  duk_push_int(ctx, 0);
  duk_put_prop_index(ctx, -2, 0);
  // Store it as "refs" in the heap stash
  duk_put_prop_string(ctx, -2, "refs");

  duk_pop(ctx);
}

// like luaL_ref, but assumes storage in "refs" property of heap stash
int duv_ref(duk_context *ctx) {
  int ref;
  if (duk_is_undefined(ctx, -1)) {
    duk_pop(ctx);
    return 0;
  }
  // Get the "refs" array in the heap stash
  duk_push_heap_stash(ctx);
  duk_get_prop_string(ctx, -1, "refs");
  duk_remove(ctx, -2);

  // ref = refs[0]
  duk_get_prop_index(ctx, -1, 0);
  ref = duk_get_int(ctx, -1);
  duk_pop(ctx);

  // If there was a free slot, remove it from the list
  if (ref != 0) {
    // refs[0] = refs[ref]
    duk_get_prop_index(ctx, -1, ref);
    duk_put_prop_index(ctx, -2, 0);
  }
  // Otherwise use the end of the list
  else {
    // ref = refs.length;
    ref = duk_get_length(ctx, -1);
  }

  // swap the array and the user value in the stack
  duk_insert(ctx, -2);

  // refs[ref] = value
  duk_put_prop_index(ctx, -2, ref);

  // Remove the refs array from the stack.
  duk_pop(ctx);

  return ref;
}

void duv_push_ref(duk_context *ctx, int ref) {
  if (!ref) {
    duk_push_undefined(ctx);
    return;
  }
  // Get the "refs" array in the heap stash
  duk_push_heap_stash(ctx);
  duk_get_prop_string(ctx, -1, "refs");
  duk_remove(ctx, -2);

  duk_get_prop_index(ctx, -1, ref);

  duk_remove(ctx, -2);
}

void duv_unref(duk_context *ctx, int ref) {

  if (!ref) return;

  // Get the "refs" array in the heap stash
  duk_push_heap_stash(ctx);
  duk_get_prop_string(ctx, -1, "refs");
  duk_remove(ctx, -2);

  // Insert a new link in the freelist

  // refs[ref] = refs[0]
  duk_get_prop_index(ctx, -1, 0);
  duk_put_prop_index(ctx, -2, ref);
  // refs[0] = ref
  duk_push_int(ctx, ref);
  duk_put_prop_index(ctx, -2, 0);

  duk_pop(ctx);
}


#ifndef bool
  typedef enum { false, true } bool;
#endif

#define DIPROP_CURL "\xff\xff" "curl"

typedef struct {
  CURL *curl;
  duk_context *ctx;
  int write_cb;
  int header_cb;
  int read_cb;
} dcurl_t;

static char error_buf[CURL_ERROR_SIZE];

static void dcurl_verify(duk_context *ctx, CURLcode code) {
  if (!code) { return; }
  const char* message = error_buf;
  if (error_buf[0] == 0) {
    message = curl_easy_strerror(code);
  }
  duk_error(ctx, DUK_ERR_ERROR, message);
}

// Helper to verify item at index is curl instance and get it's pointer
static dcurl_t* dcurl_require_pointer(duk_context *ctx, int index) {
  dcurl_t *container;
  duk_get_prop_string(ctx, index, DIPROP_CURL);
  container = duk_get_pointer(ctx, -1);
  duk_pop(ctx);
  if (!container) {
    duk_error(ctx, DUK_ERR_TYPE_ERROR, "Expected Curl at index %d", index);
    return NULL;
  }
  return container;
}

static CURL* dcurl_instance(duk_context *ctx) {
  CURL *curl;
  duk_push_this(ctx);
  curl = dcurl_require_pointer(ctx, -1);
  duk_pop(ctx);
  return curl;
}

static void dcurl_push(duk_context *ctx, dcurl_t *container) {
  // Create a new instance of CurlPrototype
  duk_push_object(ctx);
  duk_get_global_string(ctx, "CurlPrototype");
  duk_set_prototype(ctx, -2);

  // Store the pointer inside it
  duk_push_pointer(ctx, container);
  duk_put_prop_string(ctx, -2, DIPROP_CURL);
}

// Create a new curl instance
static duk_ret_t dcurl_easy_init(duk_context *ctx) {
  CURL *curl = curl_easy_init();
  dcurl_t *container = malloc(sizeof(*container));
  container->curl = curl;
  container->ctx = ctx;
  container->write_cb = 0;
  container->header_cb = 0;
  container->read_cb = 0;
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buf);
  dcurl_push(ctx, container);
  return 1;
}

// Finalizer that's called when a curl instance is garbage collected.
static duk_ret_t dcurl_easy_cleanup(duk_context *ctx) {
  dcurl_t *container = dcurl_require_pointer(ctx, 0);
  duv_unref(ctx, container->write_cb);
  container->write_cb = 0;
  duv_unref(ctx, container->header_cb);
  container->header_cb = 0;
  duv_unref(ctx, container->read_cb);
  container->read_cb = 0;
  curl_easy_cleanup(container->curl);
  free(container);
  return 0;
}

static size_t write_callback(const char *ptr, size_t size, size_t num, void *userdata) {
  char *buffer;
  dcurl_t *container = userdata;
  duk_context *ctx = container->ctx;
  size = size * num;
  duv_push_ref(ctx, container->write_cb);
  buffer = duk_push_fixed_buffer(ctx, size);
  memcpy(buffer, ptr, size);
  duk_call(ctx, 1);
  return duk_to_int(ctx, -1);
}

static size_t header_callback(const char *ptr, size_t size, size_t num, void *userdata) {
  char *buffer;
  dcurl_t *container = userdata;
  duk_context *ctx = container->ctx;
  size = size * num;
  duv_push_ref(ctx, container->header_cb);
  buffer = duk_push_fixed_buffer(ctx, size);
  memcpy(buffer, ptr, size);
  duk_call(ctx, 1);
  return duk_to_int(ctx, -1);
}

static size_t read_callback(char *buffer, size_t size, size_t num, void *userdata) {
  dcurl_t *container = userdata;
  duk_context *ctx = container->ctx;
  size = size * num;
  size_t outsize;
  const char *output;
  duv_push_ref(ctx, container->read_cb);
  duk_push_int(ctx, size);
  duk_call(ctx, 1);
  if (duk_is_string(ctx, -1)) {
    output = duk_require_lstring(ctx, -1, &outsize);
  }
  else {
    output = duk_require_buffer(ctx, -1, &outsize);
  }
  if (outsize > size) {
    duk_error(ctx, DUK_ERR_TYPE_ERROR, "Read data too big for curl to handle");
    return 0;
  }
  memcpy(buffer, output, outsize);
  return outsize;
}

#define OPT(type, name, constant) \
  if (strcmp(str, name) == 0) {   \
    opt = constant;               \
    goto process##type;           \
  }

#define CALLBACK(type, name, constant1, constant2)                             \
  if (strcmp(str, name) == 0) {                                                \
    if (!duk_is_function(ctx, 1)) {                                            \
      duk_error(ctx, DUK_ERR_TYPE_ERROR, "Function required for callback");    \
    }                                                                          \
    dcurl_verify(ctx, curl_easy_setopt(curl, constant1, type##_callback));     \
    dcurl_verify(ctx, curl_easy_setopt(curl, constant2, container));           \
    duk_dup(ctx, 1);                                                           \
    container->type##_cb = duv_ref(ctx);                                       \
    return 0;                                                                  \
  }

static duk_ret_t dcurl_easy_setopt(duk_context *ctx) {
  dcurl_t *container = dcurl_instance(ctx);
  CURL *curl = container->curl;

  const char *str = duk_require_string(ctx, 0);
  CURLoption opt;

  // Callback options
  CALLBACK(write, "writefunction", CURLOPT_WRITEFUNCTION, CURLOPT_WRITEDATA)
  CALLBACK(header, "headerfunction", CURLOPT_HEADERFUNCTION, CURLOPT_HEADERDATA)
  CALLBACK(read, "readfunction", CURLOPT_READFUNCTION, CURLOPT_READDATA)

  // BEHAVIOR OPTIONS
  OPT(bool, "verbose", CURLOPT_VERBOSE)
  OPT(bool, "header", CURLOPT_HEADER)
  OPT(bool, "noprogress", CURLOPT_NOPROGRESS)
  OPT(bool, "wildcardmatch", CURLOPT_WILDCARDMATCH)

  // NETWORK OPTIONS
  OPT(char, "url", CURLOPT_URL)
  OPT(char, "proxy", CURLOPT_PROXY)
  OPT(long, "proxyport", CURLOPT_PROXYPORT)
  OPT(char, "noproxy", CURLOPT_NOPROXY)
  OPT(long, "httpproxytunnel", CURLOPT_HTTPPROXYTUNNEL)

  OPT(char, "interface", CURLOPT_INTERFACE)
  OPT(long, "localport", CURLOPT_LOCALPORT)
  OPT(long, "localportrange", CURLOPT_LOCALPORTRANGE)
  OPT(long, "dns-cache-timeout", CURLOPT_DNS_CACHE_TIMEOUT)
  OPT(long, "buffersize", CURLOPT_BUFFERSIZE)
  OPT(long, "port", CURLOPT_PORT)
  OPT(bool, "tcp-nodelay", CURLOPT_TCP_NODELAY)
  OPT(long, "address_scope", CURLOPT_ADDRESS_SCOPE)
  OPT(bool, "tcp-keepalive", CURLOPT_TCP_KEEPALIVE)
  OPT(long, "tcp-keepidle", CURLOPT_TCP_KEEPIDLE)
  OPT(long, "tcp-keepintvl", CURLOPT_TCP_KEEPINTVL)
#ifdef CURLOPT_UNIX_SOCKET_PATH
  OPT(char, "unix-socket-path", CURLOPT_UNIX_SOCKET_PATH)
#endif

  // Auth options
  OPT(char, "userpwd", CURLOPT_USERPWD)
  OPT(char, "proxyuserpwd", CURLOPT_PROXYUSERPWD)
  OPT(char, "username", CURLOPT_USERNAME)
  OPT(char, "password", CURLOPT_PASSWORD)
  OPT(char, "login_options", CURLOPT_LOGIN_OPTIONS)
  OPT(char, "proxyusername", CURLOPT_PROXYUSERNAME)
  OPT(char, "proxypassword", CURLOPT_PROXYPASSWORD)


  OPT(bool, "nobody", CURLOPT_NOBODY)
  OPT(long, "infilesize", CURLOPT_INFILESIZE)
  OPT(bool, "upload", CURLOPT_UPLOAD)
  OPT(bool, "ssl-verifypeer", CURLOPT_SSL_VERIFYPEER)
  OPT(long, "ssl-verifyhost", CURLOPT_SSL_VERIFYHOST)

  // HTTP Options
  OPT(bool, "autoreferer", CURLOPT_AUTOREFERER)
  OPT(char, "accept-encoding", CURLOPT_ACCEPT_ENCODING)
  OPT(bool, "transfer-encoding", CURLOPT_TRANSFER_ENCODING)
  OPT(bool, "followlocation", CURLOPT_FOLLOWLOCATION)
  OPT(bool, "unrestricted-auth", CURLOPT_UNRESTRICTED_AUTH)
  OPT(long, "maxredirs", CURLOPT_MAXREDIRS)
  OPT(bool, "post", CURLOPT_POST)
  OPT(char, "postfields", CURLOPT_POSTFIELDS)
  OPT(long, "postfieldsize", CURLOPT_POSTFIELDSIZE)
  OPT(char, "referer", CURLOPT_REFERER)
  OPT(char, "useragent", CURLOPT_USERAGENT)
  OPT(curl_slist, "httpheader", CURLOPT_HTTPHEADER)
  OPT(char, "customrequest", CURLOPT_CUSTOMREQUEST)
  OPT(char, "cookie", CURLOPT_COOKIE)
  OPT(bool, "http-content-decoding", CURLOPT_HTTP_CONTENT_DECODING)
  OPT(bool, "http-transfer-decoding", CURLOPT_HTTP_TRANSFER_DECODING)
  OPT(bool, "httpget", CURLOPT_HTTPGET)
  OPT(bool, "put", CURLOPT_PUT)

  duk_error(ctx, DUK_ERR_REFERENCE_ERROR, "Unknown or unsupported curlopt");
  return 0;

  processchar: {
    dcurl_verify(ctx,
      curl_easy_setopt(curl, opt, (char*)duk_require_string(ctx, 1))
    );
    return 0;
  }

  processlong: {
    dcurl_verify(ctx,
      curl_easy_setopt(curl, opt, (long)duk_require_int(ctx, 1))
    );
    return 0;
  }

  processbool: {
    dcurl_verify(ctx,
      curl_easy_setopt(curl, opt, (long)duk_require_boolean(ctx, 1))
    );
    return 0;
  }

  processcurl_slist: {
    int i, l;
    struct curl_slist *slist = NULL;

    if (!duk_is_array(ctx, 1)) {
      duk_error(ctx, DUK_ERR_TYPE_ERROR, "Expected array of strings");
      return 0;
    }
    l = duk_get_length(ctx, 1);
    for (i = 0; i < l; ++i) {
      duk_get_prop_index(ctx, 1, i);
      slist = curl_slist_append(slist, duk_get_string(ctx, -1));
      duk_pop(ctx);
    }
    dcurl_verify(ctx,
      curl_easy_setopt(curl, opt, slist)
    );
    return 0;
  }

}

static duk_ret_t dcurl_easy_perform(duk_context *ctx) {
  dcurl_t *container = dcurl_instance(ctx);
  CURL *curl = container->curl;

  dcurl_verify(ctx, curl_easy_perform(curl));

  return 0;
}

#define INFO(type, name, constant) \
  if (strcmp(str, name) == 0) {    \
    info = constant;               \
    goto process##type;            \
  }

static duk_ret_t dcurl_easy_getinfo(duk_context *ctx) {
  dcurl_t *container = dcurl_instance(ctx);
  CURL *curl = container->curl;
  const char *str = duk_require_string(ctx, 0);
  CURLINFO info;

  INFO(char, "effective-url", CURLINFO_EFFECTIVE_URL)
  INFO(long, "response-code", CURLINFO_RESPONSE_CODE)
  INFO(long, "http-connectcode", CURLINFO_HTTP_CONNECTCODE)
  INFO(long, "filetime", CURLINFO_FILETIME)
  INFO(double, "total-time", CURLINFO_TOTAL_TIME)
  INFO(double, "namelookup-time", CURLINFO_NAMELOOKUP_TIME)
  INFO(double, "connect-time", CURLINFO_CONNECT_TIME)
  INFO(double, "appconnect-time", CURLINFO_APPCONNECT_TIME)
  INFO(double, "pretransfer-time", CURLINFO_PRETRANSFER_TIME)
  INFO(double, "starttransfer-time", CURLINFO_STARTTRANSFER_TIME)
  INFO(double, "redirect-time", CURLINFO_REDIRECT_TIME)
  INFO(long, "redirect-count", CURLINFO_REDIRECT_COUNT)
  INFO(char, "redirect-url", CURLINFO_REDIRECT_URL)
  INFO(double, "size-upload", CURLINFO_SIZE_UPLOAD)
  INFO(double, "size-download", CURLINFO_SIZE_DOWNLOAD)
  INFO(double, "speed-download", CURLINFO_SPEED_DOWNLOAD)
  INFO(double, "speed-upload", CURLINFO_SPEED_UPLOAD)
  INFO(long, "header-size", CURLINFO_HEADER_SIZE)
  INFO(long, "request-size", CURLINFO_REQUEST_SIZE)
  INFO(long, "ssl-verifyresult", CURLINFO_SSL_VERIFYRESULT)
  INFO(double, "content-length-download", CURLINFO_CONTENT_LENGTH_DOWNLOAD)
  INFO(double, "content-length-upload", CURLINFO_CONTENT_LENGTH_UPLOAD)
  INFO(char, "content-type", CURLINFO_CONTENT_TYPE)
  INFO(char, "private", CURLINFO_PRIVATE)
  INFO(long, "os-errno", CURLINFO_OS_ERRNO)
  INFO(long, "num-connects", CURLINFO_NUM_CONNECTS)
  INFO(char, "primary-ip", CURLINFO_PRIMARY_IP)
  INFO(long, "primary-port", CURLINFO_PRIMARY_PORT)
  INFO(char, "local-ip", CURLINFO_LOCAL_IP)
  INFO(long, "local-port", CURLINFO_LOCAL_PORT)

  duk_error(ctx, DUK_ERR_REFERENCE_ERROR, "Unknown or unsupported curlinfo");
  return 0;

  processchar: {
    const char* str = NULL;
    dcurl_verify(ctx,
      curl_easy_getinfo(curl, info, &str)
    );
    duk_push_string(ctx, str);
    return 1;
  }

  processlong: {
    long num = 0;
    dcurl_verify(ctx,
      curl_easy_getinfo(curl, info, &num)
    );
    duk_push_int(ctx, num);
    return 1;
  }

  processdouble: {
    double num = 0;
    dcurl_verify(ctx,
      curl_easy_getinfo(curl, info, &num)
    );
    duk_push_number(ctx, num);
    return 1;
  }
}

static duk_ret_t dcurl_easy_duphandle(duk_context *ctx) {
  dcurl_t *container = dcurl_instance(ctx);
  CURL *curl = container->curl;
  CURL *dup = curl_easy_duphandle(curl);
  dcurl_push(ctx, dup);
  return 1;
}

static duk_ret_t dcurl_easy_reset(duk_context *ctx) {
  dcurl_t *container = dcurl_instance(ctx);
  CURL *curl = container->curl;
  curl_easy_reset(curl);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buf);
  return 0;
}

static const duk_function_list_entry dcurl_easy_methods[] = {
  {"setopt", dcurl_easy_setopt, 2},
  {"perform", dcurl_easy_perform, 0},
  {"getinfo", dcurl_easy_getinfo, 1},
  {"duphandle", dcurl_easy_duphandle, 0},
  {"reset", dcurl_easy_reset, 0},
  {NULL, NULL, 0},
};

duk_ret_t dukopen_curl(duk_context *ctx) {
  // Setup the ref system
  duv_ref_setup(ctx);

  // Create the handle prototype as global CurlPrototype
  duk_push_object(ctx);
  duk_push_c_function(ctx, dcurl_easy_cleanup, 0);
  duk_set_finalizer(ctx, -2);
  duk_put_function_list(ctx, -1, dcurl_easy_methods);
  duk_put_global_string(ctx, "CurlPrototype");
  // Push init as the module itself
  duk_push_c_function(ctx, dcurl_easy_init, 0);
  duk_put_global_string(ctx, "curl");
  return 1;
}
