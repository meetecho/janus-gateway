#ifndef DUKCURL_H
#define DUKCURL_H

#include "../duktape.h"
#include <curl/curl.h>

duk_ret_t dukopen_curl(duk_context *ctx);

#endif
