/*! \file   janus_duktape_extra.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Duktape plugin extra hooks
 * \details  The Janus Duktape plugin implements all the mandatory hooks to
 * allow the C code to interact with a custom JavaScript script, and viceversa.
 * Anyway, JavaScript developers may want to have the C code do more than what
 * is provided out of the box, e.g., by exposing additional JavaScript methods
 * from C for further low level processing or native integration. This
 * "extra" implementation provides a mechanism to do just that, as
 * developers can just add their own custom hooks in the C extra code,
 * and the Duktape plugin will register the new methods along the stock ones.
 *
 * More specifically, the Janus Duktape plugin will always invoke the
 * janus_duktape_register_extra_functions() method when initializing. This
 * means that all developers will need to do to register a new function
 * is adding new \c duk_push_c_function calls to register their own functions
 * there, and they'll be added to the stack.
 *
 * \ingroup jspapi
 * \ref jspapi
 */

#include "janus_duktape_data.h"
#include "janus_duktape_extra.h"
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

/* Helper method to stringify Duktape types */
#define DUK_CASE_STR(type) case type: return #type


static const char *janus_duktape_type_string(int type) {
    switch(type) {
        DUK_CASE_STR(DUK_TYPE_NONE);
        DUK_CASE_STR(DUK_TYPE_UNDEFINED);
        DUK_CASE_STR(DUK_TYPE_NULL);
        DUK_CASE_STR(DUK_TYPE_BOOLEAN);
        DUK_CASE_STR(DUK_TYPE_NUMBER);
        DUK_CASE_STR(DUK_TYPE_STRING);
        DUK_CASE_STR(DUK_TYPE_OBJECT);
        DUK_CASE_STR(DUK_TYPE_BUFFER);
        DUK_CASE_STR(DUK_TYPE_POINTER);
        DUK_CASE_STR(DUK_TYPE_LIGHTFUNC);
        default:
            break;
    }
    return NULL;
}
struct url_data {
    size_t size;
    char* data;
};

size_t write_data(void *ptr, size_t size, size_t nmemb, struct url_data *data) {
    size_t index = data->size;
    size_t n = (size * nmemb);
    char* tmp;

    data->size += (size * nmemb);


    fprintf(stderr, "data at %p size=%ld nmemb=%ld\n", ptr, size, nmemb);

    tmp = realloc(data->data, data->size + 1); /* +1 for '\0' */

    if(tmp) {
        data->data = tmp;
    } else {
        if(data->data) {
            free(data->data);
        }
        fprintf(stderr, "Failed to allocate memory.\n");
        return 0;
    }

    memcpy((data->data + index), ptr, n);
    data->data[data->size] = '\0';

    return size * nmemb;
}

char *handle_url(char* url, char* method, char* body) {
    CURL *curl;

    struct url_data data;
    data.size = 0;
    data.data = malloc(4096); /* reasonable size initial buffer */
    if(NULL == data.data) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return NULL;
    }

    data.data[0] = '\0';

    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        if (method == "post") {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);

    }
    return data.data;
}


/* Sample extra function we can register */
static duk_ret_t http_get(duk_context *ctx) {
    char* data;
    char* url;
    if(duk_get_type(ctx, 0) != DUK_TYPE_STRING && duk_get_type(ctx, 0) != DUK_TYPE_UNDEFINED) {
        duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid URL argument (expected %s, got %s)\n",
                              janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 0)));
        return duk_throw(ctx);
    }else{
        url = duk_get_string(ctx, 0);;
    }
    char* method = "get";
    data = handle_url(url, method, NULL);
    if(data) {
        duk_push_string(ctx, data);
        free(data);
    }

    return 1;
}

static duk_ret_t http_post(duk_context *ctx) {
    char* data;
    char* url;
    char* body;
    if(duk_get_type(ctx, 0) != DUK_TYPE_STRING && duk_get_type(ctx, 0) != DUK_TYPE_UNDEFINED) {
        duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid URL argument (expected %s, got %s)\n",
                              janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 0)));
        return duk_throw(ctx);
    } else {
        url = duk_get_string(ctx, 0);
        body = duk_get_string(ctx, 1);
    }
    char* method = "post";
    data = handle_url(url, method, body);
    if(data) {
        duk_push_string(ctx, data);
        free(data);
    }

    return 1;
}


/* This is where you can add your custom extra functions */


/* Public method to register all custom extra functions */
void janus_duktape_register_extra_functions(duk_context *ctx) {
	if(ctx == NULL)
		return;
	JANUS_LOG(LOG_VERB, "Registering extra Duktape functions\n");

	/* Register all extra functions here */

	duk_push_c_function(ctx, http_get, 1);
	duk_put_global_string(ctx, "http_get");

	duk_push_c_function(ctx, http_post, 2);
    duk_put_global_string(ctx, "http_post");
}
