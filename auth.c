/*! \file    auth.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Requests authentication
 * \details  Implementation of a simple mechanism for authenticating
 * requests. If enabled (it's disabled by default), the Janus admin API
 * can be used to specify valid tokens; each request must then contain
 * a valid token string, or otherwise the request is rejected with an
 * error. Whether tokens should be shared across users or not is
 * completely up to the controlling application: these tokens are
 * completely opaque to Janus, and treated as strings, which means
 * Janus will only check if the token exists or not when asked.
 * 
 * \ingroup core
 * \ref core
 */

#ifdef HAVE_LIBCURL
#  include <curl/curl.h>
#endif
#include "auth.h"
#include "debug.h"
#include "mutex.h"
#include "ice.h"
#include "janus.h"
#include "plugins/plugin.h"

/* Hash table to contain the tokens to match */
static GHashTable *tokens = NULL, *allowed_plugins = NULL;
static gboolean auth_enabled = FALSE;
static char auth_type = '-';
static const void *auth_external_private_data = NULL;
static janus_mutex mutex;

static void janus_auth_free_token(char *token) {
	g_free(token);
}

gboolean (*janus_auth_check_token_external)(const char *token, json_t *root) =
#ifdef HAVE_LIBCURL
        janus_auth_check_token_http;
#else
        janus_auth_check_token_false;
#endif


/* Setup */
void janus_auth_init(char type) {
        auth_type = type;       /* save the requested authentication type */

        switch(auth_type) {
        case 'I' :              /* Internal (traditional) token authentication */
		JANUS_LOG(LOG_INFO, "Internal token based authentication enabled\n");
		tokens = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)janus_auth_free_token, NULL);
		allowed_plugins = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)janus_auth_free_token, NULL);
		auth_enabled = TRUE;
                break;

        case 'E' :              /* External token authentication */
		JANUS_LOG(LOG_INFO, "External token based authentication enabled\n");
                auth_enabled = TRUE;
                break;

        case '-' :
		JANUS_LOG(LOG_WARN, "Token based authentication disabled\n");
                auth_enabled = FALSE;
                break;

        default :
                /* Should never occur. */
		JANUS_LOG(LOG_ERR, "Programmer error: Unexpected auth type: %c\n", type);
                auth_enabled = TRUE;
                break;
        }

	janus_mutex_init(&mutex);
}

gboolean janus_auth_is_enabled(void) {
	return auth_enabled;
}

void janus_auth_deinit(void) {
	janus_mutex_lock(&mutex);
	if(tokens != NULL)
		g_hash_table_destroy(tokens);
	tokens = NULL;
	if(allowed_plugins != NULL)
		g_hash_table_destroy(allowed_plugins);
	allowed_plugins = NULL;
	janus_mutex_unlock(&mutex);
}

/* Tokens manipulation */
gboolean janus_auth_add_token(const char *token) {
	if(!auth_enabled || tokens == NULL) {
		JANUS_LOG(LOG_ERR, "Can't add token, authentication mechanism is disabled\n");
		return FALSE;
	}
	if(token == NULL)
		return FALSE;
	janus_mutex_lock(&mutex);
	if(g_hash_table_lookup(tokens, token)) {
		JANUS_LOG(LOG_VERB, "Token already validated\n");
		janus_mutex_unlock(&mutex);
		return TRUE;
	}
	char *new_token = g_strdup(token);
	g_hash_table_insert(tokens, new_token, new_token);
	janus_mutex_unlock(&mutex);
	return TRUE;
}

gboolean janus_auth_check_token(const char *token, json_t *root) {
        if(!auth_enabled)
                return TRUE;

        if(auth_type == 'I') {  /* Internal authentication */
                if(tokens == NULL)
                        return TRUE;
                janus_mutex_lock(&mutex);
                if(token && g_hash_table_lookup(tokens, token)) {
                        janus_mutex_unlock(&mutex);
                        return TRUE;
                }
                janus_mutex_unlock(&mutex);
                return FALSE;
        } else {                /* External authentication */
                return janus_auth_check_token_external(token, root);
        }
}

GList *janus_auth_list_tokens(void) {
	/* Always NULL if the mechanism is disabled, of course */
	if(!auth_enabled || tokens == NULL)
		return NULL;
	janus_mutex_lock(&mutex);
	GList *list = NULL;
	if(g_hash_table_size(tokens) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, tokens);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			const char *token = value;
			list = g_list_append(list, g_strdup(token));
		}
	}
	janus_mutex_unlock(&mutex);
	return list;
}

gboolean janus_auth_remove_token(const char *token) {
	if(!auth_enabled || tokens == NULL) {
		JANUS_LOG(LOG_ERR, "Can't remove token, authentication mechanism is disabled\n");
		return FALSE;
	}
	janus_mutex_lock(&mutex);
	gboolean ok = token && g_hash_table_remove(tokens, token);
	/* Also clear the allowed plugins mapping */
	GList *list = g_hash_table_lookup(allowed_plugins, token);
	g_hash_table_remove(allowed_plugins, token);
	if(list != NULL)
		g_list_free(list);
	/* Done */
	janus_mutex_unlock(&mutex);
	return ok;
}

/* Plugins access */
gboolean janus_auth_allow_plugin(const char *token, void *plugin) {
	if(!auth_enabled || allowed_plugins == NULL) {
		JANUS_LOG(LOG_ERR, "Can't allow access to plugin, authentication mechanism is disabled\n");
		return FALSE;
	}
	if(token == NULL || plugin == NULL)
		return FALSE;
	janus_mutex_lock(&mutex);
	if(!g_hash_table_lookup(tokens, token)) {
		janus_mutex_unlock(&mutex);
		return FALSE;
	}
	GList *list = g_hash_table_lookup(allowed_plugins, token);
	if(list == NULL) {
		/* Add the new permission now */
		list = g_list_append(list, plugin);
		char *new_token = g_strdup(token);
		g_hash_table_insert(allowed_plugins, new_token, list);
		janus_mutex_unlock(&mutex);
		return TRUE;
	}
	/* We already have a list, update it if needed */
	if(g_list_find(list, plugin) != NULL) {
		JANUS_LOG(LOG_VERB, "Plugin access already allowed for token\n");
		janus_mutex_unlock(&mutex);
		return TRUE;
	}
	list = g_list_append(list, plugin);
	char *new_token = g_strdup(token);
	g_hash_table_insert(allowed_plugins, new_token, list);
	janus_mutex_unlock(&mutex);
	return TRUE;
}

gboolean janus_auth_check_plugin(const char *token, void *plugin) {
	/* Always TRUE if the mechanism is disabled, of course */
	if(!auth_enabled || allowed_plugins == NULL)
		return TRUE;
	janus_mutex_lock(&mutex);
	if(!g_hash_table_lookup(tokens, token)) {
		janus_mutex_unlock(&mutex);
		return FALSE;
	}
	GList *list = g_hash_table_lookup(allowed_plugins, token);
	if(g_list_find(list, plugin) == NULL) {
		janus_mutex_unlock(&mutex);
		return FALSE;
	}
	janus_mutex_unlock(&mutex);
	return TRUE;
}

GList *janus_auth_list_plugins(const char *token) {
	/* Always NULL if the mechanism is disabled, of course */
	if(!auth_enabled || allowed_plugins == NULL)
		return NULL;
	janus_mutex_lock(&mutex);
	if(!g_hash_table_lookup(tokens, token)) {
		janus_mutex_unlock(&mutex);
		return FALSE;
	}
	GList *list = NULL;
	GList *plugins_list = g_hash_table_lookup(allowed_plugins, token);
	if(plugins_list != NULL)
		list = g_list_copy(plugins_list);
	janus_mutex_unlock(&mutex);
	return list;
}

gboolean janus_auth_disallow_plugin(const char *token, void *plugin) {
	if(!auth_enabled || allowed_plugins == NULL) {
		JANUS_LOG(LOG_ERR, "Can't disallow access to plugin, authentication mechanism is disabled\n");
		return FALSE;
	}
	janus_mutex_lock(&mutex);
	if(!g_hash_table_lookup(tokens, token)) {
		janus_mutex_unlock(&mutex);
		return FALSE;
	}
	GList *list = g_hash_table_lookup(allowed_plugins, token);
	if(list != NULL) {
		/* Update the list */
		list = g_list_remove_all(list, plugin);
		char *new_token = g_strdup(token);
		g_hash_table_insert(allowed_plugins, new_token, list);
	}
	janus_mutex_unlock(&mutex);
	return TRUE;
}

#ifdef HAVE_LIBCURL

static const char * get_plugin_name(json_t *root) {
        const char *plugin_name = NULL;
        guint64 session_id = 0;
        guint64 handle_id = 0;
	json_t *s = json_object_get(root, "session_id");
	if(s && json_is_integer(s))
		session_id = json_integer_value(s);
	json_t *h = json_object_get(root, "handle_id");
	if(h && json_is_integer(h))
		handle_id = json_integer_value(h);
        if(session_id > 0 && handle_id > 0) {
                /* Look for our handle */
                janus_session *session = janus_session_find(session_id);
                janus_ice_handle *handle = janus_ice_handle_find(session, handle_id);
                janus_plugin *plugin_t = (janus_plugin *)handle->app;
                plugin_name = plugin_t->get_package();
        }

        return plugin_name;
}


typedef struct ResultData {
        char *memory;
        size_t size;
} ResultData;


static size_t 
resultBytesCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        size_t realsize = size * nmemb;
        struct ResultData *mem = userp;
 
        mem->memory = realloc(mem->memory, mem->size + realsize + 1);
        if(mem->memory == NULL) {
                JANUS_LOG(LOG_ERR, "auth http: out of memory!\n");
                return 0;
        }
 
        /* Copy this new data into the buffer */
        memcpy(&mem->memory[mem->size], contents, realsize);
        mem->size += realsize;        /* update number of bytes in buffer */
        mem->memory[mem->size] = 0;   /* null-terminate */
 
        return realsize;
}

gboolean janus_auth_check_token_http(const char *token, json_t *root) {
        CURL *curl;
        CURLcode res;
        const char *plugin_name = root == NULL ? NULL : get_plugin_name(root);
        char *message;
        ResultData result;
        gboolean ret;
        struct curl_slist *list = NULL;

        /* Add the plugin package name to the message */
        json_object_set(root, "plugin_package", json_string(plugin_name));

        /* Format the request message into a JSON string */
        message = json_dumps(root, JSON_INDENT(2));

        JANUS_LOG(LOG_INFO, "janus_auth_check_token_http: plugin=%s, message:\n%s\n",
                  plugin_name == NULL ? "<null>" : plugin_name, message);

        /* Ensure that a URL has been configured */
        if(!auth_external_private_data) {
                JANUS_LOG(LOG_ERR, "auth http: no URL has been configured\n");
                return FALSE;
        }

        /* Prepare to receive a result */
        if ((result.memory = malloc(1)) == NULL) { /* will grow as needed */
                JANUS_LOG(LOG_ERR, "auth http: out of memory!\n");
                return FALSE;
        }
        result.size = 0;        /* result buffer is initially empty */

        /* Initialize the curl library */
        curl_global_init(CURL_GLOBAL_ALL);

        /* Get a curl handle */
        curl = curl_easy_init();
        if(!curl) {
                JANUS_LOG(LOG_ERR, "auth http: could not initialize curl!\n");
                curl_global_cleanup();
                return FALSE;
        }

        /* Set the URL for this request */
        curl_easy_setopt(curl, CURLOPT_URL, (char *) auth_external_private_data);

        if(message) {
                /* Add the POST data: the user's request we are processing */
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, message);

                /* Give it the data length */
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(message));
        }

        /* Save the authentication request result in memory, piece-by-piece */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resultBytesCallback);

        /* Pass our result struct to the callback function */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&result);

        /* Set the content type of the data we're sending */
        list = curl_slist_append(list, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

        /* Issue the request and get our response! */
        res = curl_easy_perform(curl);

        /* Success? */
        if(res != CURLE_OK) {
                JANUS_LOG(LOG_ERR, "auth http: request failed (%d) to %s\n", res, (char *) auth_external_private_data);
                ret = FALSE;
                goto cleanup;
        }

        JANUS_LOG(LOG_INFO, "janus_auth_check_token_http result:\n%s\n", result.memory);

	/* Parse the JSON payload */
	json_error_t error;
        json_t *resroot;
	resroot = json_loads(result.memory, 0, &error);
	if(!resroot) {
                /* could not parse JSON */
		ret = FALSE;
		goto cleanup;
	}
	if(!json_is_object(resroot)) {
		ret = FALSE;
		json_decref(resroot);
		goto cleanup;
	}

        // Get the 'authenticated' value provided to us
        json_t *authenticated = json_object_get(resroot, "authenticated");
        ret = json_is_true(authenticated);
        json_decref(resroot);

cleanup:
        // Free the result buffer
        free(result.memory);

        /* Clean up this curl request */
        curl_easy_cleanup(curl);

        /* Deinitialize the curl library */
        curl_global_cleanup();

        return ret;
}

#else
gboolean janus_auth_check_token_false(const char *token, json_t *root) {
        JANUS_LOG(LOG_INFO, "External token authentication is not available (LIBCURL was not found)\n");
        return FALSE;
}
#endif

void janus_auth_set_external_private_data(void * data)
{
        auth_external_private_data = data;
}

const char * janus_auth_get_external_private_data(void)
{
        return auth_external_private_data;
}
