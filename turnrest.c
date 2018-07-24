/*! \file    utils.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    TURN REST API client
 * \details  Implementation of the \c draft-uberti-rtcweb-turn-rest-00
 * draft, that is a REST API that can be used to access TURN services,
 * more specifically credentials to use. Currently implemented in both
 * rfc5766-turn-server and coturn, and so should be generic enough to
 * be usable here.
 * \note This implementation depends on \c libcurl and is optional.
 * 
 * \ingroup core
 * \ref core
 */
 
#ifdef HAVE_LIBCURL

#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <agent.h>

#include "turnrest.h"
#include "debug.h"
#include "mutex.h"
#include "ip-utils.h"

static const char *api_server = NULL;
static const char *api_key = NULL;
static gboolean api_http_get = FALSE;
static janus_mutex api_mutex = JANUS_MUTEX_INITIALIZER;


/* Buffer we use to receive the response via libcurl */
typedef struct janus_turnrest_buffer {
	char *buffer;
	size_t size;
} janus_turnrest_buffer;
 
/* Callback we use to progressively receive the whole response via libcurl in the buffer */
static size_t janus_turnrest_callback(void *payload, size_t size, size_t nmemb, void *data) {
	size_t realsize = size * nmemb;
	janus_turnrest_buffer *buf = (struct janus_turnrest_buffer *)data;
	/* (Re)allocate if needed */
	buf->buffer = g_realloc(buf->buffer, buf->size+realsize+1);
	/* Update the buffer */
	memcpy(&(buf->buffer[buf->size]), payload, realsize);
	buf->size += realsize;
	buf->buffer[buf->size] = 0;
	/* Done! */
	return realsize;
}


void janus_turnrest_init(void) {
	/* Initialize libcurl, needed for contacting the TURN REST API backend */
	curl_global_init(CURL_GLOBAL_ALL);
}

void janus_turnrest_deinit(void) {
	/* Cleanup the libcurl initialization */
	curl_global_cleanup();
	janus_mutex_lock(&api_mutex);
	g_free((char *)api_server);
	g_free((char *)api_key);
	janus_mutex_unlock(&api_mutex);
}

void janus_turnrest_set_backend(const char *server, const char *key, const char *method) {
	janus_mutex_lock(&api_mutex);
	
	/* Get rid of the old values first */
	g_free((char *)api_server);
	api_server = NULL;
	g_free((char *)api_key);
	api_key = NULL;

	if(server != NULL) {
		/* Set a new server now */
		api_server = g_strdup(server);
		if(key != NULL)
			api_key = g_strdup(key);
		if(method != NULL) {
			if(!strcasecmp(method, "get")) {
				api_http_get = TRUE;
			} else if(!strcasecmp(method, "post")) {
				api_http_get = FALSE;
			} else {
				JANUS_LOG(LOG_WARN, "Unknown method '%s' for TURN REST API, assuming POST\n", method);
				api_http_get = FALSE;
			}
		}
	}
	janus_mutex_unlock(&api_mutex);
}

const char *janus_turnrest_get_backend(void) {
	return api_server;
}

static void janus_turnrest_instance_destroy(gpointer data) {
	janus_turnrest_instance *instance = (janus_turnrest_instance *)data;
	if(instance == NULL)
		return;
	g_free(instance->server);
	g_free(instance);
}

void janus_turnrest_response_destroy(janus_turnrest_response *response) {
	if(response == NULL)
		return;
	g_free(response->username);
	g_free(response->password);
	g_list_free_full(response->servers, janus_turnrest_instance_destroy);
}

janus_turnrest_response *janus_turnrest_request(void) {
	janus_mutex_lock(&api_mutex);
	if(api_server == NULL) {
		janus_mutex_unlock(&api_mutex);
		return NULL;
	}
	/* Prepare the request URI */
	char query_string[512];
	g_snprintf(query_string, 512, "service=turn");
	if(api_key != NULL) {
		char buffer[256];
		g_snprintf(buffer, 256, "&api=%s", api_key);
		g_strlcat(query_string, buffer, 512);
	}
	char request_uri[1024];
	g_snprintf(request_uri, 1024, "%s?%s", api_server, query_string);
	JANUS_LOG(LOG_VERB, "Sending request: %s\n", request_uri);
	janus_mutex_unlock(&api_mutex);
	/* Prepare the libcurl context */
	CURLcode res;
	CURL *curl = curl_easy_init();
	if(curl == NULL) {
		JANUS_LOG(LOG_ERR, "libcurl error\n");
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_URL, request_uri);
	curl_easy_setopt(curl, api_http_get ? CURLOPT_HTTPGET : CURLOPT_POST, 1);
	if(!api_http_get) {
		/* FIXME Some servers don't like a POST with no data */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query_string);
	}
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);	/* FIXME Max 10 seconds */
	/* For getting data, we use an helper struct and the libcurl callback */
	janus_turnrest_buffer data;
	data.buffer = g_malloc0(1);
	data.size = 0;
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, janus_turnrest_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "Janus/1.0");
	/* Send the request */
	res = curl_easy_perform(curl);
	if(res != CURLE_OK) {
		JANUS_LOG(LOG_ERR, "Couldn't send the request: %s\n", curl_easy_strerror(res));
		g_free(data.buffer);
		curl_easy_cleanup(curl);
		return NULL;
	}
	/* Cleanup the libcurl context */
	curl_easy_cleanup(curl);
	/* Process the response */
	JANUS_LOG(LOG_VERB, "Got %zu bytes from the TURN REST API server\n", data.size);
	JANUS_LOG(LOG_VERB, "%s\n", data.buffer);
	json_error_t error;
	json_t *root = json_loads(data.buffer, 0, &error);
	if(!root) {
		JANUS_LOG(LOG_ERR, "Couldn't parse response: error on line %d: %s", error.line, error.text);
		g_free(data.buffer);
		return NULL;
	}
	g_free(data.buffer);
	json_t *username = json_object_get(root, "username");
	if(!username) {
		JANUS_LOG(LOG_ERR, "Invalid response: missing username\n");
		return NULL;
	}
	if(!json_is_string(username)) {
		JANUS_LOG(LOG_ERR, "Invalid response: username should be a string\n");
		return NULL;
	}
	json_t *password = json_object_get(root, "password");
	if(!password) {
		JANUS_LOG(LOG_ERR, "Invalid response: missing password\n");
		return NULL;
	}
	if(!json_is_string(password)) {
		JANUS_LOG(LOG_ERR, "Invalid response: password should be a string\n");
		return NULL;
	}
	json_t *ttl = json_object_get(root, "ttl");
	if(ttl && (!json_is_integer(ttl) || json_integer_value(ttl) < 0)) {
		JANUS_LOG(LOG_ERR, "Invalid response: ttl should be a positive integer\n");
		return NULL;
	}
	json_t *uris = json_object_get(root, "uris");
	if(!uris) {
		JANUS_LOG(LOG_ERR, "Invalid response: missing uris\n");
		return NULL;
	}
	if(!json_is_array(uris) || json_array_size(uris) == 0) {
		JANUS_LOG(LOG_ERR, "Invalid response: uris should be a non-empty array\n");
		return NULL;
	}
	/* Turn the response into a janus_turnrest_response object we can use */
	janus_turnrest_response *response = g_malloc(sizeof(janus_turnrest_response));
	response->username = g_strdup(json_string_value(username));
	response->password = g_strdup(json_string_value(password));
	response->ttl = ttl ? json_integer_value(ttl) : 0;
	response->servers = NULL;
	size_t i = 0;
	for(i=0; i<json_array_size(uris); i++) {
		json_t *uri = json_array_get(uris, i);
		if(uri == NULL || !json_is_string(uri)) {
			JANUS_LOG(LOG_WARN, "Skipping invalid TURN URI (not a string)...\n");
			continue;
		}
		const char *turn_uri = json_string_value(uri);
		if(strstr(turn_uri, "turn:") != turn_uri && strstr(turn_uri, "turns:") != turn_uri) {
			JANUS_LOG(LOG_WARN, "Skipping invalid TURN URI '%s' (not a TURN URI)...\n", turn_uri);
			continue;
		}
		janus_turnrest_instance *instance = g_malloc(sizeof(janus_turnrest_instance));
		instance->transport = NICE_RELAY_TYPE_TURN_UDP;
		if(strstr(turn_uri, "turns:") == turn_uri || strstr(turn_uri, "transport=tls") != NULL)
			instance->transport = NICE_RELAY_TYPE_TURN_TLS;
		else if(strstr(turn_uri, "transport=tcp") != NULL)
			instance->transport = NICE_RELAY_TYPE_TURN_TCP;
		gchar **parts = NULL;
		if(strstr(turn_uri, "?") != NULL) {
			parts = g_strsplit(turn_uri, "?", -1);
			turn_uri = parts[0];
		}
		gchar **uri_parts = g_strsplit(turn_uri, ":", -1);
		/* Resolve the TURN URI address */
		struct addrinfo *res = NULL;
		janus_network_address addr;
		janus_network_address_string_buffer addr_buf;
		if(getaddrinfo(uri_parts[1], NULL, NULL, &res) != 0 ||
				janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
				janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
			JANUS_LOG(LOG_WARN, "Skipping invalid TURN URI '%s' (could not resolve the address)...\n", uri_parts[1]);
			if(res != NULL)
				freeaddrinfo(res);
			g_strfreev(uri_parts);
			continue;
		}
		freeaddrinfo(res);
		instance->server = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
		if(uri_parts[2] == NULL) {
			/* No port? Use 3478 by default */
			instance->port = 3478;
		} else {
			instance->port = atoi(uri_parts[2]);
		}
		g_strfreev(uri_parts);
		g_strfreev(parts);
		/* Add the server to the list */
		response->servers = g_list_append(response->servers, instance);
	}
	if(response->servers == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't find any valid TURN URI in the response...\n");
		janus_turnrest_response_destroy(response);
		return NULL; 
	}
	/* Done */
	return response;
}

#endif
