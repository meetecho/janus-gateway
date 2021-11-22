/*! \file    auth.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Requests authentication
 * \details  Implementation of simple mechanisms for authenticating
 * requests.
 *
 * If enabled (it's disabled by default), each request must contain a
 * valid token string, * or otherwise the request is rejected with an
 * error.
 *
 * When no \c token_auth_secret is set, Stored-token mode is active.
 * In this mode the Janus admin API can be used to specify valid string
 * tokens. Whether tokens should be shared across users or not is
 * completely up to the controlling application: these tokens are
 * completely opaque to Janus, and treated as strings, which means
 * Janus will only check if the token exists or not when asked.
 *
 * However, if a secret is set, the Signed-token mode is used.
 * In this mode, no direct communication between the controlling
 * application and Janus is necessary. Instead, the application signs
 * tokens that Janus can verify using the secret key.
 *
 * \ingroup core
 * \ref core
 */

#include <string.h>
#include <openssl/hmac.h>

#include "auth.h"
#include "debug.h"
#include "mutex.h"
#include "utils.h"

/* Hash table to contain the tokens to match */
static GHashTable *tokens = NULL, *allowed_plugins = NULL;
static gboolean auth_enabled = FALSE;
static janus_mutex mutex;
static char *auth_secret = NULL;

static void janus_auth_free_token(char *token) {
	g_free(token);
}

/* Setup */
void janus_auth_init(gboolean enabled, const char *secret) {
	if(enabled) {
		if(secret == NULL) {
			JANUS_LOG(LOG_INFO, "Stored-Token based authentication enabled\n");
			tokens = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)janus_auth_free_token, NULL);
			allowed_plugins = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)janus_auth_free_token, NULL);
			auth_enabled = TRUE;
		} else {
			JANUS_LOG(LOG_INFO, "Signed-Token based authentication enabled\n");
			auth_secret = g_strdup(secret);
			auth_enabled = TRUE;
		}
	} else {
		JANUS_LOG(LOG_INFO, "Token based authentication disabled\n");
	}
	janus_mutex_init(&mutex);
}

gboolean janus_auth_is_enabled(void) {
	return auth_enabled;
}

gboolean janus_auth_is_stored_mode(void) {
	return auth_enabled && tokens != NULL;
}

void janus_auth_deinit(void) {
	janus_mutex_lock(&mutex);
	if(tokens != NULL)
		g_hash_table_destroy(tokens);
	tokens = NULL;
	if(allowed_plugins != NULL)
		g_hash_table_destroy(allowed_plugins);
	allowed_plugins = NULL;
	g_free(auth_secret);
	auth_secret = NULL;
	janus_mutex_unlock(&mutex);
}

gboolean janus_auth_check_signature(const char *token, const char *realm) {
	if (!auth_enabled || auth_secret == NULL)
		return FALSE;
	gchar **parts = g_strsplit(token, ":", 2);
	gchar **data = NULL;
	/* Token should have exactly one data and one hash part */
	if(!parts[0] || !parts[1] || parts[2])
		goto fail;
	data = g_strsplit(parts[0], ",", 3);
	/* Need at least an expiry timestamp and realm */
	if(!data[0] || !data[1])
		goto fail;
	/* Verify timestamp */
	gint64 expiry_time = strtoll(data[0], NULL, 10);
	gint64 real_time = janus_get_real_time() / 1000000;
	if(expiry_time < 0 || real_time > expiry_time)
		goto fail;
	/* Verify realm */
	if(strcmp(data[1], realm))
		goto fail;
	/* Verify HMAC-SHA1 */
	unsigned char signature[EVP_MAX_MD_SIZE];
	unsigned int len;
	HMAC(EVP_sha1(), auth_secret, strlen(auth_secret), (const unsigned char*)parts[0], strlen(parts[0]), signature, &len);
	gchar *base64 = g_base64_encode(signature, len);
	/* BB - Added conversion to base64URL removing any padding */
	base64ToBase64UrlNoPadding(base64);
	gboolean result = janus_strcmp_const_time(parts[1], base64);
	g_strfreev(data);
	g_strfreev(parts);
	g_free(base64);
	return result;

fail:
	g_strfreev(data);
	g_strfreev(parts);
	return FALSE;
}


/* BB - Added parameter checksum verification */
#define MAX_CHECKSUM_FIELD_NAME_SIZE 64
#define MAX_CHECKSUM_FIELD_SIZE 1024
#define MIN_CHECKSUM_FIELD_SIZE 20

gboolean janus_check_param_checksum(json_t *root, const char* request) {

	char param_name[MAX_CHECKSUM_FIELD_NAME_SIZE];
	gchar **parts = NULL;
	gchar **fields = NULL;

	/* Build the field name */
	g_snprintf(param_name, MAX_CHECKSUM_FIELD_NAME_SIZE, "%s_checksum", request);

	/* Get the checksum parameter */
	json_t *checksum = json_object_get(root, param_name);

	if(!checksum) {
		JANUS_LOG(LOG_WARN, "Field '%s' not present\n", param_name);
		goto fail;
	}


	/* Get the string from the parameter */
	gchar* checksum_str = json_string_value(checksum);

	JANUS_LOG(LOG_WARN, "Field '%s', value '%s'\n", param_name, checksum_str);

	if(strlen(checksum_str) < MIN_CHECKSUM_FIELD_SIZE) {
		JANUS_LOG(LOG_WARN, "Field '%s' too short: '%s'\n", param_name, checksum_str);
		goto fail;
	}

	/* Get the three components: fields, time, signature separated by commas */
	parts = g_strsplit(checksum_str, ":", 3);

	int content_count = 0;

	while(parts[content_count]) {
		content_count++;
	}

	if(content_count < 2) {
		JANUS_LOG(LOG_WARN, "Missing components in '%s': '%s'\n", param_name, checksum_str);
		goto fail;
	}

	fields = g_strsplit(parts[0], ",", -1);

	int field_count = 0;

	while(fields[field_count])
		field_count++;

	if(field_count < 1) {
		JANUS_LOG(LOG_WARN, "Missing fields in '%s': '%s'\n", param_name, checksum_str);
		goto fail;
	}

	char field_content[MAX_CHECKSUM_FIELD_SIZE];
	field_content[0] = 0;

	for(int i = 0; i < field_count; i++) {

		json_t* json_field = json_object_get(root, fields[i]);

		if (!json_field) {
			JANUS_LOG(LOG_WARN, "Field '%s' unavailable for '%s': '%s'\n", fields[i], param_name, checksum_str);
			goto fail;
		}

		int type = json_typeof(json_field);

		gchar* field = NULL;
		switch(type) {
		case JSON_STRING:
			field = json_string_value(json_field);
			break;
		case JSON_TRUE:
			field = "true";
			break;
		case JSON_FALSE:
			field = "false";
			break;
		}

		if (!field) {
			JANUS_LOG(LOG_WARN, "Field value of '%s' could not be obtained for '%s': '%s'\n", fields[i], param_name, checksum_str);
			goto fail;
		}
		if((strlen(field_content) + strlen(field)) >= MAX_CHECKSUM_FIELD_SIZE) {
			JANUS_LOG(LOG_WARN, "Maximum size (%d) exceeded in '%s': '%s'\n", MAX_CHECKSUM_FIELD_SIZE, param_name, checksum_str);
			goto fail;
		}
		strcat(field_content, field);
	}

	if(strlen(field_content) + strlen(parts[1]) >= MAX_CHECKSUM_FIELD_SIZE) {
		JANUS_LOG(LOG_WARN, "Maximum size (%d) exceeded when adding time in '%s': '%s'\n", MAX_CHECKSUM_FIELD_SIZE, param_name, checksum_str);
	}
	else {
		strcat(field_content, parts[1]);
	}

	unsigned char signature[EVP_MAX_MD_SIZE];
	unsigned int len;
	HMAC(EVP_sha256(), auth_secret, strlen(auth_secret), (const unsigned char*)field_content, strlen(field_content), signature, &len);
	gchar *base64 = g_base64_encode(signature, len);
	base64ToBase64UrlNoPadding(base64);

	JANUS_LOG(LOG_INFO, "Calculated checksum hash '%s' -> '%s' %s\n", field_content, base64, strcmp(parts[2], base64) ? "DOES NOT MATCH" : "MATCHES");
	g_free(base64);

fail:

	g_strfreev(parts);
	g_strfreev(fields);

	return TRUE;
}


gboolean janus_auth_check_signature_contains(const char *token, const char *realm, const char *desc) {
	if (!auth_enabled || auth_secret == NULL)
		return FALSE;
	gchar **parts = g_strsplit(token, ":", 2);
	gchar **data = NULL;
	/* Token should have exactly one data and one hash part */
	if(!parts[0] || !parts[1] || parts[2])
		goto fail;
	data = g_strsplit(parts[0], ",", 0);
	/* Need at least an expiry timestamp and realm */
	if(!data[0] || !data[1])
		goto fail;
	/* Verify timestamp */
	gint64 expiry_time = strtoll(data[0], NULL, 10);
	gint64 real_time = janus_get_real_time() / 1000000;
	if(expiry_time < 0 || real_time > expiry_time)
		goto fail;
	/* Verify realm */
	if(strcmp(data[1], realm))
		goto fail;
	/* Find descriptor */
	gboolean result = FALSE;
	int i = 2;
	for(i = 2; data[i]; i++) {
		// BB change instead of verbatim check, verify if the token plugin list contains a superset of the
		// plugin name
		if (strstr(data[i], desc)) {
			result = TRUE;
			break;
		}
	}
	if (!result)
		goto fail;
	/* Verify HMAC-SHA1 */
	unsigned char signature[EVP_MAX_MD_SIZE];
	unsigned int len;
	HMAC(EVP_sha1(), auth_secret, strlen(auth_secret), (const unsigned char*)parts[0], strlen(parts[0]), signature, &len);
	gchar *base64 = g_base64_encode(signature, len);
	/* BB - Added conversion to base64URL removing any padding */
	base64ToBase64UrlNoPadding(base64);
	result = janus_strcmp_const_time(parts[1], base64);
	g_strfreev(data);
	g_strfreev(parts);
	g_free(base64);
	return result;

fail:
	g_strfreev(data);
	g_strfreev(parts);
	return FALSE;
}

/* Tokens manipulation */
gboolean janus_auth_add_token(const char *token) {
	if(!auth_enabled || tokens == NULL) {
		JANUS_LOG(LOG_ERR, "Can't add token, stored-authentication mechanism is disabled\n");
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

gboolean janus_auth_check_token(const char *token) {
	/* Always TRUE if the mechanism is disabled, of course */
	if(!auth_enabled)
		return TRUE;
	if (tokens == NULL)
		return janus_auth_check_signature(token, "janus");
	janus_mutex_lock(&mutex);
	if(token && g_hash_table_lookup(tokens, token)) {
		janus_mutex_unlock(&mutex);
		return TRUE;
	}
	janus_mutex_unlock(&mutex);
	return FALSE;
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
		JANUS_LOG(LOG_ERR, "Can't remove token, stored-authentication mechanism is disabled\n");
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
gboolean janus_auth_allow_plugin(const char *token, janus_plugin *plugin) {
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

gboolean janus_auth_check_plugin(const char *token, janus_plugin *plugin) {
	/* Always TRUE if the mechanism is disabled, of course */
	if(!auth_enabled)
		return TRUE;
	if (allowed_plugins == NULL)
		return janus_auth_check_signature_contains(token, "janus", plugin->get_package());
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

gboolean janus_auth_disallow_plugin(const char *token, janus_plugin *plugin) {
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
