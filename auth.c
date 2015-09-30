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

#include "auth.h"
#include "debug.h"
#include "mutex.h"

/* Hash table to contain the tokens to match */
static GHashTable *tokens = NULL, *allowed_plugins = NULL;
static gboolean auth_enabled = FALSE;
static janus_mutex mutex;

static void janus_auth_free_token(char *token) {
	g_free(token);
}

/* Setup */
void janus_auth_init(gboolean enabled) {
	if(enabled) {
		JANUS_LOG(LOG_INFO, "Token based authentication enabled\n");
		tokens = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)janus_auth_free_token, NULL);
		allowed_plugins = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)janus_auth_free_token, NULL);
		auth_enabled = TRUE;
	} else {
		JANUS_LOG(LOG_WARN, "Token based authentication disabled\n");
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

gboolean janus_auth_check_token(const char *token) {
	/* Always TRUE if the mechanism is disabled, of course */
	if(!auth_enabled || tokens == NULL)
		return TRUE;
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
