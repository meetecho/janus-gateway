/*! \file   janus_mqtt.c
 * \author OEJ
 * Based on the mqtt transport by
 * \author Andrei Nesterov <ae.nesterov@gmail.com>
 * \copyright GNU General Public License v3
 * \brief  Janus MQTT transport plugin
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <MQTTAsync.h>

#include "../debug.h"
#include "../config.h"
#include "../utils.h"

/* Plugin information */
#define JANUS_MQTTEVH_VERSION               1
#define JANUS_MQTTEVH_VERSION_STRING        "0.0.1"
#define JANUS_MQTTEVH_DESCRIPTION           "This is a trivial MQTT event handler plugin for Janus."
#define JANUS_MQTTEVH_NAME                  "JANUS MqttEventHandler plugin"
#define JANUS_MQTTEVH_AUTHOR                "Edvina AB"
#define JANUS_MQTTEVH_PACKAGE               "janus.eventhandler.mqttevh"

/* Plugin methods */
janus_eventhandler *create(void);
int janus_mqttevh_init(const char *config_path);
void janus_mqttevh_destroy(void);
int janus_mqttevh_get_api_compatibility(void);
int janus_mqttevh_get_version(void);
const char *janus_mqttevh_get_version_string(void);
const char *janus_mqttevh_get_description(void);
const char *janus_mqttevh_get_name(void);
const char *janus_mqttevh_get_author(void);
const char *janus_mqttevh_get_package(void);
void janus_mqttevh_incoming_event(json_t *event);

gboolean janus_mqttevh_is_janus_api_enabled(void);
int janus_mqttevh_send_message(void *context, void *request_id, json_t *message);
void janus_mqttevh_session_created(void *context, guint64 session_id);
void janus_mqttevh_session_over(void *context, guint64 session_id, gboolean timeout);


/* Event handler setup */
static janus_eventhandler janus_mqttevh =
        JANUS_EVENTHANDLER_INIT (
                .init = janus_mqttevh_init,
                .destroy = janus_mqttevh_destroy,

                .get_api_compatibility = janus_mqttevh_get_api_compatibility,
                .get_version = janus_mqttevh_get_version,
                .get_version_string = janus_mqttevh_get_version_string,
                .get_description = janus_mqttevh_get_description,
                .get_name = janus_mqttevh_get_name,
                .get_author = janus_mqttevh_get_author,
                .get_package = janus_mqttevh_get_package,

                .incoming_event = janus_mqttevh_incoming_event,

                .events_mask = JANUS_EVENT_TYPE_NONE
        );

/* Plugin creator */
janus_eventhandler *create(void) {
        JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_MQTTEVH_NAME);
        return &janus_mqttevh;
};

/* API flags */
static gboolean janus_mqtt_evh_enabled_ = FALSE;

/* JSON serialization options */
static size_t json_format_ = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* MQTT client context */
typedef struct janus_mqttevh_context {
	//janus_transport_callbacks *gateway;
	MQTTAsync client;
	struct {
		int keep_alive_interval;
		int cleansession;
		char *username;
		char *password;
	} connect;
	struct {
		int timeout;
	} disconnect;
	struct {
		char *topic;
		int qos;
	} publish;
	struct {
		struct {
			char *topic;
			int qos;
			char *lastwill;
		} publish;
	} will;
} janus_mqttevh_context;

/* Transport client methods */
int janus_mqttevh_client_message_arrived(void *context, char *topicName, int topicLen, MQTTAsync_message *message);
void janus_mqttevh_client_connection_lost(void *context, char *cause);
void janus_mqttevh_client_delivery_complete(void *context, MQTTAsync_token token);
int janus_mqttevh_client_connect(janus_mqttevh_context *ctx);
void janus_mqttevh_client_connect_success(void *context, MQTTAsync_successData *response);
void janus_mqttevh_client_connect_failure(void *context, MQTTAsync_failureData *response);
int janus_mqttevh_client_reconnect(janus_mqttevh_context *ctx);
void janus_mqttevh_client_reconnect_success(void *context, MQTTAsync_successData *response);
void janus_mqttevh_client_reconnect_failure(void *context, MQTTAsync_failureData *response);
int janus_mqttevh_client_disconnect(janus_mqttevh_context *ctx);
void janus_mqttevh_client_disconnect_success(void *context, MQTTAsync_successData *response);
void janus_mqttevh_client_disconnect_failure(void *context, MQTTAsync_failureData *response);
int janus_mqttevh_client_publish_message(janus_mqttevh_context *ctx, char *payload);
void janus_mqttevh_client_publish_janus_success(void *context, MQTTAsync_successData *response);
void janus_mqttevh_client_publish_janus_failure(void *context, MQTTAsync_failureData *response);
void janus_mqttevh_client_destroy_context(janus_mqttevh_context **ctx);

/* We only handle a single client */
static janus_mqttevh_context *context_ = NULL;

int janus_mqttevh_init(const char *config_path) {
	if(config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Initializing context */
	janus_mqttevh_context *ctx = g_malloc0(sizeof(struct janus_mqttevh_context));
	context_ = ctx;

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_MQTTEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL) {
		janus_config_print(config);
	}

	/* Handle configuration */
	janus_config_item *url_item = janus_config_get_item_drilldown(config, "general", "url");
	const char *url = g_strdup((url_item && url_item->value) ? url_item->value : "tcp://localhost:1883");

	janus_config_item *client_id_item = janus_config_get_item_drilldown(config, "general", "client_id");
	const char *client_id = g_strdup((client_id_item && client_id_item->value) ? client_id_item->value : "guest");

	janus_config_item *username_item = janus_config_get_item_drilldown(config, "general", "username");
	ctx->connect.username = g_strdup((username_item && username_item->value) ? username_item->value : "guest");
	
	janus_config_item *password_item = janus_config_get_item_drilldown(config, "general", "password");
	ctx->connect.password = g_strdup((password_item && password_item->value) ? password_item->value : "guest");

	janus_config_item *json_item = janus_config_get_item_drilldown(config, "general", "json");
	if(json_item && json_item->value) {
		/* Check how we need to format/serialize the JSON output */
		if(!strcasecmp(json_item->value, "indented")) {
			/* Default: indented, we use three spaces for that */
			json_format_ = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
		} else if(!strcasecmp(json_item->value, "plain")) {
			/* Not indented and no new lines, but still readable */
			json_format_ = JSON_INDENT(0) | JSON_PRESERVE_ORDER;
		} else if(!strcasecmp(json_item->value, "compact")) {
			/* Compact, so no spaces between separators */
			json_format_ = JSON_COMPACT | JSON_PRESERVE_ORDER;
		} else {
			JANUS_LOG(LOG_WARN, "Unsupported JSON format option '%s', using default (indented)\n", json_item->value);
			json_format_ = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
		}
	}

	/* Connect configuration */
	janus_config_item *keep_alive_interval_item = janus_config_get_item_drilldown(config, "general", "keep_alive_interval");
	ctx->connect.keep_alive_interval = (keep_alive_interval_item && keep_alive_interval_item->value) ? atoi(keep_alive_interval_item->value) : 20;

	janus_config_item *cleansession_item = janus_config_get_item_drilldown(config, "general", "cleansession");
	ctx->connect.cleansession = (cleansession_item && cleansession_item->value) ? atoi(cleansession_item->value) : 0;

	/* Disconnect configuration */
	janus_config_item *disconnect_timeout_item = janus_config_get_item_drilldown(config, "general", "disconnect_timeout");
	ctx->disconnect.timeout = (disconnect_timeout_item && disconnect_timeout_item->value) ? atoi(disconnect_timeout_item->value) : 100;

	janus_config_item *enable_item = janus_config_get_item_drilldown(config, "general", "enable");
	if(enable_item && enable_item->value && janus_is_true(enable_item->value)) {
		janus_mqtt_evh_enabled_ = TRUE;

		/* Publish configuration */
		{
			janus_config_item *topic_item = janus_config_get_item_drilldown(config, "general", "publish_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for outgoing messages for MQTT event handler integration...\n");
				goto error;
			}
			ctx->publish.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get_item_drilldown(config, "general", "publish_qos");
			ctx->publish.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}
	}
	else {
		janus_mqtt_evh_enabled_ = FALSE;
		ctx->publish.topic = NULL;
	}

	if(!janus_mqtt_evh_enabled_ ) {
		JANUS_LOG(LOG_WARN, "MQTT event handler support disabled, giving up\n");
		goto error;
	}

	/* Creating a client */
	if(MQTTAsync_create(
			&ctx->client,
			url,
			client_id,
			MQTTCLIENT_PERSISTENCE_NONE,
			NULL) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker: error creating client...\n");
		goto error;
	}
	if(MQTTAsync_setCallbacks(
			ctx->client,
			ctx,
			janus_mqttevh_client_connection_lost,
			janus_mqttevh_client_message_arrived,	//Needed
			janus_mqttevh_client_delivery_complete) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Event handler : Can't connect to MQTT broker: error setting up callbacks...\n");
		goto error;
	}

	/* Connecting to the broker */
	int rc = janus_mqttevh_client_connect(ctx);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d\n", rc);
		goto error;
	}

	return 0;

error:
	/* If we got here, something went wrong */
	janus_mqttevh_client_destroy_context(&ctx);
	g_free((char *)url);
	g_free((char *)client_id);
	g_free(config);

	return -1;
}

void janus_mqttevh_destroy(void) {
	JANUS_LOG(LOG_INFO, "Disconnecting MQTT EVH client...\n");
	janus_mqttevh_client_disconnect(context_);
}

int janus_mqttevh_get_version(void) {
	return JANUS_MQTTEVH_VERSION;
}

const char *janus_mqttevh_get_version_string(void) {
	return JANUS_MQTTEVH_VERSION_STRING;
}

const char *janus_mqttevh_get_description(void) {
	return JANUS_MQTTEVH_DESCRIPTION;
}

const char *janus_mqttevh_get_name(void) {
	return JANUS_MQTTEVH_NAME;
}

const char *janus_mqttevh_get_author(void) {
	return JANUS_MQTTEVH_AUTHOR;
}

const char *janus_mqttevh_get_package(void) {
	return JANUS_MQTTEVH_PACKAGE;
}

gboolean janus_mqttevh_is_janus_api_enabled(void) {
	return janus_mqtt_evh_enabled_;
}

int janus_mqttevh_send_message(void *context, void *request_id, json_t *message) {
	if(message == NULL) {
		return -1;
	}
	if(context == NULL) {
		json_decref(message);
		return -1;
	}

	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
	char *payload = json_dumps(message, json_format_);
	json_decref(message);
	JANUS_LOG(LOG_HUGE, "Sending Event via MQTT: %s\n", payload);

	int rc = janus_mqttevh_client_publish_message(ctx, payload);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_ERR, "Can't publish to MQTT topic: %s, return code: %d\n", ctx->publish.topic, rc);
	}

	return 0;
}

void janus_mqttevh_session_created(void *context, guint64 session_id) {
	/* We don't care */
	JANUS_LOG(LOG_INFO, "MQTT EVHconnection created \n");
}

void janus_mqttevh_session_over(void *context, guint64 session_id, gboolean timeout) {
	/* We don't care, not even if it's a timeout (should we?), our client is always up */
}

void janus_mqttevh_client_connection_lost(void *context, char *cause) {
	JANUS_LOG(LOG_INFO, "MQTT EVH connection lost cause of %s. Reconnecting...\n", cause);
	/* Automatic reconnect */

	/* Notify handlers about this transport being gone */
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
#ifdef SKREP
	if(notify_events && ctx && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("reconnecting"));
		ctx->gateway->notify_event(&janus_mqtt_transport_, context, info);
	}
#endif

}

/* This is not used here, but required by the api (or is it? ) */
int janus_mqttevh_client_message_arrived(void *context, char *topicName, int topicLen, MQTTAsync_message *message) {
        janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
        gchar *topic = g_strndup(topicName, topicLen);
        //const gboolean janus = janus_mqtt_evh_enabled_ &&  !strcasecmp(topic, ctx->subscribe.topic);
        const gboolean janus = janus_mqtt_evh_enabled_ ;
        g_free(topic);

        if(janus && message->payloadlen) {
                JANUS_LOG(LOG_HUGE, "Receiving %s EVH message over MQTT: %s\n", "Janus", (char *)message->payload);

#ifdef SKREP
                json_error_t error;
                json_t *root = json_loadb(message->payload, message->payloadlen, 0, &error);
                ctx->gateway->incoming_request(&janus_mqtt_transport_, ctx, NULL, admin, root, &error);
#endif
        }

        MQTTAsync_freeMessage(&message);
        MQTTAsync_free(topicName);
        return TRUE;
}

void janus_mqttevh_client_delivery_complete(void *context, MQTTAsync_token token) {
	/* If you send with QoS, you get confirmation here */
}

int janus_mqttevh_client_connect(janus_mqttevh_context *ctx) {
	MQTTAsync_connectOptions options = MQTTAsync_connectOptions_initializer;
	options.keepAliveInterval = ctx->connect.keep_alive_interval;
	options.cleansession = ctx->connect.cleansession;
	options.username = ctx->connect.username;
	options.password = ctx->connect.password;
	options.automaticReconnect = TRUE;
	options.onSuccess = janus_mqttevh_client_connect_success;
	options.onFailure = janus_mqttevh_client_connect_failure;
	options.context = ctx;
	return MQTTAsync_connect(ctx->client, &options);
}

void janus_mqttevh_client_connect_success(void *context, MQTTAsync_successData *response) {
	JANUS_LOG(LOG_INFO, "MQTT EVH client has been successfully connected to the broker\n");

	/* Subscribe to one topic at the time */
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
#ifdef SKREP
	/* No need to subscribe here */
	if(janus_mqtt_evh_enabled_) {
		int rc = janus_mqttevh_client_subscribe(context, FALSE);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Can't subscribe to MQTT topic: %s, return code: %d\n", ctx->subscribe.topic, rc);
		}
	}
	else if(janus_mqtt_admin_api_enabled_) {
		int rc = janus_mqttevh_client_subscribe(context, TRUE);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Can't subscribe to MQTT admin topic: %s, return code: %d\n", ctx->admin.subscribe.topic, rc);
		}
	}

	/* Notify handlers about this new transport */

	if(notify_events && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("connected"));
		ctx->gateway->notify_event(&janus_mqtt_transport_, context, info);
	}
#endif
}

void janus_mqttevh_client_connect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT EVH client has failed connecting to the broker, return code: %d. Reconnecting...\n", rc);

	/* Automatic reconnect */

	/* Notify handlers about this transport failure */
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
#ifdef SKREP
	if(notify_events && ctx && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("failed"));
		json_object_set_new(info, "code", json_integer(rc));
		ctx->gateway->notify_event(&janus_mqtt_transport_, context, info);
	}
#endif

}

int janus_mqttevh_client_reconnect(janus_mqttevh_context *ctx) {
	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;
	options.onSuccess = janus_mqttevh_client_reconnect_success;
	options.onFailure = janus_mqttevh_client_reconnect_failure;
	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;

	return MQTTAsync_disconnect(ctx->client, &options);
}

void janus_mqttevh_client_reconnect_success(void *context, MQTTAsync_successData *response) {
	JANUS_LOG(LOG_INFO, "MQTT EVH client has been disconnected. Reconnecting...\n");

	int rc = janus_mqttevh_client_connect(context);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d\n", rc);
	}
}

void janus_mqttevh_client_reconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT EVH client failed reconnecting to MQTT broker, return code: %d\n", rc);
}

int janus_mqttevh_client_disconnect(janus_mqttevh_context *ctx) {
	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;
	options.onSuccess = janus_mqttevh_client_disconnect_success;
	options.onFailure = janus_mqttevh_client_disconnect_failure;
	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;
	return MQTTAsync_disconnect(ctx->client, &options);
}

void janus_mqttevh_client_disconnect_success(void *context, MQTTAsync_successData *response) {
	JANUS_LOG(LOG_INFO, "MQTT EVH client has been successfully disconnected. Destroying the client...\n");

	/* Notify handlers about this transport being gone */
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
#ifdef SKREP
	if(notify_events && ctx && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("disconnected"));
		ctx->gateway->notify_event(&janus_mqtt_transport_, context, info);
	}
#endif

	janus_mqttevh_client_destroy_context(&ctx);
}

void janus_mqttevh_client_disconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "Can't disconnect from MQTT EVH broker, return code: %d\n", rc);

	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
	janus_mqttevh_client_destroy_context(&ctx);
}

int janus_mqttevh_client_publish_message(janus_mqttevh_context *ctx, char *payload ) {
	MQTTAsync_message msg = MQTTAsync_message_initializer;
	msg.payload = payload;
	msg.payloadlen = strlen(payload);
	msg.qos = ctx->publish.qos;
	msg.retained = 0;

	MQTTAsync_responseOptions options;
	options.context = ctx;
	options.onSuccess = janus_mqttevh_client_publish_janus_success;
	options.onFailure = janus_mqttevh_client_publish_janus_failure;
	return MQTTAsync_sendMessage(ctx->client, ctx->publish.topic, &msg, &options);
}

void janus_mqttevh_client_publish_janus_success(void *context, MQTTAsync_successData *response) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
	JANUS_LOG(LOG_HUGE, "MQTT EVH client has successfully published to MQTT topic: %s\n", ctx->publish.topic);
}

void janus_mqttevh_client_publish_janus_failure(void *context, MQTTAsync_failureData *response) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT EVH client has failed publishing to MQTT topic: %s, return code: %d\n", ctx->publish.topic, rc);
}

void janus_mqttevh_client_destroy_context(janus_mqttevh_context **ptr) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)*ptr;
	if(ctx) {
		MQTTAsync_destroy(&ctx->client);
		g_free(ctx->publish.topic);
		g_free(ctx->connect.username);
		g_free(ctx->connect.password);
		g_free(ctx);
		*ptr = NULL;
	}

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_MQTTEVH_NAME);
}
