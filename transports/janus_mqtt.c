/*! \file   janus_mqtt.c
 * \author Andrei Nesterov <ae.nesterov@gmail.com>
 * \copyright GNU General Public License v3
 * \brief  Janus MQTT transport plugin
 * \details  This is an implementation of a MQTT transport for the Janus API,
 * using the Eclipse Paho C Client library (https://eclipse.org/paho/clients/c).
 * This means that this module adds support for MQTT based messaging as
 * an alternative "transport" for API requests, responses and notifications.
 * This is only useful when you're handling the communication with
 * clients your own way. Right now, you can only configure
 * the address of the MQTT broker to use, and the queues to
 * make use of to receive (to-janus) and send (from-janus) messages
 * from/to an external application. As with WebSockets, considering that
 * requests wouldn't include a path to address some mandatory information,
 * these requests addressed to Janus should include as part of their payload,
 * when needed, additional pieces of information like \c session_id and
 * \c handle_id. That is, where you'd send a Janus request related to a
 * specific session to the \c /janus/<session> path, with MQTT
 * you'd have to send the same request with an additional \c session_id
 * field in the JSON payload.
 * \note When you create a session using MQTT, a subscription to the
 * events related to it is done automatically through the outgoing queue,
 * so no need for an explicit request as the GET in the plain HTTP API.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <MQTTAsync.h>

#include "../debug.h"
#include "../config.h"
#include "../utils.h"

/* Transport plugin information */
#define JANUS_MQTT_VERSION        1
#define JANUS_MQTT_VERSION_STRING "0.0.1"
#define JANUS_MQTT_DESCRIPTION    "This transport plugin adds MQTT support to the Janus API via Paho client library."
#define JANUS_MQTT_NAME           "JANUS MQTT transport plugin"
#define JANUS_MQTT_AUTHOR         "Andrei Nesterov <ae.nesterov@gmail.com>"
#define JANUS_MQTT_PACKAGE        "janus.transport.mqtt"

/* Transport methods */
janus_transport *create(void);
int janus_mqtt_init(janus_transport_callbacks *callback, const char *config_path);
void janus_mqtt_destroy(void);
int janus_mqtt_get_api_compatibility(void);
int janus_mqtt_get_version(void);
const char *janus_mqtt_get_version_string(void);
const char *janus_mqtt_get_description(void);
const char *janus_mqtt_get_name(void);
const char *janus_mqtt_get_author(void);
const char *janus_mqtt_get_package(void);
gboolean janus_mqtt_is_janus_api_enabled(void);
gboolean janus_mqtt_is_admin_api_enabled(void);
int janus_mqtt_send_message(void *context, void *request_id, gboolean admin, json_t *message);
void janus_mqtt_session_created(void *context, guint64 session_id);
void janus_mqtt_session_over(void *context, guint64 session_id, gboolean timeout);

/* Transport setup */
static janus_transport janus_mqtt_transport_ =
	JANUS_TRANSPORT_INIT (
		.init = janus_mqtt_init,
		.destroy = janus_mqtt_destroy,

		.get_api_compatibility = janus_mqtt_get_api_compatibility,
		.get_version = janus_mqtt_get_version,
		.get_version_string = janus_mqtt_get_version_string,
		.get_description = janus_mqtt_get_description,
		.get_name = janus_mqtt_get_name,
		.get_author = janus_mqtt_get_author,
		.get_package = janus_mqtt_get_package,

		.is_janus_api_enabled = janus_mqtt_is_janus_api_enabled,
		.is_admin_api_enabled = janus_mqtt_is_admin_api_enabled,

		.send_message = janus_mqtt_send_message,
		.session_created = janus_mqtt_session_created,
		.session_over = janus_mqtt_session_over,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_MQTT_NAME);
	return &janus_mqtt_transport_;
}

/* API flags */
static gboolean janus_mqtt_api_enabled_ = FALSE;
static gboolean janus_mqtt_admin_api_enabled_ = FALSE;

/* JSON serialization options */
static size_t json_format_ = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* MQTT client context */
typedef struct janus_mqtt_context {
	janus_transport_callbacks *gateway;
	MQTTAsync client;
	struct {
		int keep_alive_interval;
		int cleansession;
	} connect;
	struct {
		int timeout;
	} disconnect;
	struct {
		char *topic;
		int qos;
	} subscribe;
	struct {
		char *topic;
		int qos;
	} publish;
	struct {
		struct {
			char *topic;
			int qos;
		} subscribe;
		struct {
			char *topic;
			int qos;
		} publish;
	} admin;
} janus_mqtt_context;

/* Transport client methods */
void janus_mqtt_client_connection_lost(void *context, char *cause);
int janus_mqtt_client_message_arrived(void *context, char *topicName, int topicLen, MQTTAsync_message *message);
void janus_mqtt_client_delivery_complete(void *context, MQTTAsync_token token);
int janus_mqtt_client_connect(janus_mqtt_context *ctx);
void janus_mqtt_client_connect_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_connect_failure(void *context, MQTTAsync_failureData *response);
int janus_mqtt_client_reconnect(janus_mqtt_context *ctx);
void janus_mqtt_client_reconnect_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_reconnect_failure(void *context, MQTTAsync_failureData *response);
int janus_mqtt_client_disconnect(janus_mqtt_context *ctx);
void janus_mqtt_client_disconnect_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_disconnect_failure(void *context, MQTTAsync_failureData *response);
int janus_mqtt_client_subscribe(janus_mqtt_context *ctx, gboolean admin);
void janus_mqtt_client_subscribe_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_subscribe_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_admin_subscribe_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_admin_subscribe_failure(void *context, MQTTAsync_failureData *response);
int janus_mqtt_client_publish_message(janus_mqtt_context *ctx, char *payload, gboolean admin);
void janus_mqtt_client_publish_janus_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_publish_janus_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_publish_admin_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_publish_admin_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_destroy_context(janus_mqtt_context **ctx);

/* We only handle a single client */
static janus_mqtt_context *context_ = NULL;

int janus_mqtt_init(janus_transport_callbacks *callback, const char *config_path) {
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Initializing context */
	janus_mqtt_context *ctx = g_malloc0(sizeof(struct janus_mqtt_context));
	ctx->gateway = callback;
	context_ = ctx;

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_MQTT_PACKAGE);
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
	const char *username = g_strdup((username_item && username_item->value) ? username_item->value : "guest");
	
	janus_config_item *password_item = janus_config_get_item_drilldown(config, "general", "password");
	const char *password = g_strdup((password_item && password_item->value) ? password_item->value : "guest");

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
		janus_mqtt_api_enabled_ = TRUE;

		/* Subscribe configuration */
		{
			janus_config_item *topic_item = janus_config_get_item_drilldown(config, "general", "subscribe_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for incoming messages for MQTT integration...\n");
				goto error;
			}
			ctx->subscribe.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get_item_drilldown(config, "general", "subscribe_qos");
			ctx->subscribe.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}

		/* Publish configuration */
		{
			janus_config_item *topic_item = janus_config_get_item_drilldown(config, "general", "publish_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for outgoing messages for MQTT integration...\n");
				goto error;
			}
			ctx->publish.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get_item_drilldown(config, "general", "publish_qos");
			ctx->publish.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}
	}
	else {
		janus_mqtt_api_enabled_ = FALSE;
		ctx->subscribe.topic = NULL;
		ctx->publish.topic = NULL;
	}

	/* Admin configuration */
	janus_config_item *admin_enable_item = janus_config_get_item_drilldown(config, "admin", "admin_enable");
	if(admin_enable_item && admin_enable_item->value && janus_is_true(admin_enable_item->value)) {
		janus_mqtt_admin_api_enabled_ = TRUE;

		/* Admin subscribe configuration */
		{
			janus_config_item *topic_item = janus_config_get_item_drilldown(config, "admin", "subscribe_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for incoming admin messages for MQTT integration...\n");
				goto error;
			}
			ctx->admin.subscribe.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get_item_drilldown(config, "admin", "subscribe_qos");
			ctx->admin.subscribe.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}

		/* Admin publish configuration */
		{
			janus_config_item *topic_item = janus_config_get_item_drilldown(config, "admin", "publish_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for outgoing admin messages for MQTT integration...\n");
				goto error;
			}
			ctx->admin.publish.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get_item_drilldown(config, "admin", "publish_qos");
			ctx->admin.publish.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}
	}
	else {
		janus_mqtt_admin_api_enabled_ = FALSE;
		ctx->admin.subscribe.topic = NULL;
		ctx->admin.publish.topic = NULL;
	}

	if(!janus_mqtt_api_enabled_ && !janus_mqtt_admin_api_enabled_) {
		JANUS_LOG(LOG_WARN, "MQTT support disabled for both Janus and Admin API, giving up\n");
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
			janus_mqtt_client_connection_lost,
			janus_mqtt_client_message_arrived,
			janus_mqtt_client_delivery_complete) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker: error setting up callbacks...\n");
		goto error;
	}

	/* Connecting to the broker */
	int rc = janus_mqtt_client_connect(ctx);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d\n", rc);
		goto error;
	}

	return 0;

error:
	/* If we got here, something went wrong */
	janus_mqtt_client_destroy_context(&ctx);
	g_free((char *)url);
	g_free((char *)client_id);
	g_free((char *)username);
	g_free((char *)password);
	g_free(config);

	return -1;
}

void janus_mqtt_destroy(void) {
	JANUS_LOG(LOG_INFO, "Disconnecting MQTT client...\n");

	janus_mqtt_client_disconnect(context_);
}

int janus_mqtt_get_api_compatibility(void) {
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_mqtt_get_version(void) {
	return JANUS_MQTT_VERSION;
}

const char *janus_mqtt_get_version_string(void) {
	return JANUS_MQTT_VERSION_STRING;
}

const char *janus_mqtt_get_description(void) {
	return JANUS_MQTT_DESCRIPTION;
}

const char *janus_mqtt_get_name(void) {
	return JANUS_MQTT_NAME;
}

const char *janus_mqtt_get_author(void) {
	return JANUS_MQTT_AUTHOR;
}

const char *janus_mqtt_get_package(void) {
	return JANUS_MQTT_PACKAGE;
}

gboolean janus_mqtt_is_janus_api_enabled(void) {
	return janus_mqtt_api_enabled_;
}

gboolean janus_mqtt_is_admin_api_enabled(void) {
	return janus_mqtt_admin_api_enabled_;
}

int janus_mqtt_send_message(void *context, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL) {
		return -1;
	}
	if(context == NULL) {
		json_decref(message);
		return -1;
	}

	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	char *payload = json_dumps(message, json_format_);
	json_decref(message);
	JANUS_LOG(LOG_HUGE, "Sending %s API message via MQTT: %s\n", admin ? "admin" : "Janus", payload);

	int rc = janus_mqtt_client_publish_message(ctx, payload, admin);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_ERR, "Can't publish to MQTT topic: %s, return code: %d\n", admin ? ctx->admin.publish.topic : ctx->publish.topic, rc);
	}

	return 0;
}

void janus_mqtt_session_created(void *context, guint64 session_id) {
	/* We don't care */
}

void janus_mqtt_session_over(void *context, guint64 session_id, gboolean timeout) {
	/* We don't care, not even if it's a timeout (should we?), our client is always up */
}

void janus_mqtt_client_connection_lost(void *context, char *cause) {
	JANUS_LOG(LOG_INFO, "MQTT connection lost cause of %s. Reconnecting...\n", cause);
	/* Automatic reconnect */
}

int janus_mqtt_client_message_arrived(void *context, char *topicName, int topicLen, MQTTAsync_message *message) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	gchar *topic = g_strndup(topicName, topicLen);
	const gboolean janus = janus_mqtt_api_enabled_ &&  !strcasecmp(topic, ctx->subscribe.topic);
	const gboolean admin = janus_mqtt_admin_api_enabled_ && !strcasecmp(topic, ctx->admin.subscribe.topic);
	g_free(topic);

	if((janus || admin) && message->payloadlen) {
		JANUS_LOG(LOG_HUGE, "Receiving %s API message over MQTT: %s\n", admin ? "admin" : "Janus", (char *)message->payload);

		json_error_t error;
		json_t *root = json_loadb(message->payload, message->payloadlen, 0, &error);
		ctx->gateway->incoming_request(&janus_mqtt_transport_, ctx, NULL, admin, root, &error);
	}

	MQTTAsync_freeMessage(&message);
	MQTTAsync_free(topicName);
	return TRUE;
}

void janus_mqtt_client_delivery_complete(void *context, MQTTAsync_token token) {
}

int janus_mqtt_client_connect(janus_mqtt_context *ctx) {
	MQTTAsync_connectOptions options = MQTTAsync_connectOptions_initializer;
	options.keepAliveInterval = ctx->connect.keep_alive_interval;
	options.cleansession = ctx->connect.cleansession;
	options.automaticReconnect = TRUE;
	options.onSuccess = janus_mqtt_client_connect_success;
	options.onFailure = janus_mqtt_client_connect_failure;
	options.context = ctx;
	return MQTTAsync_connect(ctx->client, &options);
}

void janus_mqtt_client_connect_success(void *context, MQTTAsync_successData *response) {
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully connected to the broker\n");

	/* Subscribe to one (janus or admin) topic at the time */
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	if(janus_mqtt_api_enabled_) {
		int rc = janus_mqtt_client_subscribe(context, FALSE);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Can't subscribe to MQTT topic: %s, return code: %d\n", ctx->subscribe.topic, rc);
		}
	}
	else if(janus_mqtt_admin_api_enabled_) {
		int rc = janus_mqtt_client_subscribe(context, TRUE);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Can't subscribe to MQTT admin topic: %s, return code: %d\n", ctx->admin.subscribe.topic, rc);
		}
	}
}

void janus_mqtt_client_connect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT client has been failed connecting to the broker, return code: %d. Reconnecting...\n", rc);
	/* Automatic reconnect */
}

int janus_mqtt_client_reconnect(janus_mqtt_context *ctx) {
	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;
	options.onSuccess = janus_mqtt_client_reconnect_success;
	options.onFailure = janus_mqtt_client_reconnect_failure;
	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;
	return MQTTAsync_disconnect(ctx->client, &options);
}

void janus_mqtt_client_reconnect_success(void *context, MQTTAsync_successData *response) {
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully disconnected. Reconnecting...\n");

	int rc = janus_mqtt_client_connect(context);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d\n", rc);
	}
}

void janus_mqtt_client_reconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT client has been failed reconnecting from MQTT broker, return code: %d\n", rc);
}

int janus_mqtt_client_disconnect(janus_mqtt_context *ctx) {
	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;
	options.onSuccess = janus_mqtt_client_disconnect_success;
	options.onFailure = janus_mqtt_client_disconnect_failure;
	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;
	return MQTTAsync_disconnect(ctx->client, &options);
}

void janus_mqtt_client_disconnect_success(void *context, MQTTAsync_successData *response) {
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully disconnected. Destroying the client...\n");

	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	janus_mqtt_client_destroy_context(&ctx);
}

void janus_mqtt_client_disconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "Can't disconnect from MQTT broker, return code: %d\n", rc);

	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	janus_mqtt_client_destroy_context(&ctx);
}

int janus_mqtt_client_subscribe(janus_mqtt_context *ctx, gboolean admin) {
	MQTTAsync_responseOptions options = MQTTAsync_responseOptions_initializer;
	options.context = ctx;
	if(admin) {
		options.onSuccess = janus_mqtt_client_admin_subscribe_success;
		options.onFailure = janus_mqtt_client_admin_subscribe_failure;
		return MQTTAsync_subscribe(ctx->client, ctx->admin.subscribe.topic, ctx->admin.subscribe.qos, &options);
	}
	else {
		options.onSuccess = janus_mqtt_client_subscribe_success;
		options.onFailure = janus_mqtt_client_subscribe_failure;
		return MQTTAsync_subscribe(ctx->client, ctx->subscribe.topic, ctx->subscribe.qos, &options);
	}
}

void janus_mqtt_client_subscribe_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully subscribed to MQTT topic: %s\n", ctx->subscribe.topic);

	/* Subscribe to admin topic if we haven't done it yet */
	if(janus_mqtt_admin_api_enabled_ && (!janus_mqtt_api_enabled_ || strcasecmp(ctx->subscribe.topic, ctx->admin.subscribe.topic))) {
		int rc = janus_mqtt_client_subscribe(context, TRUE);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Can't subscribe to MQTT topic: %s, return code: %d\n", ctx->subscribe.topic, rc);
		}
	}
}

void janus_mqtt_client_subscribe_failure(void *context, MQTTAsync_failureData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT client has been failed subscribing to MQTT topic: %s, return code: %d. Reconnecting...\n", ctx->subscribe.topic, rc);

	/* Reconnect */
	{
		int rc = janus_mqtt_client_reconnect(context);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_FATAL, "Can't reconnect to MQTT broker, return code: %d\n", rc);
		}
	}
}

void janus_mqtt_client_admin_subscribe_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully subscribed to MQTT topic: %s\n", ctx->admin.subscribe.topic);
}

void janus_mqtt_client_admin_subscribe_failure(void *context, MQTTAsync_failureData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT client has been failed subscribing to MQTT topic: %s, return code: %d. Reconnecting...\n", ctx->admin.subscribe.topic, rc);

	/* Reconnect */
	{
		int rc = janus_mqtt_client_reconnect(context);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_FATAL, "Can't reconnect to MQTT broker, return code: %d\n", rc);
		}
	}
}

int janus_mqtt_client_publish_message(janus_mqtt_context *ctx, char *payload, gboolean admin) {
	MQTTAsync_message msg = MQTTAsync_message_initializer;
	msg.payload = payload;
	msg.payloadlen = strlen(payload);
	msg.qos = ctx->publish.qos;
	msg.retained = 0;

	MQTTAsync_responseOptions options;
	options.context = ctx;
	if(admin) {
		options.onSuccess = janus_mqtt_client_publish_admin_success;
		options.onFailure = janus_mqtt_client_publish_admin_failure;
		return MQTTAsync_sendMessage(ctx->client, ctx->admin.publish.topic, &msg, &options);
	}
	else {
		options.onSuccess = janus_mqtt_client_publish_janus_success;
		options.onFailure = janus_mqtt_client_publish_janus_failure;
		return MQTTAsync_sendMessage(ctx->client, ctx->publish.topic, &msg, &options);
	}
}

void janus_mqtt_client_publish_janus_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_HUGE, "MQTT client has been successfully published to MQTT topic: %s\n", ctx->publish.topic);
}

void janus_mqtt_client_publish_janus_failure(void *context, MQTTAsync_failureData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT client has been failed publishing to MQTT topic: %s, return code: %d\n", ctx->publish.topic, rc);
}

void janus_mqtt_client_publish_admin_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_HUGE, "MQTT client has been successfully published to MQTT topic: %s\n", ctx->admin.publish.topic);
}

void janus_mqtt_client_publish_admin_failure(void *context, MQTTAsync_failureData *response) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT client has been failed publishing to MQTT topic: %s, return code: %d\n", ctx->admin.publish.topic, rc);
}

void janus_mqtt_client_destroy_context(janus_mqtt_context **ptr) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)*ptr;
	if(ctx) {
		MQTTAsync_destroy(&ctx->client);
		g_free(ctx->subscribe.topic);
		g_free(ctx->publish.topic);
		g_free(ctx->admin.subscribe.topic);
		g_free(ctx->admin.publish.topic);
		g_free(ctx);
		*ptr = NULL;
	}

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_MQTT_NAME);
}
