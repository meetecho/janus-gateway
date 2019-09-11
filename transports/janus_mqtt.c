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
int janus_mqtt_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
void janus_mqtt_session_created(janus_transport_session *transport, guint64 session_id);
void janus_mqtt_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
void janus_mqtt_session_claimed(janus_transport_session *transport, guint64 session_id);

#define JANUS_MQTT_VERSION_3_1          "3.1"
#define JANUS_MQTT_VERSION_3_1_1        "3.1.1"
#define JANUS_MQTT_VERSION_5            "5"
#define JANUS_MQTT_VERSION_DEFAULT      JANUS_MQTT_VERSION_3_1_1
#define JANUS_MQTT_DEFAULT_STATUS_TOPIC	"status"
#define JANUS_MQTT_DEFAULT_STATUS_QOS   1

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
		.session_claimed = janus_mqtt_session_claimed,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_MQTT_NAME);
	return &janus_mqtt_transport_;
}

/* API flags */
static gboolean janus_mqtt_api_enabled_ = FALSE;
static gboolean janus_mqtt_admin_api_enabled_ = FALSE;

/* Event handlers */
static gboolean notify_events = TRUE;

/* JSON serialization options */
static size_t json_format_ = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* MQTT client context */
typedef struct janus_mqtt_context {
	janus_transport_callbacks *gateway;
	MQTTAsync client;
	struct {
		int mqtt_version;
		int keep_alive_interval;
		int cleansession;
		char *username;
		char *password;
	} connect;
	struct {
		int timeout;
	} disconnect;
	/* If we loose connection, the will is our last publish */
	struct {
		gboolean enabled;
		char *connect_message;
		char *disconnect_message;
		char *topic;
		int qos;
		gboolean retain;
	} status;
	struct {
		char *topic;
		int qos;
	} subscribe;
	struct {
		char *topic;
		int qos;
		gboolean retain;
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
	/* SSL config, if needed */
	gboolean ssl_enabled;
	char *cacert_file;
	char *cert_file;
	char *key_file;
	gboolean verify_peer;
} janus_mqtt_context;

/* Transport client methods */
void janus_mqtt_client_connected(void *context, char *cause);
void janus_mqtt_client_disconnected(void *context, MQTTProperties *properties, enum MQTTReasonCodes reasonCode);
void janus_mqtt_client_connection_lost(void *context, char *cause);
int janus_mqtt_client_message_arrived(void *context, char *topicName, int topicLen, MQTTAsync_message *message);
int janus_mqtt_client_connect(janus_mqtt_context *ctx);
int janus_mqtt_client_reconnect(janus_mqtt_context *ctx);
int janus_mqtt_client_disconnect(janus_mqtt_context *ctx);
int janus_mqtt_client_subscribe(janus_mqtt_context *ctx, gboolean admin);
int janus_mqtt_client_publish_message(janus_mqtt_context *ctx, char *payload, gboolean admin);
int janus_mqtt_client_publish_status_message(janus_mqtt_context *ctx, char *payload);
void janus_mqtt_client_destroy_context(janus_mqtt_context **ctx);
/* MQTT v3.x interface callbacks */
void janus_mqtt_client_connect_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_reconnect_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_reconnect_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_disconnect_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_disconnect_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_subscribe_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_subscribe_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_admin_subscribe_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_admin_subscribe_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_publish_janus_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_publish_janus_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_publish_admin_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_publish_admin_failure(void *context, MQTTAsync_failureData *response);
void janus_mqtt_client_publish_status_success(void *context, MQTTAsync_successData *response);
void janus_mqtt_client_publish_status_failure(void *context, MQTTAsync_failureData *response);
int janus_mqtt_client_get_response_code(MQTTAsync_failureData *response);
#ifdef MQTTVERSION_5
/* MQTT v5 interface callbacks */
void janus_mqtt_client_connect_failure5(void *context, MQTTAsync_failureData5 *response);
void janus_mqtt_client_reconnect_success5(void *context, MQTTAsync_successData5 *response);
void janus_mqtt_client_reconnect_failure5(void *context, MQTTAsync_failureData5 *response);
void janus_mqtt_client_disconnect_success5(void *context, MQTTAsync_successData5 *response);
void janus_mqtt_client_disconnect_failure5(void *context, MQTTAsync_failureData5 *response);
void janus_mqtt_client_subscribe_success5(void *context, MQTTAsync_successData5 *response);
void janus_mqtt_client_subscribe_failure5(void *context, MQTTAsync_failureData5 *response);
void janus_mqtt_client_admin_subscribe_success5(void *context, MQTTAsync_successData5 *response);
void janus_mqtt_client_admin_subscribe_failure5(void *context, MQTTAsync_failureData5 *response);
void janus_mqtt_client_publish_janus_success5(void *context, MQTTAsync_successData5 *response);
void janus_mqtt_client_publish_janus_failure5(void *context, MQTTAsync_failureData5 *response);
void janus_mqtt_client_publish_admin_success5(void *context, MQTTAsync_successData5 *response);
void janus_mqtt_client_publish_admin_failure5(void *context, MQTTAsync_failureData5 *response);
void janus_mqtt_client_publish_status_success5(void *context, MQTTAsync_successData5 *response);
void janus_mqtt_client_publish_status_failure5(void *context, MQTTAsync_failureData5 *response);
int janus_mqtt_client_get_response_code5(MQTTAsync_failureData5 *response);
#endif
/* MQTT version independent callback implementations */
void janus_mqtt_client_reconnect_success_impl(void *context);
void janus_mqtt_client_connect_failure_impl(void *context, int rc);
void janus_mqtt_client_reconnect_failure_impl(void *context, int rc);
void janus_mqtt_client_disconnect_success_impl(void *context);
void janus_mqtt_client_disconnect_failure_impl(void *context, int rc);
void janus_mqtt_client_subscribe_success_impl(void *context);
void janus_mqtt_client_subscribe_failure_impl(void *context, int rc);
void janus_mqtt_client_admin_subscribe_success_impl(void *context);
void janus_mqtt_client_admin_subscribe_failure_impl(void *context, int rc);
void janus_mqtt_client_publish_janus_success_impl(void *context);
void janus_mqtt_client_publish_janus_failure_impl(void *context, int rc);
void janus_mqtt_client_publish_admin_success_impl(void *context);
void janus_mqtt_client_publish_admin_failure_impl(void *context, int rc);
void janus_mqtt_client_publish_status_success_impl(void *context);
void janus_mqtt_client_publish_status_failure_impl(void *context, int rc);

/* We only handle a single client */
static janus_mqtt_context *context_ = NULL;
static janus_transport_session *mqtt_session = NULL;

int janus_mqtt_init(janus_transport_callbacks *callback, const char *config_path) {
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Initializing context */
	janus_mqtt_context *ctx = g_malloc0(sizeof(struct janus_mqtt_context));
	ctx->gateway = callback;
	context_ = ctx;

	/* Set default values */
	/* Strings are set to default values later */
	ctx->status.enabled = FALSE;
	ctx->status.qos = JANUS_MQTT_DEFAULT_STATUS_QOS;
	ctx->status.retain = FALSE;

	/* Prepare the transport session (again, just one) */
	mqtt_session = janus_transport_session_create(context_, NULL);

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_MQTT_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_MQTT_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_MQTT_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		janus_config_print(config);
	}
	janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
	janus_config_category *config_admin = janus_config_get_create(config, NULL, janus_config_type_category, "admin");
	janus_config_category *config_status = janus_config_get_create(config, NULL, janus_config_type_category, "status");

	/* Handle configuration */
	janus_config_item *url_item = janus_config_get(config, config_general, janus_config_type_item, "url");
	const char *url = g_strdup((url_item && url_item->value) ? url_item->value : "tcp://localhost:1883");

	janus_config_item *client_id_item = janus_config_get(config, config_general, janus_config_type_item, "client_id");
	const char *client_id = g_strdup((client_id_item && client_id_item->value) ? client_id_item->value : "guest");

	janus_config_item *username_item = janus_config_get(config, config_general, janus_config_type_item, "username");
	ctx->connect.username = g_strdup((username_item && username_item->value) ? username_item->value : "guest");

	janus_config_item *password_item = janus_config_get(config, config_general, janus_config_type_item, "password");
	ctx->connect.password = g_strdup((password_item && password_item->value) ? password_item->value : "guest");

	janus_config_item *json_item = janus_config_get(config, config_general, janus_config_type_item, "json");
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

	/* Check if we need to send events to handlers */
	janus_config_item *events_item = janus_config_get(config, config_general, janus_config_type_item, "events");
	if(events_item && events_item->value)
		notify_events = janus_is_true(events_item->value);
	if(!notify_events && callback->events_is_enabled()) {
		JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_MQTT_NAME);
	}

	/* Check if we need to enable SSL support */
	janus_config_item *ssl_item = janus_config_get(config, config_general, janus_config_type_item, "ssl_enabled");
	if(ssl_item == NULL) {
		/* Try legacy property */
		ssl_item = janus_config_get(config, config_general, janus_config_type_item, "ssl_enable");
		if (ssl_item && ssl_item->value) {
			JANUS_LOG(LOG_WARN, "Found deprecated 'ssl_enable' property, please update it to 'ssl_enabled' instead\n");
		}
	}
	if(ssl_item && ssl_item->value && janus_is_true(ssl_item->value)) {
		if(strstr(url, "ssl://") != url)
			JANUS_LOG(LOG_WARN, "SSL enabled, but MQTT url doesn't start with ssl://...\n");

		ctx->ssl_enabled = TRUE;

		janus_config_item *cacertfile = janus_config_get(config, config_general, janus_config_type_item, "cacertfile");
		if(!cacertfile || !cacertfile->value) {
			JANUS_LOG(LOG_FATAL, "Missing CA certificate for MQTT integration...\n");
			goto error;
		}
		ctx->cacert_file = g_strdup(cacertfile->value);

		janus_config_item *certfile = janus_config_get(config, config_general, janus_config_type_item, "certfile");
		ctx->cert_file = (certfile && certfile->value) ? g_strdup(certfile->value) : NULL;

		janus_config_item *keyfile = janus_config_get(config, config_general, janus_config_type_item, "keyfile");
		ctx->key_file = (keyfile && keyfile->value) ? g_strdup(keyfile->value) : NULL;

		if(ctx->cert_file && !ctx->key_file) {
			JANUS_LOG(LOG_FATAL, "Certificate is set but key isn't for MQTT integration...\n");
			goto error;
		}
		if(!ctx->cert_file && ctx->key_file) {
			JANUS_LOG(LOG_FATAL, "Key is set but certificate isn't for MQTT integration...\n");
			goto error;
		}

		janus_config_item *verify = janus_config_get(config, config_general, janus_config_type_item, "verify_peer");
		ctx->verify_peer = (verify && verify->value && janus_is_true(verify->value)) ? TRUE : FALSE;
	} else {
		JANUS_LOG(LOG_INFO, "MQTT SSL support disabled\n");
		if(strstr(url, "ssl://") == url)
			JANUS_LOG(LOG_WARN, "SSL disabled, but MQTT url starts with ssl:// instead of tcp://...\n");
	}

	/* Connect configuration */
	janus_config_item *mqtt_version = janus_config_get(config, config_general, janus_config_type_item, "mqtt_version");
	const char *mqtt_version_str = (mqtt_version && mqtt_version->value) ? mqtt_version->value : JANUS_MQTT_VERSION_DEFAULT;

	if(strcmp(mqtt_version_str, JANUS_MQTT_VERSION_3_1) == 0) {
		ctx->connect.mqtt_version = MQTTVERSION_3_1;
	} else if(strcmp(mqtt_version_str, JANUS_MQTT_VERSION_3_1_1) == 0) {
		ctx->connect.mqtt_version = MQTTVERSION_3_1_1;
	} else if(strcmp(mqtt_version_str, JANUS_MQTT_VERSION_5) == 0) {
#ifdef MQTTVERSION_5
		ctx->connect.mqtt_version = MQTTVERSION_5;
#else
		JANUS_LOG(LOG_FATAL, "Using MQTT v5 requires compilation with Paho >= 1.3.0\n");
		goto error;
#endif
	} else {
		JANUS_LOG(LOG_FATAL, "Unknown MQTT version\n");
		goto error;
	}

	janus_config_item *keep_alive_interval_item = janus_config_get(config, config_general, janus_config_type_item, "keep_alive_interval");
	ctx->connect.keep_alive_interval = (keep_alive_interval_item && keep_alive_interval_item->value) ? atoi(keep_alive_interval_item->value) : 20;

	janus_config_item *cleansession_item = janus_config_get(config, config_general, janus_config_type_item, "cleansession");
	ctx->connect.cleansession = (cleansession_item && cleansession_item->value) ? atoi(cleansession_item->value) : 0;

	janus_config_item *enabled_item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
	if(enabled_item == NULL) {
		/* Try legacy property */
		enabled_item = janus_config_get(config, config_general, janus_config_type_item, "enable");
		if (enabled_item && enabled_item->value) {
			JANUS_LOG(LOG_WARN, "Found deprecated 'enable' property, please update it to 'enabled' instead\n");
		}
	}
	if(enabled_item && enabled_item->value && janus_is_true(enabled_item->value)) {
		janus_mqtt_api_enabled_ = TRUE;

		/* Subscribe configuration */
		{
			janus_config_item *topic_item = janus_config_get(config, config_general, janus_config_type_item, "subscribe_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for incoming messages for MQTT integration...\n");
				goto error;
			}
			ctx->subscribe.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get(config, config_general, janus_config_type_item, "subscribe_qos");
			ctx->subscribe.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}

		/* Publish configuration */
		{
			janus_config_item *topic_item = janus_config_get(config, config_general, janus_config_type_item, "publish_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for outgoing messages for MQTT integration...\n");
				goto error;
			}
			ctx->publish.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get(config, config_general, janus_config_type_item, "publish_qos");
			ctx->publish.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}
	} else {
		janus_mqtt_api_enabled_ = FALSE;
		ctx->subscribe.topic = NULL;
		ctx->publish.topic = NULL;
	}

	/* Disconnect configuration */
	janus_config_item *disconnect_timeout_item = janus_config_get(config, config_general, janus_config_type_item, "disconnect_timeout");
	ctx->disconnect.timeout = (disconnect_timeout_item && disconnect_timeout_item->value) ? atoi(disconnect_timeout_item->value) : 100;

	/* Admin configuration */
	janus_config_item *admin_enabled_item = janus_config_get(config, config_admin, janus_config_type_item, "admin_enabled");
	if(admin_enabled_item == NULL) {
		/* Try legacy property */
		admin_enabled_item = janus_config_get(config, config_general, janus_config_type_item, "admin_enable");
		if (admin_enabled_item && admin_enabled_item->value) {
			JANUS_LOG(LOG_WARN, "Found deprecated 'admin_enable' property, please update it to 'admin_enabled' instead\n");
		}
	}
	if(admin_enabled_item && admin_enabled_item->value && janus_is_true(admin_enabled_item->value)) {
		janus_mqtt_admin_api_enabled_ = TRUE;

		/* Admin subscribe configuration */
		{
			janus_config_item *topic_item = janus_config_get(config, config_admin, janus_config_type_item, "subscribe_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for incoming admin messages for MQTT integration...\n");
				goto error;
			}
			ctx->admin.subscribe.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get(config, config_admin, janus_config_type_item, "subscribe_qos");
			ctx->admin.subscribe.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}

		/* Admin publish configuration */
		{
			janus_config_item *topic_item = janus_config_get(config, config_admin, janus_config_type_item, "publish_topic");
			if(!topic_item || !topic_item->value) {
				JANUS_LOG(LOG_FATAL, "Missing topic for outgoing admin messages for MQTT integration...\n");
				goto error;
			}
			ctx->admin.publish.topic = g_strdup(topic_item->value);

			janus_config_item *qos_item = janus_config_get(config, config_admin, janus_config_type_item, "publish_qos");
			ctx->admin.publish.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;
		}
	} else {
		janus_mqtt_admin_api_enabled_ = FALSE;
		ctx->admin.subscribe.topic = NULL;
		ctx->admin.publish.topic = NULL;
	}

	/* Status messages configuration */
	janus_config_item *status_enabled_item = janus_config_get(config, config_status, janus_config_type_item, "enabled");
	if(status_enabled_item && status_enabled_item->value && janus_is_true(status_enabled_item->value)) {
		ctx->status.enabled = TRUE;

		janus_config_item *status_connect_message_item = janus_config_get(config, config_status, janus_config_type_item, "connect_message");
		if(status_connect_message_item && status_connect_message_item->value) {
			ctx->status.connect_message = g_strdup(status_connect_message_item->value);
		}

		janus_config_item *status_disconnect_message_item = janus_config_get(config, config_status, janus_config_type_item, "disconnect_message");
		if(status_disconnect_message_item && status_disconnect_message_item->value) {
			ctx->status.disconnect_message = g_strdup(status_disconnect_message_item->value);
		}

		janus_config_item *status_topic_item = janus_config_get(config, config_status, janus_config_type_item, "topic");
		if(status_topic_item && status_topic_item->value) {
			ctx->status.topic = g_strdup(status_topic_item->value);
		} else {
			ctx->status.topic = g_strdup(JANUS_MQTT_DEFAULT_STATUS_TOPIC);
		}

		janus_config_item *status_qos_item = janus_config_get(config, config_status, janus_config_type_item, "qos");
		if(status_qos_item && status_qos_item->value) {
			ctx->status.qos = atoi(status_qos_item->value);
		}

		janus_config_item *status_retain_item = janus_config_get(config, config_status, janus_config_type_item, "retain");
		if(status_retain_item && status_retain_item->value && janus_is_true(status_retain_item->value)) {
			ctx->status.retain = TRUE;
		}
	}

	if(!janus_mqtt_api_enabled_ && !janus_mqtt_admin_api_enabled_) {
		JANUS_LOG(LOG_WARN, "MQTT support disabled for both Janus and Admin API, giving up\n");
		goto error;
	}

	/* Creating a client */
	MQTTAsync_createOptions create_options = MQTTAsync_createOptions_initializer;

#ifdef MQTTVERSION_5
	if (ctx->connect.mqtt_version == MQTTVERSION_5) {
		create_options.MQTTVersion = MQTTVERSION_5;
	}
#endif

	if(MQTTAsync_createWithOptions(
			&ctx->client,
			url,
			client_id,
			MQTTCLIENT_PERSISTENCE_NONE,
			NULL,
			&create_options) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker: error creating client...\n");
		goto error;
	}

	if(MQTTAsync_setConnected(ctx->client, ctx, janus_mqtt_client_connected) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker: error setting up connected callback...\n");
		goto error;
	}

	if(MQTTAsync_setDisconnected(ctx->client, ctx, janus_mqtt_client_disconnected) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker: error setting up disconnected callback...\n");
		goto error;
	}

	if(MQTTAsync_setConnectionLostCallback(ctx->client, ctx, janus_mqtt_client_connection_lost) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker: error setting up connection lost callback...\n");
		goto error;
	}

	if(MQTTAsync_setMessageArrivedCallback(ctx->client, ctx, janus_mqtt_client_message_arrived) != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker: error setting up message arrived callback...\n");
		goto error;
	}

	/* Connecting to the broker */
	int rc = janus_mqtt_client_connect(ctx);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d\n", rc);
		goto error;
	}

	g_free((char *)url);
	g_free((char *)client_id);
	janus_config_destroy(config);
	return 0;

error:
	/* If we got here, something went wrong */
	janus_transport_session_destroy(mqtt_session);
	janus_mqtt_client_destroy_context(&ctx);
	g_free((char *)url);
	g_free((char *)client_id);
	janus_config_destroy(config);

	return -1;
}

void janus_mqtt_destroy(void) {
	JANUS_LOG(LOG_INFO, "Disconnecting MQTT client...\n");

	janus_transport_session_destroy(mqtt_session);
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

int janus_mqtt_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL || transport == NULL) {
		return -1;
	}
	/* Not really needed as we always only have a single context, but that's fine */
	janus_mqtt_context *ctx = (janus_mqtt_context *)transport->transport_p;
	if(ctx == NULL) {
		json_decref(message);
		return -1;
	}

	char *payload = json_dumps(message, json_format_);
	json_decref(message);
	JANUS_LOG(LOG_HUGE, "Sending %s API message via MQTT: %s\n", admin ? "admin" : "Janus", payload);

	int rc = janus_mqtt_client_publish_message(ctx, payload, admin);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_ERR, "Can't publish to MQTT topic: %s, return code: %d\n", admin ? ctx->admin.publish.topic : ctx->publish.topic, rc);
	}
	free(payload);

	return 0;
}

void janus_mqtt_session_created(janus_transport_session *transport, guint64 session_id) {
	/* We don't care */
}

void janus_mqtt_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed) {
	/* We don't care, not even if it's a timeout (should we?), our client is always up */
}

void janus_mqtt_session_claimed(janus_transport_session *transport, guint64 session_id) {
	/* We don't care about this. We should start receiving messages from the core about this session: no action necessary */
	/* FIXME Is the above statement accurate? Should we care? Unlike the HTTP transport, there is no hashtable to update */
}

void janus_mqtt_client_connected(void *context, char *cause) {
	JANUS_LOG(LOG_INFO, "Connected to MQTT broker: %s\n", cause);
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;

	/* Subscribe to one (janus or admin) topic at the time */
	if(janus_mqtt_api_enabled_) {
		JANUS_LOG(LOG_INFO, "Subscribing to MQTT topic %s\n", ctx->subscribe.topic);
		int rc = janus_mqtt_client_subscribe(context, FALSE);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Can't subscribe to MQTT topic: %s, return code: %d\n", ctx->subscribe.topic, rc);
		}
	} else if(janus_mqtt_admin_api_enabled_) {
		JANUS_LOG(LOG_INFO, "Subscribing to MQTT admin topic %s\n", ctx->admin.subscribe.topic);
		int rc = janus_mqtt_client_subscribe(context, TRUE);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Can't subscribe to MQTT admin topic: %s, return code: %d\n", ctx->admin.subscribe.topic, rc);
		}
	}

	/* Notify handlers about this new transport */
	if(notify_events && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("connected"));
		ctx->gateway->notify_event(&janus_mqtt_transport_, mqtt_session, info);
	}

	/* Send online status message */
	if (ctx->status.enabled && ctx->status.connect_message != NULL) {
		int rc = janus_mqtt_client_publish_status_message(ctx, ctx->status.connect_message);
		if (rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Failed to publish connect status MQTT message, topic: %s, message: %s, return code: %d\n", ctx->status.topic, ctx->status.connect_message, rc);
		}
	}
}

void janus_mqtt_client_disconnected(void *context, MQTTProperties *properties, enum MQTTReasonCodes reasonCode) {
	const char *reasonCodeStr = MQTTReasonCode_toString(reasonCode);
	JANUS_LOG(LOG_INFO, "Disconnected from MQTT broker: %s\n", reasonCodeStr);

	/* Notify handlers about this transport being gone */
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	if(notify_events && ctx && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("disconnected"));
		ctx->gateway->notify_event(&janus_mqtt_transport_, mqtt_session, info);
	}
}

void janus_mqtt_client_connection_lost(void *context, char *cause) {
	JANUS_LOG(LOG_INFO, "MQTT connection lost cause of %s. Reconnecting...\n", cause);
	/* Automatic reconnect */

	/* Notify handlers about this transport being gone */
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	if(notify_events && ctx && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("reconnecting"));
		ctx->gateway->notify_event(&janus_mqtt_transport_, mqtt_session, info);
	}
}

int janus_mqtt_client_message_arrived(void *context, char *topicName, int topicLen, MQTTAsync_message *message) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	gchar *topic = g_strndup(topicName, topicLen);
	const gboolean janus = janus_mqtt_api_enabled_ && !strcasecmp(topic, ctx->subscribe.topic);
	const gboolean admin = janus_mqtt_admin_api_enabled_ && !strcasecmp(topic, ctx->admin.subscribe.topic);
	g_free(topic);

	if((janus || admin) && message->payloadlen) {
		JANUS_LOG(LOG_HUGE, "Receiving %s API message over MQTT: %s\n", admin ? "admin" : "Janus", (char *)message->payload);

		json_error_t error;
		json_t *root = json_loadb(message->payload, message->payloadlen, 0, &error);
		ctx->gateway->incoming_request(&janus_mqtt_transport_, mqtt_session, NULL, admin, root, &error);
	}

	MQTTAsync_freeMessage(&message);
	MQTTAsync_free(topicName);
	return TRUE;
}

int janus_mqtt_client_connect(janus_mqtt_context *ctx) {
	MQTTAsync_connectOptions options = MQTTAsync_connectOptions_initializer;

#ifdef MQTTVERSION_5
	if(ctx->connect.mqtt_version == MQTTVERSION_5) {
		MQTTAsync_connectOptions options5 = MQTTAsync_connectOptions_initializer5;
		options = options5;
		options.cleanstart = ctx->connect.cleansession;
		options.onFailure5 = janus_mqtt_client_connect_failure5;
	} else {
		options.cleansession = ctx->connect.cleansession;
		options.onFailure = janus_mqtt_client_connect_failure;
	}
#else
	options.cleansession = ctx->connect.cleansession;
	options.onSuccess = janus_mqtt_client_connect_success;
	options.onFailure = janus_mqtt_client_connect_failure;
#endif

	options.MQTTVersion = ctx->connect.mqtt_version;
	options.username = ctx->connect.username;
	options.password = ctx->connect.password;
	options.automaticReconnect = TRUE;
	options.keepAliveInterval = ctx->connect.keep_alive_interval;

	MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
	if(ctx->ssl_enabled) {
		ssl_opts.trustStore = ctx->cacert_file;
		ssl_opts.keyStore = ctx->cert_file;
		ssl_opts.privateKey = ctx->key_file;
		ssl_opts.enableServerCertAuth = ctx->verify_peer;
		options.ssl = &ssl_opts;
	}

	MQTTAsync_willOptions willOptions = MQTTAsync_willOptions_initializer;
	if(ctx->status.enabled && ctx->status.disconnect_message != NULL) {
		willOptions.topicName = ctx->status.topic;
		willOptions.message = ctx->status.disconnect_message;
		willOptions.retained = ctx->status.retain;
		willOptions.qos = ctx->status.qos;
		options.will = &willOptions;
	}

	options.context = ctx;
	return MQTTAsync_connect(ctx->client, &options);
}

void janus_mqtt_client_connect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_connect_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_connect_failure5(void *context, MQTTAsync_failureData5 *response) {
		int rc = janus_mqtt_client_get_response_code5(response);
		janus_mqtt_client_connect_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_connect_failure_impl(void *context, int rc) {
	JANUS_LOG(LOG_ERR, "MQTT client has failed connecting to the broker, return code: %d. Reconnecting...\n", rc);
	/* Automatic reconnect */

	/* Notify handlers about this transport failure */
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	if(notify_events && ctx && ctx->gateway && ctx->gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("failed"));
		json_object_set_new(info, "code", json_integer(rc));
		ctx->gateway->notify_event(&janus_mqtt_transport_, mqtt_session, info);
	}
}

int janus_mqtt_client_reconnect(janus_mqtt_context *ctx) {
	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;

#ifdef MQTTVERSION_5
	if(ctx->connect.mqtt_version == MQTTVERSION_5) {
		options.onSuccess5 = janus_mqtt_client_reconnect_success5;
		options.onFailure5 = janus_mqtt_client_reconnect_failure5;
	} else {
		options.onSuccess = janus_mqtt_client_reconnect_success;
		options.onFailure = janus_mqtt_client_reconnect_failure;
	}
#else
	options.onSuccess = janus_mqtt_client_reconnect_success;
	options.onFailure = janus_mqtt_client_reconnect_failure;
#endif

	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;
	return MQTTAsync_disconnect(ctx->client, &options);
}

void janus_mqtt_client_reconnect_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_client_reconnect_success_impl(context);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_reconnect_success5(void *context, MQTTAsync_successData5 *response) {
	janus_mqtt_client_reconnect_success_impl(context);
}
#endif

void janus_mqtt_client_reconnect_success_impl(void *context) {
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully disconnected. Reconnecting...\n");

	int rc = janus_mqtt_client_connect(context);
	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d\n", rc);
	}
}

void janus_mqtt_client_reconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_reconnect_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_reconnect_failure5(void *context, MQTTAsync_failureData5 *response) {
	int rc = janus_mqtt_client_get_response_code5(response);
	janus_mqtt_client_reconnect_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_reconnect_failure_impl(void *context, int rc) {
	JANUS_LOG(LOG_ERR, "MQTT client has failed reconnecting from MQTT broker, return code: %d\n", rc);
}

int janus_mqtt_client_disconnect(janus_mqtt_context *ctx) {
	if (ctx->status.enabled && ctx->status.disconnect_message != NULL) {
		int rc = janus_mqtt_client_publish_status_message(ctx, ctx->status.disconnect_message);
		if (rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_ERR, "Failed to publish disconnect status MQTT message, topic: %s, message: %s, return code: %d\n", ctx->status.topic, ctx->status.disconnect_message, rc);
		}
	}

	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;

#ifdef MQTTVERSION_5
	if(ctx->connect.mqtt_version == MQTTVERSION_5) {
		options.onSuccess5 = janus_mqtt_client_disconnect_success5;
		options.onFailure5 = janus_mqtt_client_disconnect_failure5;
	} else {
		options.onSuccess = janus_mqtt_client_disconnect_success;
		options.onFailure = janus_mqtt_client_disconnect_failure;
	}
#else
	options.onSuccess = janus_mqtt_client_disconnect_success;
	options.onFailure = janus_mqtt_client_disconnect_failure;
#endif

	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;
	return MQTTAsync_disconnect(ctx->client, &options);
}

void janus_mqtt_client_disconnect_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_client_disconnect_success_impl(context);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_disconnect_success5(void *context, MQTTAsync_successData5 *response) {
	janus_mqtt_client_disconnect_success_impl(context);
}
#endif

void janus_mqtt_client_disconnect_success_impl(void *context) {
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully disconnected.\n");
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	janus_mqtt_client_destroy_context(&ctx);
}

void janus_mqtt_client_disconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_disconnect_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_disconnect_failure5(void *context, MQTTAsync_failureData5 *response) {
	int rc = janus_mqtt_client_get_response_code5(response);
	janus_mqtt_client_disconnect_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_disconnect_failure_impl(void *context, int rc) {
	JANUS_LOG(LOG_ERR, "Can't disconnect from MQTT broker, return code: %d\n", rc);

	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	janus_mqtt_client_destroy_context(&ctx);
}

int janus_mqtt_client_subscribe(janus_mqtt_context *ctx, gboolean admin) {
	MQTTAsync_responseOptions options = MQTTAsync_responseOptions_initializer;
	options.context = ctx;
	if(admin) {
#ifdef MQTTVERSION_5
		if(ctx->connect.mqtt_version == MQTTVERSION_5) {
			options.onSuccess5 = janus_mqtt_client_admin_subscribe_success5;
			options.onFailure5 = janus_mqtt_client_admin_subscribe_failure5;
		} else {
			options.onSuccess = janus_mqtt_client_admin_subscribe_success;
			options.onFailure = janus_mqtt_client_admin_subscribe_failure;
		}
#else
		options.onSuccess = janus_mqtt_client_admin_subscribe_success;
		options.onFailure = janus_mqtt_client_admin_subscribe_failure;
#endif
		return MQTTAsync_subscribe(ctx->client, ctx->admin.subscribe.topic, ctx->admin.subscribe.qos, &options);
	} else {
#ifdef MQTTVERSION_5
		if(ctx->connect.mqtt_version == MQTTVERSION_5) {
			options.onSuccess5 = janus_mqtt_client_subscribe_success5;
			options.onFailure5 = janus_mqtt_client_subscribe_failure5;
		} else {
			options.onSuccess = janus_mqtt_client_subscribe_success;
			options.onFailure = janus_mqtt_client_subscribe_failure;
		}
#else
		options.onSuccess = janus_mqtt_client_subscribe_success;
		options.onFailure = janus_mqtt_client_subscribe_failure;
#endif
		return MQTTAsync_subscribe(ctx->client, ctx->subscribe.topic, ctx->subscribe.qos, &options);
	}
}

void janus_mqtt_client_subscribe_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_client_subscribe_success_impl(context);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_subscribe_success5(void *context, MQTTAsync_successData5 *response) {
	janus_mqtt_client_subscribe_success_impl(context);
}
#endif

void janus_mqtt_client_subscribe_success_impl(void *context) {
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
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_subscribe_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_subscribe_failure5(void *context, MQTTAsync_failureData5 *response) {
	int rc = janus_mqtt_client_get_response_code5(response);
	janus_mqtt_client_subscribe_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_subscribe_failure_impl(void *context, int rc) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_ERR, "MQTT client has failed subscribing to MQTT topic: %s, return code: %d. Reconnecting...\n", ctx->subscribe.topic, rc);

	/* Reconnect */
	{
		int rc = janus_mqtt_client_reconnect(context);
		if(rc != MQTTASYNC_SUCCESS) {
			JANUS_LOG(LOG_FATAL, "Can't reconnect to MQTT broker, return code: %d\n", rc);
		}
	}
}

void janus_mqtt_client_admin_subscribe_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_client_admin_subscribe_success_impl(context);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_admin_subscribe_success5(void *context, MQTTAsync_successData5 *response) {
	janus_mqtt_client_admin_subscribe_success_impl(context);
}
#endif

void janus_mqtt_client_admin_subscribe_success_impl(void *context) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_INFO, "MQTT client has been successfully subscribed to MQTT topic: %s\n", ctx->admin.subscribe.topic);
}

void janus_mqtt_client_admin_subscribe_failure(void *context, MQTTAsync_failureData *response) {
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_admin_subscribe_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_admin_subscribe_failure5(void *context, MQTTAsync_failureData5 *response) {
	int rc = janus_mqtt_client_get_response_code5(response);
	janus_mqtt_client_admin_subscribe_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_admin_subscribe_failure_impl(void *context, int rc) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_ERR, "MQTT client has failed subscribing to MQTT topic: %s, return code: %d. Reconnecting...\n", ctx->admin.subscribe.topic, rc);

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
	msg.retained = FALSE;

	MQTTAsync_responseOptions options = MQTTAsync_responseOptions_initializer;
	options.context = ctx;

	if(admin) {
#ifdef MQTTVERSION_5
		if(ctx->connect.mqtt_version == MQTTVERSION_5) {
			options.onSuccess5 = janus_mqtt_client_publish_admin_success5;
			options.onFailure5 = janus_mqtt_client_publish_admin_failure5;
		} else {
			options.onSuccess = janus_mqtt_client_publish_admin_success;
			options.onFailure = janus_mqtt_client_publish_admin_failure;
		}
#else
		options.onSuccess = janus_mqtt_client_publish_admin_success;
		options.onFailure = janus_mqtt_client_publish_admin_failure;
#endif
		return MQTTAsync_sendMessage(ctx->client, ctx->admin.publish.topic, &msg, &options);
	} else {
#ifdef MQTTVERSION_5
		if(ctx->connect.mqtt_version == MQTTVERSION_5) {
			options.onSuccess5 = janus_mqtt_client_publish_janus_success5;
			options.onFailure5 = janus_mqtt_client_publish_janus_failure5;
		} else {
			options.onSuccess = janus_mqtt_client_publish_janus_success;
			options.onFailure = janus_mqtt_client_publish_janus_failure;
		}
#else
		options.onSuccess = janus_mqtt_client_publish_janus_success;
		options.onFailure = janus_mqtt_client_publish_janus_failure;
#endif
		return MQTTAsync_sendMessage(ctx->client, ctx->publish.topic, &msg, &options);
	}
}

void janus_mqtt_client_publish_janus_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_client_publish_janus_success_impl(context);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_publish_janus_success5(void *context, MQTTAsync_successData5 *response) {
	janus_mqtt_client_publish_janus_success_impl(context);
}
#endif

void janus_mqtt_client_publish_janus_success_impl(void *context) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_HUGE, "MQTT client has been successfully published to MQTT topic: %s\n", ctx->publish.topic);
}

void janus_mqtt_client_publish_janus_failure(void *context, MQTTAsync_failureData *response) {
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_publish_janus_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_publish_janus_failure5(void *context, MQTTAsync_failureData5 *response) {
	int rc = janus_mqtt_client_get_response_code5(response);
	janus_mqtt_client_publish_janus_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_publish_janus_failure_impl(void *context, int rc) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_ERR, "MQTT client has failed publishing to MQTT topic: %s, return code: %d\n", ctx->publish.topic, rc);
}

void janus_mqtt_client_publish_admin_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_client_publish_admin_success_impl(context);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_publish_admin_success5(void *context, MQTTAsync_successData5 *response) {
	janus_mqtt_client_publish_admin_success_impl(context);
}
#endif

void janus_mqtt_client_publish_admin_success_impl(void *context) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_HUGE, "MQTT client has been successfully published to MQTT topic: %s\n", ctx->admin.publish.topic);
}

void janus_mqtt_client_publish_admin_failure(void *context, MQTTAsync_failureData *response) {
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_publish_admin_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_publish_admin_failure5(void *context, MQTTAsync_failureData5 *response) {
	int rc = janus_mqtt_client_get_response_code5(response);
	janus_mqtt_client_publish_admin_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_publish_admin_failure_impl(void *context, int rc) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_ERR, "MQTT client has failed publishing to MQTT topic: %s, return code: %d\n", ctx->admin.publish.topic, rc);
}

int janus_mqtt_client_publish_status_message(janus_mqtt_context *ctx, char *payload) {
	MQTTAsync_message msg = MQTTAsync_message_initializer;
	msg.payload = payload;
	msg.payloadlen = strlen(payload);
	msg.qos = ctx->status.qos;
	msg.retained = ctx->status.retain;

	MQTTAsync_responseOptions options = MQTTAsync_responseOptions_initializer;
	options.context = ctx;

#ifdef MQTTVERSION_5
	if(ctx->connect.mqtt_version == MQTTVERSION_5) {
		options.onSuccess5 = janus_mqtt_client_publish_status_success5;
		options.onFailure5 = janus_mqtt_client_publish_status_failure5;
	} else {
		options.onSuccess = janus_mqtt_client_publish_status_success;
		options.onFailure = janus_mqtt_client_publish_status_failure;
	}
#else
	options.onSuccess = janus_mqtt_client_publish_status_success;
	options.onFailure = janus_mqtt_client_publish_status_failure;
#endif

	return MQTTAsync_sendMessage(ctx->client, ctx->status.topic, &msg, &options);
}

void janus_mqtt_client_publish_status_success(void *context, MQTTAsync_successData *response) {
	janus_mqtt_client_publish_status_success_impl(context);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_publish_status_success5(void *context, MQTTAsync_successData5 *response) {
	janus_mqtt_client_publish_status_success_impl(context);
}
#endif

void janus_mqtt_client_publish_status_success_impl(void *context) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_HUGE, "MQTT client has been successfully published to status MQTT topic: %s\n", ctx->status.topic);
}

void janus_mqtt_client_publish_status_failure(void *context, MQTTAsync_failureData *response) {
	int rc = janus_mqtt_client_get_response_code(response);
	janus_mqtt_client_publish_status_failure_impl(context, rc);
}

#ifdef MQTTVERSION_5
void janus_mqtt_client_publish_status_failure5(void *context, MQTTAsync_failureData5 *response) {
	int rc = janus_mqtt_client_get_response_code5(response);
	janus_mqtt_client_publish_status_failure_impl(context, rc);
}
#endif

void janus_mqtt_client_publish_status_failure_impl(void *context, int rc) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)context;
	JANUS_LOG(LOG_ERR, "MQTT client has failed publishing to status MQTT topic: %s, return code: %d\n", ctx->status.topic, rc);
}

void janus_mqtt_client_destroy_context(janus_mqtt_context **ptr) {
	janus_mqtt_context *ctx = (janus_mqtt_context *)*ptr;
	if(ctx) {
		MQTTAsync_destroy(&ctx->client);
		g_free(ctx->subscribe.topic);
		g_free(ctx->publish.topic);
		g_free(ctx->connect.username);
		g_free(ctx->connect.password);
		g_free(ctx->admin.subscribe.topic);
		g_free(ctx->admin.publish.topic);
		g_free(ctx);
		*ptr = NULL;
	}

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_MQTT_NAME);
}

int janus_mqtt_client_get_response_code(MQTTAsync_failureData *response) {
	return response ? response->code : 0;
}

#ifdef MQTTVERSION_5
int janus_mqtt_client_get_response_code5(MQTTAsync_failureData5 *response) {
	return response ? response->code : 0;
}
#endif
