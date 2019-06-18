/*! \file   janus_mqttevh.c
 * \author Olle E. Johansson <oej@edvina.net>
 * \copyright GNU General Public License v3
 * \brief  Janus MQTTEventHandler plugin
 * \details  This is an MQTT event handler plugin for Janus. It is a
 * refactoring of the original effort contributed by Olle E. Johansson
 * (see https://github.com/meetecho/janus-gateway/pull/1185), which was
 * based on the MQTT transport by Andrei Nesterov and the RabbitMQ event
 * plugin by Piter Konstantinov.
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <MQTTAsync.h>

#include "../debug.h"
#include "../config.h"
#include "../utils.h"
#include "../events.h"

/* Plugin information */
#define JANUS_MQTTEVH_VERSION				1
#define JANUS_MQTTEVH_VERSION_STRING		"0.1.0"
#define JANUS_MQTTEVH_DESCRIPTION			"An MQTT event handler plugin for Janus."
#define JANUS_MQTTEVH_NAME					"JANUS MQTTEventHandler plugin"
#define JANUS_MQTTEVH_AUTHOR				"Olle E. Johansson, Edvina AB"
#define JANUS_MQTTEVH_PACKAGE				"janus.eventhandler.mqttevh"

/* Plugin methods */
janus_eventhandler *create(void);
static int janus_mqttevh_init(const char *config_path);
static void janus_mqttevh_destroy(void);
static int janus_mqttevh_get_api_compatibility(void);
static int janus_mqttevh_get_version(void);
static const char *janus_mqttevh_get_version_string(void);
static const char *janus_mqttevh_get_description(void);
static const char *janus_mqttevh_get_name(void);
static const char *janus_mqttevh_get_author(void);
static const char *janus_mqttevh_get_package(void);
static void janus_mqttevh_incoming_event(json_t *event);
json_t *janus_mqttevh_handle_request(json_t *request);

static int janus_mqttevh_send_message(void *context, const char *topic, json_t *message);
static void *janus_mqttevh_handler(void *data);


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
		.handle_request = janus_mqttevh_handle_request,

		.events_mask = JANUS_EVENT_TYPE_NONE
	);

/* Fix an exit event */
static json_t exit_event;

/* Destruction of events */
static void janus_mqttevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* Queue of events to handle */
static GAsyncQueue *events = NULL;

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_MQTTEVH_NAME);
	return &janus_mqttevh;
};

/* API flags */
static gboolean janus_mqtt_evh_enabled = FALSE;
static GThread *handler_thread;
static volatile gint initialized = 0, stopping = 0;

/* JSON serialization options */
#define DEFAULT_ADDPLUGIN			1
#define	DEFAULT_ADDEVENT			1
#define	DEFAULT_KEEPALIVE			30
#define	DEFAULT_CLEANSESSION		0	/* Off */
#define DEFAULT_TIMEOUT				30
#define DEFAULT_DISCONNECT_TIMEOUT	100
#define DEFAULT_QOS					0
#define DEFAULT_RETAIN				0
#define DEFAULT_CONNECT_STATUS		"{\"event\": \"connected\", \"eventhandler\": \""JANUS_MQTTEVH_PACKAGE"\"}"
#define DEFAULT_DISCONNECT_STATUS	"{\"event\": \"disconnected\"}"
#define DEFAULT_WILL_RETAIN			1
#define DEFAULT_WILL_QOS			0
#define DEFAULT_BASETOPIC			"/janus/events"
#define DEFAULT_MQTTURL				"tcp://localhost:1883"
#define DEFAULT_JSON_FORMAT	JSON_INDENT(3) | JSON_PRESERVE_ORDER

#define DEFAULT_TLS_ENABLE			FALSE
#define DEFAULT_TLS_VERIFY_PEER		FALSE
#define DEFAULT_TLS_VERIFY_HOST		FALSE

static size_t json_format = DEFAULT_JSON_FORMAT;


/* Parameter validation (for tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter tweak_parameters[] = {
	{"events", JSON_STRING, 0}
};
/* Error codes (for the tweaking via Admin API */
#define JANUS_MQTTEVH_ERROR_INVALID_REQUEST		411
#define JANUS_MQTTEVH_ERROR_MISSING_ELEMENT		412
#define JANUS_MQTTEVH_ERROR_INVALID_ELEMENT		413
#define JANUS_MQTTEVH_ERROR_UNKNOWN_ERROR		499

/* Special topics postfix */
#define JANUS_MQTTEVH_STATUS_TOPIC "status"


/* MQTT client context */
typedef struct janus_mqttevh_context {
	/* THe Paho MQTT client data structure */
	MQTTAsync client;

	int addplugin;
	int addevent;

	/* Connection data - authentication and url */
	struct {
		int keep_alive_interval;
		int cleansession;
		char *client_id;
		char *username;
		char *password;
		char *url;
	} connect;

	struct {
		int timeout;
	} disconnect;

	/* Data for publishing events */
	struct {
		char *topic;
		char *connect_status;
		char *disconnect_status;
		int qos;
		int retain;
	} publish;

	/* If we loose connection, the will is our last publish */
	struct {
		gboolean enabled;
		char *topic;
		int qos;
		int retain;
	} will;

	/* TLS connection data */
	struct {
		gboolean enable;
		char *cacert_file;
		char *cert_file;
		char *key_file;
		gboolean verify_peer;
		gboolean verify_host;
	} tls;
} janus_mqttevh_context;

/* Event handler methods */
static void janus_mqttevh_client_connection_lost(void *context, char *cause);
static int janus_mqttevh_client_connect(janus_mqttevh_context *ctx);
static void janus_mqttevh_client_connect_success(void *context, MQTTAsync_successData *response);
static void janus_mqttevh_client_connect_failure(void *context, MQTTAsync_failureData *response);
static int janus_mqttevh_client_reconnect(janus_mqttevh_context *ctx);
static void janus_mqttevh_client_reconnect_success(void *context, MQTTAsync_successData *response);
static void janus_mqttevh_client_reconnect_failure(void *context, MQTTAsync_failureData *response);
static int janus_mqttevh_client_disconnect(janus_mqttevh_context *ctx);
static void janus_mqttevh_client_disconnect_success(void *context, MQTTAsync_successData *response);
static void janus_mqttevh_client_disconnect_failure(void *context, MQTTAsync_failureData *response);
static int janus_mqttevh_client_publish_message(janus_mqttevh_context *ctx, const char *topic, int retain, char *payload);
static void janus_mqttevh_client_publish_janus_success(void *context, MQTTAsync_successData *response);
static void janus_mqttevh_client_publish_janus_failure(void *context, MQTTAsync_failureData *response);
static void janus_mqttevh_client_destroy_context(janus_mqttevh_context **ctx);

/* We only handle a single connection */
static janus_mqttevh_context *context = NULL;


/* Janus API methods */
static int janus_mqttevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

static int janus_mqttevh_get_version(void) {
	return JANUS_MQTTEVH_VERSION;
}

static const char *janus_mqttevh_get_version_string(void) {
	return JANUS_MQTTEVH_VERSION_STRING;
}

static const char *janus_mqttevh_get_description(void) {
	return JANUS_MQTTEVH_DESCRIPTION;
}

static const char *janus_mqttevh_get_name(void) {
	return JANUS_MQTTEVH_NAME;
}

static const char *janus_mqttevh_get_author(void) {
	return JANUS_MQTTEVH_AUTHOR;
}

static const char *janus_mqttevh_get_package(void) {
	return JANUS_MQTTEVH_PACKAGE;
}

/* Send an JSON message to a MQTT topic */
static int janus_mqttevh_send_message(void *context, const char *topic, json_t *message) {
	char *payload = NULL;
	int rc = 0;
	janus_mqttevh_context *ctx;

	if(message == NULL) {
		return -1;
	}
	if(context == NULL) {
		/* We have no context, so skip and move on */
		json_decref(message);
		return -1;
	}
	JANUS_LOG(LOG_HUGE, "About to send message to %s\n", topic);

#ifdef SKREP
	if(payload != NULL) {
		/* Free previous message */
		free(payload);
		payload = NULL;
	}
#endif
	ctx = (janus_mqttevh_context *)context;

	payload = json_dumps(message, json_format);
	if(payload == NULL) {
		JANUS_LOG(LOG_ERR, "Can't convert message to string format\n");
		json_decref(message);
		return 0;
	}
	JANUS_LOG(LOG_HUGE, "Converted message to JSON for %s\n", topic);
	/* Ok, lets' get rid of the message */
	json_decref(message);

	rc = janus_mqttevh_client_publish_message(ctx, topic, ctx->publish.retain, payload);

	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_WARN, "Can't publish to MQTT topic: %s, return code: %d\n", ctx->publish.topic, rc);
	}

	JANUS_LOG(LOG_HUGE, "Done with message to JSON for %s\n", topic);

	return 0;
}

static void janus_mqttevh_client_connection_lost(void *context, char *cause) {

	/* Notify handlers about this transport being gone */
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;

	JANUS_LOG(LOG_WARN, "MQTT EVH connection %s lost cause of %s. Reconnecting...\n", ctx->connect.url, cause);
}

/* Set up connection to MQTT broker */
static int janus_mqttevh_client_connect(janus_mqttevh_context *ctx) {
	int rc;

	MQTTAsync_connectOptions options = MQTTAsync_connectOptions_initializer;
	options.keepAliveInterval = ctx->connect.keep_alive_interval;
	options.cleansession = ctx->connect.cleansession;
	options.username = ctx->connect.username;
	options.password = ctx->connect.password;
	options.automaticReconnect = TRUE;
	options.onSuccess = janus_mqttevh_client_connect_success;
	options.onFailure = janus_mqttevh_client_connect_failure;
	options.context = ctx;

	MQTTAsync_willOptions willOptions = MQTTAsync_willOptions_initializer;
	if(ctx->will.enabled) {
		willOptions.topicName = ctx->will.topic;
		willOptions.message = ctx->publish.disconnect_status;
		willOptions.retained = ctx->will.retain;
		willOptions.qos = ctx->will.qos;

		options.will = &willOptions;
	}

	rc = MQTTAsync_connect(ctx->client, &options);
	return rc;
}

/* Callback for succesful connection to MQTT broker */
static void janus_mqttevh_client_connect_success(void *context, MQTTAsync_successData *response) {
	JANUS_LOG(LOG_INFO, "MQTT EVH client has been successfully connected to the broker\n");

	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;

	char topicbuf[512];
	snprintf(topicbuf, sizeof(topicbuf), "%s/%s", ctx->publish.topic, JANUS_MQTTEVH_STATUS_TOPIC);

	/* Using LWT's retain for initial status message because
	 * we need to ensure we overwrite LWT if it's retained.
	 */
	int rc = janus_mqttevh_client_publish_message(ctx, topicbuf, ctx->will.retain, ctx->publish.connect_status);

	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_WARN, "Can't publish to MQTT topic: %s, return code: %d\n", topicbuf, rc);
	}
}

/* Callback for MQTT broker connection failure */
static void janus_mqttevh_client_connect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;

	/* Notify handlers about this transport failure */
	JANUS_LOG(LOG_ERR, "MQTT EVH client has failed connecting to the broker, return code: %d. Reconnecting...\n", rc);

}

/* MQTT broker Reconnect function */
static int janus_mqttevh_client_reconnect(janus_mqttevh_context *ctx) {
	JANUS_LOG(LOG_INFO, "MQTT EVH client reconnecting to %s. Reconnecting...\n", ctx->connect.url);

	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;
	options.onSuccess = janus_mqttevh_client_reconnect_success;
	options.onFailure = janus_mqttevh_client_reconnect_failure;
	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;

	return MQTTAsync_disconnect(ctx->client, &options);
}

/* Callback for successful reconnection to MQTT broker */
static void janus_mqttevh_client_reconnect_success(void *context, MQTTAsync_successData *response) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;

	JANUS_LOG(LOG_WARN, "MQTT EVH client has been disconnected from %s. Reconnecting...\n", ctx->connect.url);

	int rc = janus_mqttevh_client_connect(context);
	if(rc != MQTTASYNC_SUCCESS) {
		const char *error;
		switch(rc) {
			case 1: error = "Connection refused - protocol version";
				break;
			case 2: error = "Connection refused - identifier rejected";
				break;
			case 3: error = "Connection refused - server unavailable";
				break;
			case 4: error = "Connection refused - bad credentials";
				break;
			case 5: error = "Connection refused - not authroized";
				break;
			default: error = "Connection refused - unknown error";
				break;
		}
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d (%s)\n", rc, error);
		return;
	}
}

/* Callback for MQTT broker reconnect failure */
static void janus_mqttevh_client_reconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT EVH client failed reconnecting to MQTT broker, return code: %d\n", rc);
}

/* Disconnect from MQTT broker */
static int janus_mqttevh_client_disconnect(janus_mqttevh_context *ctx) {
	char topicbuf[512];
	snprintf(topicbuf, sizeof(topicbuf), "%s/%s", ctx->publish.topic, JANUS_MQTTEVH_STATUS_TOPIC);

	/* Using LWT's retain for disconnect status message because
	 * we need to ensure we overwrite LWT if it's retained.
	 */
	int rc = janus_mqttevh_client_publish_message(ctx, topicbuf, 1, ctx->publish.disconnect_status);

	if(rc != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_WARN, "Can't publish to MQTT topic: %s, return code: %d\n", topicbuf, rc);
	}

	MQTTAsync_disconnectOptions options = MQTTAsync_disconnectOptions_initializer;
	options.onSuccess = janus_mqttevh_client_disconnect_success;
	options.onFailure = janus_mqttevh_client_disconnect_failure;
	options.context = ctx;
	options.timeout = ctx->disconnect.timeout;
	return MQTTAsync_disconnect(ctx->client, &options);
}

/* Callback for succesful MQTT disconnect */
static void janus_mqttevh_client_disconnect_success(void *context, MQTTAsync_successData *response) {

	/* Notify handlers about this transport being gone */
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;

	JANUS_LOG(LOG_INFO, "MQTT EVH client has been successfully disconnected from %s. Destroying the client...\n", ctx->connect.url);
	janus_mqttevh_client_destroy_context(&ctx);
}

/* Callback for MQTT disconnect failure */
void janus_mqttevh_client_disconnect_failure(void *context, MQTTAsync_failureData *response) {
	int rc = response ? response->code : 0;
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;

	JANUS_LOG(LOG_ERR, "Can't disconnect from MQTT EVH broker %s, return code: %d\n", ctx->connect.url, rc);

	janus_mqttevh_client_destroy_context(&ctx);
}


/* Publish mqtt message using paho
 * Payload is a string. JSON objects should be stringified before calling this function.
 */
static int janus_mqttevh_client_publish_message(janus_mqttevh_context *ctx, const char *topic, int retain, char *payload)
{
	int rc;

	MQTTAsync_responseOptions options;
	memset(&options, 0, sizeof(MQTTAsync_responseOptions));
	MQTTAsync_message msg = MQTTAsync_message_initializer;

	msg.payload = payload;
	msg.payloadlen = strlen(payload);
	msg.qos = ctx->publish.qos;
	msg.retained = retain;

	/* TODO: The payload if generated by json_dumps needs to be freed
	free(payload);
	payload = (char *)NULL;
	*/

	options.context = ctx;
	options.onSuccess = janus_mqttevh_client_publish_janus_success;
	options.onFailure = janus_mqttevh_client_publish_janus_failure;
	rc = MQTTAsync_sendMessage(ctx->client, topic, &msg, &options);
	if(rc == MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_HUGE, "MQTT EVH message sent to topic %s on %s. Result %d\n", topic, ctx->connect.url, rc);
	} else {
		JANUS_LOG(LOG_WARN, "FAILURE: MQTT EVH message propably not sent to topic %s on %s. Result %d\n", topic, ctx->connect.url, rc);
	}

	return rc;
}

/* Callback for successful MQTT publish */
static void janus_mqttevh_client_publish_janus_success(void *context, MQTTAsync_successData *response) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
	JANUS_LOG(LOG_HUGE, "MQTT EVH client has successfully published to MQTT base topic: %s\n", ctx->publish.topic);
}

/* Callback for MQTT publish failure
 * 	Should we bring message into queue? Right now, we just drop it.
 */
static void janus_mqttevh_client_publish_janus_failure(void *context, MQTTAsync_failureData *response) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
	int rc = response ? response->code : 0;
	JANUS_LOG(LOG_ERR, "MQTT EVH client has failed publishing to MQTT topic: %s, return code: %d\n", ctx->publish.topic, rc);
}


/* Destroy Janus MQTT event handler session context */
static void janus_mqttevh_client_destroy_context(janus_mqttevh_context **ptr) {
	JANUS_LOG(LOG_INFO, "About to destroy MQTT EVH context...\n");

	janus_mqttevh_context *ctx = (janus_mqttevh_context *)*ptr;

	if(ctx) {
		MQTTAsync_destroy(&ctx->client);
		if(ctx->publish.topic != NULL) {
			g_free(ctx->publish.topic);
		}
		if(ctx->connect.username != NULL) {
			g_free(ctx->connect.username);
		}
		if(ctx->connect.password != NULL) {
			g_free(ctx->connect.password);
		}
		g_free(ctx);
		*ptr = NULL;
	}

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_MQTTEVH_NAME);
}

/* This is not used here, but required by the api (even though docs says no) */
static int janus_mqttevh_client_message_arrived(void *context, char *topicName, int topicLen, MQTTAsync_message *message) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)context;
	gchar *topic = g_strndup(topicName, topicLen);
	//~ const gboolean janus = janus_mqtt_evh_enabled && !strcasecmp(topic, ctx->subscribe.topic);
	const gboolean janus = janus_mqtt_evh_enabled ;
	g_free(topic);

	if(janus && message->payloadlen) {
		JANUS_LOG(LOG_HUGE, "MQTT %s: Receiving %s EVH message over MQTT: %s\n",
			ctx->connect.url, "Janus", (char *)message->payload);
	}

	MQTTAsync_freeMessage(&message);
	MQTTAsync_free(topicName);
	return TRUE;
}

static void janus_mqttevh_client_delivery_complete(void *context, MQTTAsync_token token) {
	/* If you send with QoS, you get confirmation here */
}

/* Plugin implementation */
static int janus_mqttevh_init(const char *config_path) {
	int res = 0;
	janus_config_item *url_item;
	janus_config_item *username_item, *password_item, *topic_item, *addevent_item;
	janus_config_item *keep_alive_interval_item, *cleansession_item, *disconnect_timeout_item, *qos_item, *retain_item, *connect_status_item, *disconnect_status_item;
	janus_config_item *will_retain_item, *will_qos_item, *will_enabled_item;

	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}
	/* Read configuration */
	char filename[255];
	g_snprintf(filename, sizeof(filename), "%s/%s.jcfg", config_path, JANUS_MQTTEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_MQTTEVH_PACKAGE);
		g_snprintf(filename, sizeof(filename), "%s/%s.cfg", config_path, JANUS_MQTTEVH_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
		if(config == NULL) {
			JANUS_LOG(LOG_FATAL, "Couldn't find .cfg configuration file (%s), giving up\n", JANUS_MQTTEVH_PACKAGE);
			return -1;
		}
	}

	janus_config_print(config);

	janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

	/* Initializing context */
	janus_mqttevh_context *ctx = g_malloc0(sizeof(struct janus_mqttevh_context));
	context = ctx;

	/* Set default values */
	/* Strings are set to default values later */
	ctx->addplugin = DEFAULT_ADDPLUGIN;
	ctx->addevent = DEFAULT_ADDEVENT;
	ctx->publish.qos = DEFAULT_QOS;
	ctx->publish.retain = DEFAULT_RETAIN;
	ctx->connect.username = NULL;
	ctx->connect.password = NULL;
	ctx->disconnect.timeout = DEFAULT_TIMEOUT;

	ctx->will.enabled = FALSE;
	ctx->will.qos = DEFAULT_WILL_QOS;
	ctx->will.retain = DEFAULT_WILL_RETAIN;

	ctx->tls.enable = DEFAULT_TLS_ENABLE;
	ctx->tls.verify_peer = DEFAULT_TLS_VERIFY_PEER;
	ctx->tls.verify_host = DEFAULT_TLS_VERIFY_HOST;

	/* Setup the event handler, if required */
	janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "enabled");

	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "MQTT event handler disabled\n");
		goto error;
	}
	janus_mqtt_evh_enabled = TRUE;

	/* MQTT URL */
	url_item = janus_config_get(config, config_general, janus_config_type_item, "url");
	ctx->connect.url= g_strdup((url_item && url_item->value) ? url_item->value : DEFAULT_MQTTURL);

	janus_config_item *client_id_item = janus_config_get(config, config_general, janus_config_type_item, "client_id");

	ctx->connect.client_id = g_strdup((client_id_item && client_id_item->value) ? client_id_item->value : "guest");

	username_item = janus_config_get(config, config_general, janus_config_type_item, "username");
	if(username_item && username_item->value) {
		ctx->connect.username = g_strdup(username_item->value);
	} else {
		ctx->connect.username = NULL;
	}

	password_item = janus_config_get(config, config_general, janus_config_type_item, "password");
	if(password_item && password_item->value) {
		ctx->connect.password = g_strdup(password_item->value);
	} else {
		ctx->connect.password = NULL;
	}

	janus_config_item *json_item = janus_config_get(config, config_general, janus_config_type_item, "json");
	if(json_item && json_item->value) {
		/* Check how we need to format/serialize the JSON output */
		if(!strcasecmp(json_item->value, "indented")) {
			/* Default: indented, we use three spaces for that */
			json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
		} else if(!strcasecmp(json_item->value, "plain")) {
			/* Not indented and no new lines, but still readable */
			json_format = JSON_INDENT(0) | JSON_PRESERVE_ORDER;
		} else if(!strcasecmp(json_item->value, "compact")) {
			/* Compact, so no spaces between separators */
			json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;
		} else {
			JANUS_LOG(LOG_WARN, "Unsupported JSON format option '%s', using default (indented)\n", json_item->value);
			json_format = DEFAULT_JSON_FORMAT;
		}
	}

	/* Which events should we subscribe to? */
	item = janus_config_get(config, config_general, janus_config_type_item, "events");
	if(item && item->value)
		janus_events_edit_events_mask(item->value, &janus_mqttevh.events_mask);

	/* Connect configuration */
	keep_alive_interval_item = janus_config_get(config, config_general, janus_config_type_item, "keep_alive_interval");
	ctx->connect.keep_alive_interval = (keep_alive_interval_item && keep_alive_interval_item->value) ? atoi(keep_alive_interval_item->value) : DEFAULT_KEEPALIVE;

	cleansession_item = janus_config_get(config, config_general, janus_config_type_item, "cleansession");
	ctx->connect.cleansession = (cleansession_item && cleansession_item->value) ? atoi(cleansession_item->value) : DEFAULT_CLEANSESSION;

	/* Disconnect configuration */
	disconnect_timeout_item = janus_config_get(config, config_general, janus_config_type_item, "disconnect_timeout");
	ctx->disconnect.timeout = (disconnect_timeout_item && disconnect_timeout_item->value) ? atoi(disconnect_timeout_item->value) : DEFAULT_DISCONNECT_TIMEOUT;

	topic_item = janus_config_get(config, config_general, janus_config_type_item, "topic");
	if(!topic_item || !topic_item->value) {
		ctx->publish.topic = g_strdup(DEFAULT_BASETOPIC);
	} else {
		ctx->publish.topic = g_strdup(topic_item->value);
	}
	addevent_item = janus_config_get(config, config_general, janus_config_type_item, "addevent");
	if(addevent_item && addevent_item->value && janus_is_true(addevent_item->value)) {
		ctx->addevent = TRUE;
	}
	retain_item = janus_config_get(config, config_general, janus_config_type_item, "retain");
	if(retain_item && retain_item->value && janus_is_true(retain_item->value)) {
		ctx->publish.retain = atoi(retain_item->value);;
	}

	qos_item = janus_config_get(config, config_general, janus_config_type_item, "qos");
	ctx->publish.qos = (qos_item && qos_item->value) ? atoi(qos_item->value) : 1;

	connect_status_item = janus_config_get(config, config_general, janus_config_type_item, "connect_status");
	if(connect_status_item && connect_status_item->value) {
		ctx->publish.connect_status = g_strdup(connect_status_item->value);
	} else {
		ctx->publish.connect_status = g_strdup(DEFAULT_CONNECT_STATUS);
	}

	disconnect_status_item = janus_config_get(config, config_general, janus_config_type_item, "disconnect_status");
	if(disconnect_status_item && disconnect_status_item->value) {
		ctx->publish.disconnect_status = g_strdup(disconnect_status_item->value);
	} else {
		ctx->publish.disconnect_status = g_strdup(DEFAULT_DISCONNECT_STATUS);
	}

	/* LWT config */
	will_enabled_item = janus_config_get(config, config_general, janus_config_type_item, "will_enabled");
	if(will_enabled_item && will_enabled_item->value && janus_is_true(will_enabled_item->value)) {
		ctx->will.enabled = TRUE;

		will_retain_item = janus_config_get(config, config_general, janus_config_type_item, "will_retain");
		if(will_retain_item && will_retain_item->value && janus_is_true(will_retain_item->value)) {
			ctx->will.retain = 1;
		}

		will_qos_item = janus_config_get(config, config_general, janus_config_type_item, "will_qos");
		if(will_qos_item && will_qos_item->value) {
			ctx->will.qos = atoi(will_qos_item->value);
		}

		/* Using the topic for LWT as configured for publish and suffixed with JANUS_MQTTEVH_STATUS_TOPIC. */
		char will_topic_buf[512];
		snprintf(will_topic_buf, sizeof(will_topic_buf), "%s/%s", ctx->publish.topic, JANUS_MQTTEVH_STATUS_TOPIC);
		ctx->will.topic = g_strdup(will_topic_buf);
	}

	/* TLS config*/
	item = janus_config_get(config, config_general, janus_config_type_item, "tls_enable");
	/* for old people */
	if(!item) {
		item = janus_config_get(config, config_general, janus_config_type_item, "ssl_enable");
	}

	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_INFO, "MQTTEventHandler: MQTT TLS support disabled\n");
	} else {
		ctx->tls.enable = TRUE;
		item = janus_config_get(config, config_general, janus_config_type_item, "tls_cacert");
		if(!item) {
			item = janus_config_get(config, config_general, janus_config_type_item, "ssl_cacert");
		}
		if(item && item->value) {
			ctx->tls.cacert_file = g_strdup(item->value);
		}

		item = janus_config_get(config, config_general, janus_config_type_item, "tls_client_cert");
		if(!item) {
			item = janus_config_get(config, config_general, janus_config_type_item, "ssl_client_cert");
		}
		if(item && item->value) {
			ctx->tls.cert_file = g_strdup(item->value);
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "tls_client_key");
		if(!item) {
			item = janus_config_get(config, config_general, janus_config_type_item, "ssl_client_key");
		}
		if(item && item->value) {
			ctx->tls.key_file = g_strdup(item->value);
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "tls_verify_peer");
		if(!item) {
			item = janus_config_get(config, config_general, janus_config_type_item, "ssl_verify_peer");
		}
		if(item && item->value && janus_is_true(item->value)) {
			ctx->tls.verify_peer = TRUE;
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "tls_verify_hostname");
		if(!item) {
			item = janus_config_get(config, config_general, janus_config_type_item, "ssl_verify_hostname");
		}
		if(item && item->value && janus_is_true(item->value)) {
			ctx->tls.verify_host = TRUE;
		}
	}

	if(!janus_mqtt_evh_enabled) {
		JANUS_LOG(LOG_WARN, "MQTT event handler support disabled, giving up\n");
		goto error;
	}

	/* Create a MQTT client */
	res = MQTTAsync_create(
		&ctx->client,
		ctx->connect.url,
		ctx->connect.client_id,
		MQTTCLIENT_PERSISTENCE_NONE,
		NULL);

	 if(res != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Can't setup library for connection to MQTT broker %s: error %d creating client...\n",
			ctx->connect.url, res);
		goto error;
	}
	/* Set callbacks. We should not really subscribe to anything but nevertheless */
	res = MQTTAsync_setCallbacks(ctx->client,
			ctx,
			janus_mqttevh_client_connection_lost,
			janus_mqttevh_client_message_arrived,	//Needed
			janus_mqttevh_client_delivery_complete);

	if(res != MQTTASYNC_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Event handler: Can't setup MQTT broker %s: error %d setting up callbacks...\n",
			ctx->connect.url, res);
		goto error;
	}
	JANUS_LOG(LOG_INFO, "Event handler: About to connect to MQTT broker %s: ...\n",
		ctx->connect.url);

	/* Connecting to the broker */
	int rc = janus_mqttevh_client_connect(ctx);
	if(rc != MQTTASYNC_SUCCESS) {
		const char *error;
		switch(rc) {
			case 1: error = "Connection refused - protocol version";
				break;
			case 2: error = "Connection refused - identifier rejected";
				break;
			case 3: error = "Connection refused - server unavailable";
				break;
			case 4: error = "Connection refused - bad credentials";
				break;
			case 5: error = "Connection refused - not authroized";
				break;
			default: error = "Connection refused - unknown error";
				break;
		}
		JANUS_LOG(LOG_FATAL, "Can't connect to MQTT broker, return code: %d (%s)\n", rc, error);
		goto error;
	}

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify)janus_mqttevh_event_free);
	g_atomic_int_set(&initialized, 1);

	/* Create the event handler thread */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus mqttevh handler", janus_mqttevh_handler, ctx, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the MQTT EventHandler handler thread...\n", error->code, error->message ? error->message : "??");
		goto error;
	}

	/* Done */
	if(config) {
		janus_config_destroy(config);
	}

	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_MQTTEVH_NAME);
	return 0;

error:
	/* If we got here, something went wrong */
	janus_mqttevh_client_destroy_context(&ctx);

	if(config) {
		janus_config_destroy(config);
	}
	return -1;
}

static void janus_mqttevh_destroy(void) {

	if(!g_atomic_int_get(&initialized)) {
		/* We never started, so just quit */
		return;
	}
	g_atomic_int_set(&stopping, 1);

	/* Put the exit event on the queue to stop the other thread */
	g_async_queue_push(events, &exit_event);

	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}

	g_async_queue_unref(events);
	events = NULL;

	/* Shut down the MQTT connection now */
	janus_mqttevh_client_disconnect(context);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_MQTTEVH_NAME);
}

static void janus_mqttevh_incoming_event(json_t *event) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		/* Janus is closing or the plugin is */
		return;
	}
	json_incref(event);
	g_async_queue_push(events, event);
}

json_t *janus_mqttevh_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to apply tweaks to the logic */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_MQTTEVH_ERROR_MISSING_ELEMENT, JANUS_MQTTEVH_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "tweak")) {
		/* We only support a request to tweak the current settings */
		JANUS_VALIDATE_JSON_OBJECT(request, tweak_parameters,
			error_code, error_cause, TRUE,
			JANUS_MQTTEVH_ERROR_MISSING_ELEMENT, JANUS_MQTTEVH_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		/* Events */
		if(json_object_get(request, "events"))
			janus_events_edit_events_mask(json_string_value(json_object_get(request, "events")), &janus_mqttevh.events_mask);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_MQTTEVH_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			json_t *response = json_object();
			if(error_code == 0) {
				/* Return a success */
				json_object_set_new(response, "result", json_integer(200));
			} else {
				/* Prepare JSON error event */
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}
}


/* Thread to handle incoming events and push them out on the MQTT. We
 * will publish events on multiple topics, depending on the event type.
 * If the base topic is configured to "/janus/events", then a handle
 * event will be published to "/janus/events/handle" */
static void *janus_mqttevh_handler(void *data) {
	janus_mqttevh_context *ctx = (janus_mqttevh_context *)data;
	json_t *event = NULL;
	char topicbuf[512];

	JANUS_LOG(LOG_VERB, "Joining MqttEventHandler handler thread\n");

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Get event from queue */
		event = g_async_queue_pop(events);
		if(event == NULL) {
			/* There was nothing in the queue */
			continue;
		}
		if(event == &exit_event) {
			break;
		}
		/* Handle event: just for fun, let's see how long it took for us to take care of this */
		json_t *created = json_object_get(event, "timestamp");
		if(created && json_is_integer(created)) {
			gint64 then = json_integer_value(created);
			gint64 now = janus_get_monotonic_time();
			JANUS_LOG(LOG_DBG, "Handled event after %"SCNu64" us\n", now-then);
		}

		int type = json_integer_value(json_object_get(event, "type"));
		const char *elabel = janus_events_type_to_label(type);
		const char *ename = janus_events_type_to_name(type);

		/* Hack to test new functions */
		if(elabel && ename) {
			JANUS_LOG(LOG_HUGE, "Event label %s, name %s\n", elabel, ename);
			json_object_set_new(event, "eventtype", json_string(ename));
		} else {
			JANUS_LOG(LOG_WARN, "Can't get event label or name\n");
		}

		if(!g_atomic_int_get(&stopping)) {
			/* Convert event to string */
			if(ctx->addevent) {
				snprintf(topicbuf, sizeof(topicbuf), "%s/%s", ctx->publish.topic, janus_events_type_to_label(type));
				JANUS_LOG(LOG_DBG, "Debug: MQTT Publish event on %s\n", topicbuf);
				janus_mqttevh_send_message(ctx, topicbuf, event);
			} else {
				janus_mqttevh_send_message(ctx, ctx->publish.topic, event);
			}
		}

		JANUS_LOG(LOG_VERB, "Debug: Thread done publishing MQTT Publish event on %s\n", topicbuf);
	}
	JANUS_LOG(LOG_VERB, "Leaving MQTTEventHandler handler thread\n");
	return NULL;
}
