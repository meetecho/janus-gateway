/*! \file   janus_homerlog.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Homer logger plugin
 * \details  This is a Homer logger plugin for Janus, which either uses
 * the HEP protocol (when using plain UDP/TCP) or simulates handler events
 * with a custom type (when using HTTP/HTTPS) to send Janus log lines to a
 * remote Homer instance. This is particularly useful to store and go
 * through logs using Homer, and doubly so if Homer is also used to collect
 * Janus events via actual event handlers.
 *
 * \ingroup loggers
 * \ref loggers
 */

#include "logger.h"

#include <curl/curl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"
#include "../ip-utils.h"


/* Plugin information */
#define JANUS_HOMERLOG_VERSION			1
#define JANUS_HOMERLOG_VERSION_STRING	"0.0.1"
#define JANUS_HOMERLOG_DESCRIPTION		"This is a Homer logger plugin for Janus, which sends all logs to a remote Homer instance."
#define JANUS_HOMERLOG_NAME				"JANUS Homer logger plugin"
#define JANUS_HOMERLOG_AUTHOR			"Meetecho s.r.l."
#define JANUS_HOMERLOG_PACKAGE			"janus.logger.homerlog"

/* Plugin methods */
janus_logger *create(void);
int janus_homerlog_init(const char *server_name, const char *config_path);
void janus_homerlog_destroy(void);
int janus_homerlog_get_api_compatibility(void);
int janus_homerlog_get_version(void);
const char *janus_homerlog_get_version_string(void);
const char *janus_homerlog_get_description(void);
const char *janus_homerlog_get_name(void);
const char *janus_homerlog_get_author(void);
const char *janus_homerlog_get_package(void);
void janus_homerlog_incoming_logline(int64_t timestamp, const char *line);
json_t *janus_homerlog_handle_request(json_t *request);

/* Logger setup */
static janus_logger janus_homerlog =
	JANUS_LOGGER_INIT (
		.init = janus_homerlog_init,
		.destroy = janus_homerlog_destroy,

		.get_api_compatibility = janus_homerlog_get_api_compatibility,
		.get_version = janus_homerlog_get_version,
		.get_version_string = janus_homerlog_get_version_string,
		.get_description = janus_homerlog_get_description,
		.get_name = janus_homerlog_get_name,
		.get_author = janus_homerlog_get_author,
		.get_package = janus_homerlog_get_package,

		.incoming_logline = janus_homerlog_incoming_logline,
		.handle_request = janus_homerlog_handle_request,
	);

/* Plugin creator */
janus_logger *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_HOMERLOG_NAME);
	return &janus_homerlog;
}


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *logger_thread;
static void *janus_homerlog_thread(void *data);
static janus_mutex logger_mutex;
static char *server = NULL;


/* Structure we use for queueing log lines */
typedef struct janus_homerlog_line {
	int64_t timestamp;		/* When the log line was printed */
	char *line;				/* Content of the log line */
} janus_homerlog_line;
static janus_homerlog_line exit_line;
static void janus_homerlog_line_free(janus_homerlog_line *jline) {
	if(!jline || jline == &exit_line)
		return;
	g_free(jline->line);
	g_free(jline);
}
/* Queue of log lines to handle */
static GAsyncQueue *loglines = NULL;

/* HEPv3 stuff */
#define JANUS_HOMERLOG_HEP3_ID					0x48455033
#define JANUS_HOMERLOG_HEP3_TYPE_SECONDS		0x0009
#define JANUS_HOMERLOG_HEP3_TYPE_MICROSECONDS	0x000a
#define JANUS_HOMERLOG_HEP3_TYPE_PROTOCOL		0x000b
#define JANUS_HOMERLOG_HEP3_TYPE_AGENT			0x000c
#define JANUS_HOMERLOG_HEP3_TYPE_PAYLOAD		0x000f
#define JANUS_HOMERLOG_HEP3_CAPTURE_TYPE_LOG	100
static uint32_t homer_agent_id = 0;

struct janus_homerlog_hep3_header {
	uint32_t id;			/* HEP protocol ID */
	uint16_t length;		/* Total length */
} __attribute__((packed));
typedef struct janus_homerlog_hep3_header janus_homerlog_hep3_header;

typedef struct janus_homerlog_hep3_chunk {
	uint16_t vendor_id;		/* Vendor ID */
	uint16_t type_id;		/* Type ID */
	uint16_t length;		/* Chunk length */
} janus_homerlog_hep3_chunk;

struct janus_homerlog_hep3_log {
	janus_homerlog_hep3_header header;
	janus_homerlog_hep3_chunk s_chunk;
	uint32_t s;
	janus_homerlog_hep3_chunk ms_chunk;
	uint32_t ms;
	janus_homerlog_hep3_chunk type_chunk;
	char type;
	janus_homerlog_hep3_chunk agent_chunk;
	uint32_t agent;
	janus_homerlog_hep3_chunk payload_chunk;
	char payload[1];
} __attribute__((packed));
typedef struct janus_homerlog_hep3_log janus_homerlog_hep3_log;

/* Fake event handler type, when using HTTP/HTTPS: we use one high
 * enough that it should never conflict with newer types later on */
#define JANUS_EVENT_TYPE_LOG			(1 << 30)


/* Address of the remote Homer instance */
static char *homer_address = NULL;
static struct sockaddr_in homer_addr4;
static struct sockaddr_in6 homer_addr6;
static struct sockaddr *homer_addr = NULL;
static size_t homer_addrlen = 0;
static uint16_t homer_port = 0;
static int homer_fd = -1;

#define JANUS_HOMERLOG_HEP3_UDP		1
#define JANUS_HOMERLOG_HEP3_TCP		2
#define JANUS_HOMERLOG_HEP3_CURL	3
static int homer_transport = 0;

/* Parameter validation (for querying or tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
/* Error codes for the Admin API interaction */
#define JANUS_HOMERLOG_ERROR_INVALID_REQUEST	411
#define JANUS_HOMERLOG_ERROR_MISSING_ELEMENT	412
#define JANUS_HOMERLOG_ERROR_INVALID_ELEMENT	413
#define JANUS_HOMERLOG_ERROR_UNKNOWN_ERROR		499


/* Plugin implementation */
int janus_homerlog_init(const char *server_name, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}
	if(server_name != NULL)
		server = g_strdup(server_name);
JANUS_LOG(LOG_WARN, "%s\n", server);
	/* Initialize libcurl, in case it's needed */
	curl_global_init(CURL_GLOBAL_ALL);

	/* Read configuration */
	gboolean enabled = FALSE;
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_HOMERLOG_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_HOMERLOG_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_HOMERLOG_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

		/* Setup the logger, if required */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Homer logger disabled\n");
			goto done;
		}

		/* Configure the capture agent ID */
		item = janus_config_get(config, config_general, janus_config_type_item, "agent_id");
		if(item && item->value)
			homer_agent_id = atol(item->value);

		/* Configure remote Homer instance */
		item = janus_config_get(config, config_general, janus_config_type_item, "address");
		if(!item || !item->value) {
			JANUS_LOG(LOG_ERR, "Homer address not specified...\n");
			goto done;
		}
		homer_transport = 0;
		homer_address = g_strdup(item->value);
		char host[100];
		/* Parse the uri scheme (TODO: needs better checks for IPvs addresses) */
		if(sscanf(homer_address, "udp://%99[^:]:%"SCNu16, host, &homer_port) == 2) {
			/* Use plain UDP */
			homer_transport = JANUS_HOMERLOG_HEP3_UDP;
		} else if(sscanf(homer_address, "tcp://%99[^:]:%"SCNu16, host, &homer_port) == 2) {
			/* Use plain TCP */
			homer_transport = JANUS_HOMERLOG_HEP3_TCP;
		} else {
			/* Check if libcurl supports this scheme */
			CURLU *h = curl_url();
			if(h != NULL) {
				CURLUcode uc = curl_url_set(h, CURLUPART_URL, homer_address, 0);
				if(uc == 0) {
					char *scheme = NULL;
					uc = curl_url_get(h, CURLUPART_SCHEME, &scheme, 0);
					if(uc == 0 && scheme != NULL && (!strcasecmp(scheme, "http") || !strcasecmp(scheme, "http"))) {
						char *url = NULL;
						uc = curl_url_get(h, CURLUPART_URL, &url, 0);
						if(uc == 0 && url != NULL) {
							/* Use libcurl */
							homer_transport = JANUS_HOMERLOG_HEP3_CURL;
							g_free(homer_address);
							homer_address = g_strdup(url);
						}
						if(url != NULL)
							curl_free(url);
					}
					if(scheme != NULL)
						curl_free(scheme);
				}
				curl_url_cleanup(h);
			}
			if(homer_transport == 0) {
				JANUS_LOG(LOG_ERR, "Unsupported address scheme '%s'...\n", homer_address);
				goto done;
			}
		}
		/* If this is UDP or TCP, resolve the address and prepare the socket */
		if(homer_transport == JANUS_HOMERLOG_HEP3_UDP || homer_transport == JANUS_HOMERLOG_HEP3_TCP) {
			/* Check if we need to resolve this address */
			struct addrinfo *res = NULL, *start = NULL;
			janus_network_address addr;
			janus_network_address_string_buffer addr_buf;
			const char *resolved_host = NULL;
			memset(&homer_addr4, 0, sizeof(homer_addr4));
			memset(&homer_addr6, 0, sizeof(homer_addr6));
			if(getaddrinfo(host, NULL, NULL, &res) == 0) {
				start = res;
				while(res != NULL) {
					if(janus_network_address_from_sockaddr(res->ai_addr, &addr) == 0 &&
							janus_network_address_to_string_buffer(&addr, &addr_buf) == 0) {
						/* Resolved */
						resolved_host = janus_network_address_string_from_buffer(&addr_buf);
						if(addr.family == AF_INET) {
							homer_addr4.sin_family = AF_INET;
							homer_addr4.sin_addr = addr.ipv4;
							homer_addr4.sin_port = htons(homer_port);
							homer_addr = (struct sockaddr *)&homer_addr4;
							homer_addrlen = sizeof(homer_addr4);
						} else {
							homer_addr6.sin6_family = AF_INET6;
							homer_addr6.sin6_addr = addr.ipv6;
							homer_addr6.sin6_port = htons(homer_port);
							homer_addr = (struct sockaddr *)&homer_addr6;
							homer_addrlen = sizeof(homer_addr6);
						}
						freeaddrinfo(start);
						start = NULL;
						break;
					}
					res = res->ai_next;
				}
			}
			if(resolved_host == NULL) {
				if(start)
					freeaddrinfo(start);
				JANUS_LOG(LOG_ERR, "Could not resolve address (%s)...\n", host);
				goto done;
			}
			/* Create the socket and connect */
			JANUS_LOG(LOG_INFO, "Connecting to Homer: %s://%s:%"SCNu16" (capture agent ID: %"SCNu32")\n",
				homer_transport == JANUS_HOMERLOG_HEP3_UDP ? "udp" : "tcp", resolved_host, homer_port, homer_agent_id);
			homer_fd = socket(AF_INET6,
				homer_transport == JANUS_HOMERLOG_HEP3_UDP ? SOCK_DGRAM : SOCK_STREAM,
				homer_transport == JANUS_HOMERLOG_HEP3_UDP ? IPPROTO_UDP : IPPROTO_TCP);
			int v6only = 0;
			if(homer_fd <= 0 ||
					setsockopt(homer_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
				JANUS_LOG(LOG_ERR, "Error creating Homer HEP %s socket... %d (%s)\n",
					homer_transport == JANUS_HOMERLOG_HEP3_UDP ? "UDP" : "TCP", errno, strerror(errno));
				goto done;
			}
			if(connect(homer_fd, homer_addr, homer_addrlen) < 0) {
				JANUS_LOG(LOG_ERR, "Error connecting to Homer HEP server... %d (%s)\n",
					errno, strerror(errno));
				goto done;
			}
		}
		enabled = TRUE;
	}

	/* Done */
done:
	janus_config_destroy(config);
	config = NULL;
	if(!enabled) {
		g_free(server);
		g_free(homer_address);
		if(homer_fd != -1) {
			if(homer_transport == JANUS_HOMERLOG_HEP3_TCP)
				shutdown(homer_fd, SHUT_RDWR);
			close(homer_fd);
		}
		return -1;	/* No point in keeping the plugin loaded */
	}

	JANUS_LOG(LOG_VERB, "Homer logger configured: %s\n", homer_address);

	/* Initialize the log queue */
	loglines = g_async_queue_new_full((GDestroyNotify) janus_homerlog_line_free);
	janus_mutex_init(&logger_mutex);

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming log lines */
	GError *error = NULL;
	logger_thread = g_thread_try_new("janus homerlog thread", janus_homerlog_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Homer logger thread...\n",
			error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_HOMERLOG_NAME);
	return 0;
}

void janus_homerlog_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(loglines, &exit_line);
	if(logger_thread != NULL) {
		g_thread_join(logger_thread);
		logger_thread = NULL;
	}

	g_async_queue_unref(loglines);
	loglines = NULL;

	/* Get rid of the sockets, if any */
	g_free(server);
	g_free(homer_address);
	if(homer_fd != -1) {
		if(homer_transport == JANUS_HOMERLOG_HEP3_TCP)
			shutdown(homer_fd, SHUT_RDWR);
		close(homer_fd);
	}

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_HOMERLOG_NAME);
}

int janus_homerlog_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_LOGGER_API_VERSION;
}

int janus_homerlog_get_version(void) {
	return JANUS_HOMERLOG_VERSION;
}

const char *janus_homerlog_get_version_string(void) {
	return JANUS_HOMERLOG_VERSION_STRING;
}

const char *janus_homerlog_get_description(void) {
	return JANUS_HOMERLOG_DESCRIPTION;
}

const char *janus_homerlog_get_name(void) {
	return JANUS_HOMERLOG_NAME;
}

const char *janus_homerlog_get_author(void) {
	return JANUS_HOMERLOG_AUTHOR;
}

const char *janus_homerlog_get_package(void) {
	return JANUS_HOMERLOG_PACKAGE;
}

void janus_homerlog_incoming_logline(int64_t timestamp, const char *line) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || line == NULL) {
		/* Janus is closing or the plugin is */
		return;
	}

	/* Do NOT handle the log line here in this callback! Since Janus sends
	 * log lines from its internal logger thread, performing I/O or network
	 * operations in here could dangerously slow Janus down. Let's just
	 * duplicate and enqueue the string containing the log line, and handle
	 * it in our own thread: we have a monotonic time indicator of when the
	 * log line was actually added on this machine, so that, if relevant, we can
	 * compute any delay in the actual log line processing ourselves. */
	janus_homerlog_line *l = g_malloc(sizeof(janus_homerlog_line));
	l->timestamp = timestamp;
	l->line = g_strdup(line);
	g_async_queue_push(loglines, l);

}

json_t *janus_homerlog_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to query the plugin or apply tweaks to the logic */
	json_t *response = json_object();
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_HOMERLOG_ERROR_MISSING_ELEMENT, JANUS_HOMERLOG_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "info")) {
		/* We only support a request to get some info from the plugin */
		json_object_set_new(response, "result", json_integer(200));
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_HOMERLOG_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code != 0) {
				/* Prepare JSON error event */
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}
}

/* Helper callback to send data using libcurl */
static size_t janus_homerlog_curl_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
	return size*nmemb;
}

/* Thread to handle incoming log lines */
static void *janus_homerlog_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining Homer logger thread\n");

	janus_homerlog_line *hline = NULL;
	janus_homerlog_hep3_log *packet = NULL;

	struct pollfd fds[1];
	char buffer[8192];
	size_t len = 0, linelen = 0;
	int resfd = 0;

	int64_t s_big = 0, ms_big = 0;
	uint32_t s = 0, ms = 0;

	json_t *event = NULL, *body = NULL;
	char *event_text = NULL;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Get a log line from the queue */
		hline = g_async_queue_pop(loglines);
		if(hline == NULL)
			continue;
		if(hline == &exit_line)
			break;
		if(hline->line == NULL) {
			janus_homerlog_line_free(hline);
			continue;
		}
		linelen = strlen(hline->line);

		/* Send the log line to Homer */
		if(homer_transport == JANUS_HOMERLOG_HEP3_CURL) {
			/* Use libcurl: this means generating a JSON string to
			 * simulate a fake eventhandler event of type log */
			event = json_object();
			if(server != NULL)
				json_object_set_new(event, "emitter", json_string(server));
			json_object_set_new(event, "type", json_integer(JANUS_EVENT_TYPE_LOG));
			json_object_set_new(event, "timestamp", json_integer(hline->timestamp));
			body = json_object();
			if(homer_agent_id != 0)
				json_object_set_new(body, "agent_id", json_integer(homer_agent_id));
			json_object_set_new(body, "log", json_string(hline->line));
			json_object_set_new(event, "event", body);
			event_text = json_dumps(event, JSON_COMPACT | JSON_PRESERVE_ORDER);
			json_decref(event);

			/* Prepare the libcurl context */
			CURLcode res;
			struct curl_slist *headers = NULL;
			CURL *curl = curl_easy_init();
			if(curl == NULL) {
				JANUS_LOG(LOG_ERR, "Error initializing CURL context\n");
				goto curldone;
			}
			curl_easy_setopt(curl, CURLOPT_URL, homer_address);
			headers = curl_slist_append(headers, "Accept: application/json");
			headers = curl_slist_append(headers, "Content-Type: application/json");
			headers = curl_slist_append(headers, "charsets: utf-8");
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, event_text);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, janus_homerlog_curl_write_data);
			/* Don't wait forever (let's say, 10 seconds) */
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
			/* Send the request */
			res = curl_easy_perform(curl);
			if(res != CURLE_OK) {
				JANUS_LOG(LOG_ERR, "Couldn't send log line to the backend: %s\n", curl_easy_strerror(res));
			}
curldone:
			/* Cleanup */
			if(curl)
				curl_easy_cleanup(curl);
			if(headers)
				curl_slist_free_all(headers);
			free(event_text);
		} else {
			/* Send manually over UDP or TCP as a HEP packet */
			len = 0;
			packet = (janus_homerlog_hep3_log *)buffer;

			/* Compute seconds and microseconds as HEP needs them */
			s_big = hline->timestamp / G_USEC_PER_SEC;
			ms_big = hline->timestamp - (s_big * G_USEC_PER_SEC);
			s = (uint32_t)s_big;
			ms = (uint32_t)ms_big;

			/* HEPv3 header */
			packet->header.id = htonl(JANUS_HOMERLOG_HEP3_ID);
			packet->header.length = 0;		/* We'll update this later */
			len += (sizeof(janus_homerlog_hep3_header));
			/* Seconds timestamp */
			packet->s_chunk.vendor_id = 0;
			packet->s_chunk.type_id = htons(JANUS_HOMERLOG_HEP3_TYPE_SECONDS);
			packet->s_chunk.length = htons(sizeof(janus_homerlog_hep3_chunk) + sizeof(uint32_t));
			packet->s = htonl(s);
			len += (sizeof(janus_homerlog_hep3_chunk) + sizeof(uint32_t));
			/* Microseconds timestamp */
			packet->ms_chunk.vendor_id = 0;
			packet->ms_chunk.type_id = htons(JANUS_HOMERLOG_HEP3_TYPE_MICROSECONDS);
			packet->ms_chunk.length = htons(sizeof(janus_homerlog_hep3_chunk) + sizeof(uint32_t));
			packet->ms = htonl(ms);
			len += (sizeof(janus_homerlog_hep3_chunk) + sizeof(uint32_t));
			/* Protocol type */
			packet->type_chunk.vendor_id = 0;
			packet->type_chunk.type_id = htons(JANUS_HOMERLOG_HEP3_TYPE_PROTOCOL);
			packet->type_chunk.length = htons(sizeof(janus_homerlog_hep3_chunk) + 1);
			packet->type = JANUS_HOMERLOG_HEP3_CAPTURE_TYPE_LOG;
			len += (sizeof(janus_homerlog_hep3_chunk) + 1);
			/* Capture agent ID */
			packet->agent_chunk.vendor_id = 0;
			packet->agent_chunk.type_id = htons(JANUS_HOMERLOG_HEP3_TYPE_AGENT);
			packet->agent_chunk.length = htons(sizeof(janus_homerlog_hep3_chunk) + sizeof(uint32_t));
			packet->agent = htonl(homer_agent_id);
			len += (sizeof(janus_homerlog_hep3_chunk) + sizeof(uint32_t));
			/* Payload */
			packet->payload_chunk.vendor_id = 0;
			packet->payload_chunk.type_id = htons(JANUS_HOMERLOG_HEP3_TYPE_PAYLOAD);
			if((linelen + len) > sizeof(buffer)) {
				/* Line too long, truncate */
				linelen = sizeof(buffer)-len;
			}
			packet->payload_chunk.length = htons(sizeof(janus_homerlog_hep3_chunk) + linelen);
			memcpy(packet->payload, hline->line, linelen);
			len += (sizeof(janus_homerlog_hep3_chunk) + linelen);
			/* Update the total length in the HEPv3 header */
			packet->header.length = htons(len);

			while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
				fds[0].fd = homer_fd;
				fds[0].events = POLLOUT | POLLERR;
				fds[0].revents = 0;
				resfd = poll(fds, 1, 100);
				if(resfd < 0) {
					if(errno == EINTR) {
						JANUS_LOG(LOG_HUGE, "Got an EINTR (%s), ignoring...\n", strerror(errno));
						continue;
					}
					/* Probably a socket error, should we reconnect? */
					JANUS_LOG(LOG_ERR, "Error polling... %d (%s)\n", errno, strerror(errno));
					break;
				} else if(resfd == 0) {
					/* Nothing yet, keep going */
					continue;
				}
				if(homer_transport == JANUS_HOMERLOG_HEP3_UDP && len > 1472)
					len = 1472;	/* Packet too large, truncate it */
				if(send(homer_fd, buffer, len, 0) < 0) {
					/* Probably a socket error, should we reconnect? */
					JANUS_LOG(LOG_ERR, "Error sending the packet... %d (%s)\n", errno, strerror(errno));
					break;
				} else {
					/* Packet sent */
					break;
				}
			}
		}
		janus_homerlog_line_free(hline);
	}
	JANUS_LOG(LOG_VERB, "Leaving Homer logger thread\n");
	return NULL;
}
