/*! \file   janus_audiobridge.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
 * \brief  Janus AudioBridge plugin
 * \details  This is a plugin implementing an audio conference bridge for
 * Janus, specifically mixing Opus streams. This means that it replies
 * by providing in the SDP only support for Opus, and disabling video.
 * Opus encoding and decoding is implemented using libopus (http://opus.codec.org).
 * The plugin provides an API to allow peers to join and leave conference
 * rooms. Peers can then mute/unmute themselves by sending specific messages
 * to the plugin: any way a peer mutes/unmutes, an event is triggered
 * to the other participants, so that it can be rendered in the UI
 * accordingly.
 * 
 * \todo Right now only wideband (16kHz) mixing is implemented.
 * 
 * Rooms to make available are listed in the plugin configuration file.
 * A pre-filled configuration file is provided in \c conf/janus.plugin.audiobridge.cfg
 * and includes a demo room for testing.
 * 
 * To add more rooms or modify the existing one, you can use the following
 * syntax:
 * 
 * \verbatim
[<unique room ID>]
description = This is my awesome room
sampling_rate = <sampling rate> (e.g., 16000 for wideband mixing)
\endverbatim
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>
#include <opus/opus.h>
#include <sys/time.h>

#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../rtcp.h"


/* Plugin information */
#define JANUS_AUDIOBRIDGE_VERSION			1
#define JANUS_AUDIOBRIDGE_VERSION_STRING	"0.0.1"
#define JANUS_AUDIOBRIDGE_DESCRIPTION		"This is a plugin implementing an audio conference bridge for Janus, mixing Opus streams."
#define JANUS_AUDIOBRIDGE_NAME				"JANUS AudioBridge plugin"
#define JANUS_AUDIOBRIDGE_PACKAGE			"janus.plugin.audiobridge"

/* Plugin methods */
janus_plugin *create(void);
int janus_audiobridge_init(janus_callbacks *callback, const char *config_path);
void janus_audiobridge_destroy(void);
int janus_audiobridge_get_version(void);
const char *janus_audiobridge_get_version_string(void);
const char *janus_audiobridge_get_description(void);
const char *janus_audiobridge_get_name(void);
const char *janus_audiobridge_get_package(void);
void janus_audiobridge_create_session(janus_pluginession *handle, int *error);
void janus_audiobridge_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_audiobridge_setup_media(janus_pluginession *handle);
void janus_audiobridge_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len);
void janus_audiobridge_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len);
void janus_audiobridge_hangup_media(janus_pluginession *handle);
void janus_audiobridge_destroy_session(janus_pluginession *handle, int *error);

/* Plugin setup */
static janus_plugin janus_audiobridge_plugin =
	{
		.init = janus_audiobridge_init,
		.destroy = janus_audiobridge_destroy,

		.get_version = janus_audiobridge_get_version,
		.get_version_string = janus_audiobridge_get_version_string,
		.get_description = janus_audiobridge_get_description,
		.get_name = janus_audiobridge_get_name,
		.get_package = janus_audiobridge_get_package,
		
		.create_session = janus_audiobridge_create_session,
		.handle_message = janus_audiobridge_handle_message,
		.setup_media = janus_audiobridge_setup_media,
		.incoming_rtp = janus_audiobridge_incoming_rtp,
		.incoming_rtcp = janus_audiobridge_incoming_rtcp,
		.hangup_media = janus_audiobridge_hangup_media,
		.destroy_session = janus_audiobridge_destroy_session,
	}; 

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_PRINT("%s created!\n", JANUS_AUDIOBRIDGE_NAME);
	return &janus_audiobridge_plugin;
}


/* Useful stuff */
static int initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_audiobridge_handler(void *data);
static void janus_audiobridge_relay_rtp_packet(gpointer data, gpointer user_data);
static void *janus_audiobridge_mixer_thread(void *data);

typedef struct janus_audiobridge_message {
	janus_pluginession *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_audiobridge_message;
GQueue *messages;

typedef struct janus_audiobridge_room {
	guint64 room_id;	/* Unique room ID */
	gchar *room_name;	/* Room description */
	uint32_t sampling_rate;	/* Sampling rate of the mix (e.g., 16000 for wideband) */
	gboolean record;
	FILE *recording;
	gboolean destroy;
	GHashTable *participants;	/* Map of participants */
	janus_mutex mutex;
} janus_audiobridge_room;
GHashTable *rooms;

typedef struct janus_audiobridge_session {
	janus_pluginession *handle;
	gpointer participant;
	gboolean started;
	gboolean stopping;
	gboolean destroy;
} janus_audiobridge_session;
GHashTable *sessions;

typedef struct janus_audiobridge_participant {
	janus_audiobridge_session *session;
	janus_audiobridge_room *room;	/* Room */
	guint64 user_id;	/* Unique ID in the room */
	gchar *display;	/* Display name (just for fun) */
	gboolean audio_active;
	/* RTP stuff */
	GQueue *inbuf;
	int opus_pt;
	/* Opus stuff */
	OpusEncoder *encoder;
	OpusDecoder *decoder;
} janus_audiobridge_participant;

/* Packets we get from gstreamer and relay */
typedef struct janus_audiobridge_rtp_relay_packet {
	rtp_header *data;
	gint length;
} janus_audiobridge_rtp_relay_packet;

/* SDP offer/answer template */
static const char *sdp_template =
		"v=0\r\n"
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */
		"s=%s\r\n"							/* Audio bridge name */
		"t=0 0\r\n"
		"m=audio 1 RTP/SAVPF %d\r\n"		/* Opus payload type */
		"c=IN IP4 1.1.1.1\r\n"
		"a=rtpmap:%d opus/48000/2\r\n"		/* Opus payload type */
		"a=fmtp:%d maxplaybackrate=%d; stereo=0; sprop-stereo=0; useinbandfec=0\r\n"
											/* Opus payload type and room sampling rate */
		"a=mid:audio\r\n";

/* Helper struct to generate and parse WAVE headers */
typedef struct wav_header {
	char riff[4];
	uint32_t len;
	char wave[4];
	char fmt[4];
	uint32_t formatsize;
	uint16_t format;
	uint16_t channels;
	uint32_t samplerate;
	uint32_t avgbyterate;
	uint16_t samplebytes;
	uint16_t channelbits;
	char data[4];
	uint32_t blocksize;
} wav_header;


/* Opus settings */		
#define	BUFFER_SAMPLES	8000
#define	OPUS_SAMPLES	160
#define USE_FEC			0
#define DEFAULT_COMPLEXITY	4


/* Plugin implementation */
int janus_audiobridge_init(janus_callbacks *callback, const char *config_path) {
	if(stopping) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	sprintf(filename, "%s/%s.cfg", config_path, JANUS_AUDIOBRIDGE_PACKAGE);
	JANUS_PRINT("Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	
	rooms = g_hash_table_new(NULL, NULL);
	sessions = g_hash_table_new(NULL, NULL);
	messages = g_queue_new();
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		janus_config_category *cat = janus_config_get_categories(config);
		while(cat != NULL) {
			if(cat->name == NULL) {
				cat = cat->next;
				continue;
			}
			JANUS_PRINT("Adding audio room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get_item(cat, "description");
			janus_config_item *sampling = janus_config_get_item(cat, "sampling_rate");
			janus_config_item *record = janus_config_get_item(cat, "record");
			if(sampling == NULL || sampling->value == NULL) {
				JANUS_DEBUG("Can't add the audio room, missing mandatory information...\n");
				cat = cat->next;
				continue;
			}
			/* Create the audio bridge room */
			janus_audiobridge_room *audiobridge = calloc(1, sizeof(janus_audiobridge_room));
			if(audiobridge == NULL) {
				JANUS_DEBUG("Memory error!\n");
				continue;
			}
			audiobridge->room_id = atoi(cat->name);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			if(description == NULL) {
				JANUS_DEBUG("Memory error!\n");
				continue;
			}
			audiobridge->room_name = description;
			audiobridge->sampling_rate = atoi(sampling->value);
			if(audiobridge->sampling_rate != 16000) {
				JANUS_DEBUG("We currently only support 16kHz (wideband) as a sampling rate for audio rooms, changing %"SCNu32" to 16000...\n", audiobridge->sampling_rate);
				audiobridge->sampling_rate = 16000;
			}
			audiobridge->record = FALSE;
			if(record && record->value && !strcasecmp(record->value, "yes"))
				audiobridge->record = TRUE;
			audiobridge->recording = NULL;
			audiobridge->destroy = 0;
			audiobridge->participants = g_hash_table_new(NULL, NULL);
			janus_mutex_init(&audiobridge->mutex);
			g_hash_table_insert(rooms, GUINT_TO_POINTER(audiobridge->room_id), audiobridge);
			JANUS_PRINT("Created audiobridge: %"SCNu64" (%s)\n", audiobridge->room_id, audiobridge->room_name);
			/* We need a thread for the mix */
			g_thread_new("audiobridge mixer thread", &janus_audiobridge_mixer_thread, audiobridge);
			cat = cat->next;
		}
		/* Done */
		janus_config_destroy(config);
		config = NULL;
	}

	/* Show available rooms */
	GList *rooms_list = g_hash_table_get_values(rooms);
	GList *r = rooms_list;
	while(r) {
		janus_audiobridge_room *ar = (janus_audiobridge_room *)r->data;
		JANUS_PRINT("  ::: [%"SCNu64"][%s] %"SCNu32" (%s be recorded)\n",
			ar->room_id, ar->room_name, ar->sampling_rate, ar->record ? "will" : "will NOT");
		r = r->next;
	}
	g_list_free(rooms_list);

	initialized = 1;
	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus audiobridge handler", janus_audiobridge_handler, NULL, &error);
	if(error != NULL) {
		initialized = 0;
		/* Something went wrong... */
		JANUS_DEBUG("Got error %d (%s) trying to launch thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_PRINT("%s initialized!\n", JANUS_AUDIOBRIDGE_NAME);
	return 0;
}

void janus_audiobridge_destroy() {
	if(!initialized)
		return;
	stopping = 1;
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
	}
	handler_thread = NULL;
	/* TODO Actually remove rooms and its participants */
	g_hash_table_destroy(sessions);
	g_hash_table_destroy(rooms);
	g_queue_free(messages);
	sessions = NULL;
	initialized = 0;
	JANUS_PRINT("%s destroyed!\n", JANUS_AUDIOBRIDGE_NAME);
}

int janus_audiobridge_get_version() {
	return JANUS_AUDIOBRIDGE_VERSION;
}

const char *janus_audiobridge_get_version_string() {
	return JANUS_AUDIOBRIDGE_VERSION_STRING;
}

const char *janus_audiobridge_get_description() {
	return JANUS_AUDIOBRIDGE_DESCRIPTION;
}

const char *janus_audiobridge_get_name() {
	return JANUS_AUDIOBRIDGE_NAME;
}

const char *janus_audiobridge_get_package() {
	return JANUS_AUDIOBRIDGE_PACKAGE;
}

void janus_audiobridge_create_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_audiobridge_session *session = (janus_audiobridge_session *)calloc(1, sizeof(janus_audiobridge_session));
	if(session == NULL) {
		JANUS_DEBUG("Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->started = FALSE;
	session->stopping = FALSE;
	session->destroy = FALSE;
	handle->plugin_handle = session;
	g_hash_table_insert(sessions, handle, session);

	return;
}

void janus_audiobridge_destroy_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_audiobridge_session *session = (janus_audiobridge_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(session->destroy) {
		JANUS_PRINT("Session already destroyed...\n");
		g_free(session);
		return;
	}
	JANUS_PRINT("Removing Audio Bridge session...\n");
	g_hash_table_remove(sessions, handle);
	janus_audiobridge_hangup_media(handle);
	session->destroy = TRUE;
	g_free(session);

	return;
}

void janus_audiobridge_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(stopping || !initialized)
		return;
	JANUS_PRINT("%s\n", message);
	janus_audiobridge_message *msg = calloc(1, sizeof(janus_audiobridge_message));
	if(msg == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return;
	}
	msg->handle = handle;
	msg->transaction = transaction ? g_strdup(transaction) : NULL;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;
	g_queue_push_tail(messages, msg);
}

void janus_audiobridge_setup_media(janus_pluginession *handle) {
	JANUS_DEBUG("WebRTC media is now available\n");
	if(stopping || !initialized)
		return;
	janus_audiobridge_session *session = (janus_audiobridge_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* TODO Only send this peer the audio mix when we get this event */
}

void janus_audiobridge_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized)
		return;
	janus_audiobridge_session *session = (janus_audiobridge_session *)handle->plugin_handle;	
	if(!session || session->destroy || session->stopping || !session->participant)
		return;
	janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
	if(!participant->audio_active)
		return;
	/* Decode frame (Opus -> slinear) */
	janus_audiobridge_rtp_relay_packet *pkt = calloc(1, sizeof(janus_audiobridge_rtp_relay_packet));
	if(pkt == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return;
	}
	pkt->data = calloc(BUFFER_SAMPLES, sizeof(opus_int16));
	if(pkt->data == NULL) {
		JANUS_DEBUG("Memory error!\n");
		g_free(pkt);
		return;
	}
	pkt->length = opus_decode(participant->decoder, (const unsigned char *)buf+12, len-12, (opus_int16 *)pkt->data, BUFFER_SAMPLES, USE_FEC);
	if(pkt->length < 0) {
		JANUS_PRINT("[Opus] Ops! got an error decoding the Opus frame: %d (%s)\n", pkt->length, opus_strerror(pkt->length));
		g_free(pkt->data);
		g_free(pkt);
		return;
	}
	/* Enqueue the decoded frame */
	g_queue_push_tail(participant->inbuf, pkt);
}

void janus_audiobridge_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized)
		return;
	/* FIXME Should we care? */
}

void janus_audiobridge_hangup_media(janus_pluginession *handle) {
	JANUS_PRINT("No WebRTC media anymore\n");
	if(stopping || !initialized)
		return;
	janus_audiobridge_session *session = (janus_audiobridge_session *)handle->plugin_handle;
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy || !session->participant)
		return;
	/* Get rid of participant */
	janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
	janus_audiobridge_room *audiobridge = participant->room;
	janus_mutex_lock(&audiobridge->mutex);
	json_t *event = json_object();
	json_object_set(event, "audiobridge", json_string("event"));
	json_object_set(event, "room", json_integer(audiobridge->room_id));
	json_object_set(event, "leaving", json_integer(participant->user_id));
	char *leaving_text = json_dumps(event, JSON_INDENT(3));
	json_decref(event);
	g_hash_table_remove(audiobridge->participants, GUINT_TO_POINTER(participant->user_id));
	GList *participants_list = g_hash_table_get_values(audiobridge->participants);
	GList *ps = participants_list;
	while(ps) {
		janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
		if(p == participant) {
			ps = ps->next;
			continue;	/* Skip the leaving participant itself */
		}
		JANUS_PRINT("Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display);
		JANUS_PRINT("  >> %d\n", gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, leaving_text, NULL, NULL));
		ps = ps->next;
	}
	g_free(leaving_text);
	g_list_free(participants_list);
	participant->audio_active = 0;
	session->started = FALSE;
	session->destroy = 1;
	janus_mutex_unlock(&audiobridge->mutex);
}

/* Thread to handle incoming messages */
static void *janus_audiobridge_handler(void *data) {
	JANUS_DEBUG("Joining thread\n");
	janus_audiobridge_message *msg = NULL;
	char *error_cause = calloc(512, sizeof(char));	/* FIXME 512 should be enough, but anyway... */
	if(error_cause == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return NULL;
	}
	while(initialized && !stopping) {
		if(!messages || (msg = g_queue_pop_head(messages)) == NULL) {
			usleep(50000);
			continue;
		}
		janus_audiobridge_session *session = (janus_audiobridge_session *)msg->handle->plugin_handle;	
		if(!session) {
			JANUS_DEBUG("No session associated with this handle...\n");
			continue;
		}
		if(session->destroy)
			continue;
		/* Handle request */
		JANUS_PRINT("Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_DEBUG("No message??\n");
			sprintf(error_cause, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		json_t *root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_DEBUG("JSON error: on line %d: %s\n", error.line, error.text);
			sprintf(error_cause, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_DEBUG("JSON error: not an object\n");
			sprintf(error_cause, "JSON error: not an object");
			goto error;
		}
		/* Get the request first */
		json_t *request = json_object_get(root, "request");
		if(!request || !json_is_string(request)) {
			JANUS_DEBUG("JSON error: invalid element (request)\n");
			sprintf(error_cause, "JSON error: invalid element (request)");
			goto error;
		}
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		if(!strcasecmp(request_text, "create")) {
			/* Create a new audiobridge */
			JANUS_PRINT("Creating a new audiobridge\n");
			json_t *desc = json_object_get(root, "description");
			if(desc && !json_is_string(desc)) {
				JANUS_DEBUG("JSON error: invalid element (desc)\n");
				sprintf(error_cause, "JSON error: invalid element (desc)");
				goto error;
			}
			json_t *sampling = json_object_get(root, "sampling");
			if(sampling && !json_is_integer(sampling)) {
				JANUS_DEBUG("JSON error: invalid element (sampling)\n");
				sprintf(error_cause, "JSON error: invalid element (sampling)");
				goto error;
			}
			json_t *record = json_object_get(root, "record");
			if(record && !json_is_boolean(record)) {
				JANUS_DEBUG("JSON error: invalid element (record)\n");
				sprintf(error_cause, "JSON error: invalid value (record)");
				goto error;
			}
			/* Create the audio bridge room */
			janus_audiobridge_room *audiobridge = calloc(1, sizeof(janus_audiobridge_room));
			if(audiobridge == NULL) {
				JANUS_DEBUG("Memory error!\n");
				sprintf(error_cause, "Memory error");
				goto error;
			}
			/* Generate a random ID */
			guint64 room_id = 0;
			while(room_id == 0) {
				room_id = g_random_int();
				if(g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id)) != NULL) {
					/* Room ID already taken, try another one */
					room_id = 0;
				}
			}
			audiobridge->room_id = room_id;
			char *description = NULL;
			if(desc != NULL) {
				description = g_strdup(json_string_value(desc));
			} else {
				char roomname[255];
				sprintf(roomname, "Room %"SCNu64"", audiobridge->room_id);
				description = g_strdup(roomname);
			}
			if(description == NULL) {
				JANUS_DEBUG("Memory error!\n");
				continue;
			}
			audiobridge->room_name = description;
			if(sampling)
				audiobridge->sampling_rate = json_integer_value(sampling);
			else
				audiobridge->sampling_rate = 16000;
			if(audiobridge->sampling_rate != 16000) {
				JANUS_DEBUG("We currently only support 16kHz (wideband) as a sampling rate for audio rooms, changing %"SCNu32" to 16000...\n", audiobridge->sampling_rate);
				audiobridge->sampling_rate = 16000;
			}
			audiobridge->record = FALSE;
			if(record && json_is_true(record))
				audiobridge->record = TRUE;
			audiobridge->recording = NULL;
			audiobridge->destroy = 0;
			audiobridge->participants = g_hash_table_new(NULL, NULL);
			janus_mutex_init(&audiobridge->mutex);
			g_hash_table_insert(rooms, GUINT_TO_POINTER(audiobridge->room_id), audiobridge);
			JANUS_PRINT("Created audiobridge: %"SCNu64" (%s)\n", audiobridge->room_id, audiobridge->room_name);
			/* We need a thread for the mix */
			g_thread_new("audiobridge mixer thread", &janus_audiobridge_mixer_thread, audiobridge);
			/* Show updated rooms list */
			GList *rooms_list = g_hash_table_get_values(rooms);
			GList *r = rooms_list;
			while(r) {
				janus_audiobridge_room *ar = (janus_audiobridge_room *)r->data;
				JANUS_PRINT("  ::: [%"SCNu64"][%s] %"SCNu32" (%s be recorded)\n",
					ar->room_id, ar->room_name, ar->sampling_rate, ar->record ? "will" : "will NOT");
				r = r->next;
			}
			g_list_free(rooms_list);
			/* Send info back */
			event = json_object();
			json_object_set(event, "audiobridge", json_string("created"));
			json_object_set(event, "room", json_integer(audiobridge->room_id));
		} else if(!strcasecmp(request_text, "join")) {
			JANUS_PRINT("Configuring new participant\n");
			json_t *room = json_object_get(root, "room");
			if(!room || !json_is_integer(room)) {
				JANUS_DEBUG("JSON error: invalid element (room)\n");
				sprintf(error_cause, "JSON error: invalid element (room)");
				goto error;
			}
			guint64 room_id = json_integer_value(room);
			janus_audiobridge_room *audiobridge = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
			if(audiobridge == NULL) {
				JANUS_DEBUG("No such room (%"SCNu64")\n", room_id);
				sprintf(error_cause, "No such room (%"SCNu64")", room_id);
				goto error;
			}
			json_t *display = json_object_get(root, "display");
			if(!display || !json_is_string(display)) {
				JANUS_DEBUG("JSON error: invalid element (display)\n");
				sprintf(error_cause, "JSON error: invalid element (display)");
				goto error;
			}
			const char *display_text = json_string_value(display);
			/* Generate a random ID */
			guint64 user_id = 0;
			while(user_id == 0) {
				user_id = g_random_int();
				if(g_hash_table_lookup(audiobridge->participants, GUINT_TO_POINTER(user_id)) != NULL) {
					/* User ID already taken, try another one */
					user_id = 0;
				}
			}
			JANUS_PRINT("  -- Participant ID: %"SCNu64"\n", user_id);
			janus_audiobridge_participant *participant = calloc(1, sizeof(janus_audiobridge_participant));
			if(participant == NULL) {
				JANUS_DEBUG("Memory error!\n");
				sprintf(error_cause, "Memory error");
				goto error;
			}
			participant->session = session;
			participant->room = audiobridge;
			participant->user_id = user_id;
			participant->display = g_strdup(display_text);
			if(participant->display == NULL) {
				JANUS_DEBUG("Memory error!\n");
				sprintf(error_cause, "Memory error");
				g_free(participant);
				goto error;
			}
			participant->audio_active = FALSE;
			participant->inbuf = g_queue_new();
			participant->opus_pt = 0;
			JANUS_PRINT("Creating Opus encoder/decoder (sampling rate %d)\n", audiobridge->sampling_rate);
			/* Opus encoder */
			int error = 0;
			participant->encoder = opus_encoder_create(audiobridge->sampling_rate, 1, OPUS_APPLICATION_VOIP, &error);
			if(error != OPUS_OK) {
				g_free(participant->display);
				g_free(participant);
				JANUS_DEBUG("Error creating Opus encoder\n");
				sprintf(error_cause, "Error creating Opus decoder");
				goto error;
			}
			if(audiobridge->sampling_rate == 8000)
				opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
			else if(audiobridge->sampling_rate == 12000)
				opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_MEDIUMBAND));
			else if(audiobridge->sampling_rate == 16000)
				opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
			else if(audiobridge->sampling_rate == 24000)
				opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_SUPERWIDEBAND));
			else if(audiobridge->sampling_rate == 48000)
				opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND));
			else
				JANUS_PRINT("Unsupported sampling rate %d\n", audiobridge->sampling_rate);
			/* FIXME This settings should be configurable */
			opus_encoder_ctl(participant->encoder, OPUS_SET_INBAND_FEC(USE_FEC));
			opus_encoder_ctl(participant->encoder, OPUS_SET_COMPLEXITY(DEFAULT_COMPLEXITY));
			/* Opus decoder */
			error = 0;
			participant->decoder = opus_decoder_create(audiobridge->sampling_rate, 1, &error);
			if(error != OPUS_OK) {
				g_free(participant->display);
				if(participant->encoder)
					opus_encoder_destroy(participant->encoder);
				if(participant->decoder)
					opus_decoder_destroy(participant->decoder);
				g_free(participant);
				JANUS_DEBUG("Error creating Opus encoder\n");
				sprintf(error_cause, "Error creating Opus decoder");
				goto error;
			}

			/* Done */
			janus_mutex_lock(&audiobridge->mutex);
			session->participant = participant;
			g_hash_table_insert(audiobridge->participants, GUINT_TO_POINTER(user_id), participant);
			/* Return a list of all available participants (those with an SDP available, that is) */
			json_t *list = json_array();
			GList *participants_list = g_hash_table_get_values(audiobridge->participants);
			GList *ps = participants_list;
			while(ps) {
				janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
				if(p == participant) {
					ps = ps->next;
					continue;
				}
				json_t *pl = json_object();
				json_object_set_new(pl, "id", json_integer(p->user_id));
				json_object_set_new(pl, "display", json_string(p->display));
				//~ json_object_set_new(pl, "muted", json_boolean(!p->audio_active));
				json_object_set_new(pl, "muted", json_string(p->audio_active ? "false" : "true"));
				json_array_append_new(list, pl);
				ps = ps->next;
			}
			event = json_object();
			json_object_set(event, "audiobridge", json_string("joined"));
			json_object_set(event, "room", json_integer(audiobridge->room_id));
			json_object_set(event, "id", json_integer(user_id));
			json_object_set_new(event, "participants", list);
			g_list_free(participants_list);
			janus_mutex_unlock(&audiobridge->mutex);
		} else if(!strcasecmp(request_text, "configure")) {
			/* Handle this participant */
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_DEBUG("Can't configure (not in a room)\n");
				sprintf(error_cause, "Can't configure (not in a room)");
				goto error;
			}
			/* Configure settings for this participant */
			json_t *audio = json_object_get(root, "audio");
			if(audio && !json_is_boolean(audio)) {
				JANUS_DEBUG("JSON error: invalid element (audio)\n");
				sprintf(error_cause, "JSON error: invalid value (audio)");
				goto error;
			}
			if(audio) {
				participant->audio_active = json_is_true(audio);
				JANUS_PRINT("Setting audio property: %s (room %"SCNu64", user %"SCNu64")\n", participant->audio_active ? "true" : "false", participant->room->room_id, participant->user_id);
				if(!participant->audio_active) {
					/* Clear the queued packets waiting to be handled */
					while(!g_queue_is_empty(participant->inbuf)) {
						janus_audiobridge_rtp_relay_packet *pkt = g_queue_pop_head(participant->inbuf);
						if(pkt == NULL)
							continue;
						if(pkt->data)
							g_free(pkt->data);
						g_free(pkt);
					}
				}
				/* Notify all other participants about the mute/unmute */
				janus_audiobridge_room *audiobridge = participant->room;
				janus_mutex_lock(&audiobridge->mutex);
				json_t *list = json_array();
				json_t *pl = json_object();
				json_object_set_new(pl, "id", json_integer(participant->user_id));
				json_object_set_new(pl, "display", json_string(participant->display));
				//~ json_object_set_new(pl, "muted", json_boolean(!participant->audio_active));
				json_object_set_new(pl, "muted", json_string(participant->audio_active ? "false" : "true"));
				json_array_append_new(list, pl);
				json_t *pub = json_object();
				json_object_set(pub, "audiobridge", json_string("event"));
				json_object_set(pub, "room", json_integer(participant->room->room_id));
				json_object_set_new(pub, "participants", list);
				char *pub_text = json_dumps(pub, JSON_INDENT(3));
				json_decref(list);
				json_decref(pub);
				GList *participants_list = g_hash_table_get_values(participant->room->participants);
				GList *ps = participants_list;
				while(ps) {
					janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
					if(p == participant) {
						ps = ps->next;
						continue;	/* Skip the new participant itself */
					}
					JANUS_PRINT("Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display);
					JANUS_PRINT("  >> %d\n", gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, pub_text, NULL, NULL));
					ps = ps->next;
				}
				g_list_free(participants_list);
				janus_mutex_unlock(&audiobridge->mutex);
			}
			/* Done */
			event = json_object();
			json_object_set(event, "audiobridge", json_string("event"));
			json_object_set(event, "room", json_integer(participant->room->room_id));
			json_object_set(event, "result", json_string("ok"));
		} else if(!strcasecmp(request_text, "leave")) {
			/* This participant is leaving */
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_DEBUG("Can't leave (not in a room)\n");
				sprintf(error_cause, "Can't leave (not in a room)");
				goto error;
			}
			/* Tell everybody */
			janus_audiobridge_room *audiobridge = participant->room;
			janus_mutex_lock(&audiobridge->mutex);
			event = json_object();
			json_object_set(event, "audiobridge", json_string("event"));
			json_object_set(event, "room", json_integer(audiobridge->room_id));
			json_object_set(event, "leaving", json_integer(participant->user_id));
			char *leaving_text = json_dumps(event, JSON_INDENT(3));
			GList *participants_list = g_hash_table_get_values(audiobridge->participants);
			GList *ps = participants_list;
			while(ps) {
				janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
				if(p == participant) {
					ps = ps->next;
					continue;	/* Skip the new participant itself */
				}
				JANUS_PRINT("Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display);
				JANUS_PRINT("  >> %d\n", gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, leaving_text, NULL, NULL));
				ps = ps->next;
			}
			g_free(leaving_text);
			g_list_free(participants_list);
			/* Done */
			participant->audio_active = 0;
			session->started = FALSE;
			session->destroy = 1;
			janus_mutex_unlock(&audiobridge->mutex);
		} else {
			JANUS_DEBUG("Unknown request '%s'\n", request_text);
			sprintf(error_cause, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Prepare JSON event */
		JANUS_PRINT("Preparing JSON event as a reply\n");
		char *event_text = json_dumps(event, JSON_INDENT(3));
		json_decref(event);
		/* Any SDP to handle? */
		if(!msg->sdp) {
			JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_audiobridge_plugin, msg->transaction, event_text, NULL, NULL));
		} else {
			JANUS_PRINT("This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			char *type = NULL;
			if(!strcasecmp(msg->sdp_type, "offer"))
				type = "answer";
			if(!strcasecmp(msg->sdp_type, "answer"))
				type = "offer";
			/* Fill the SDP template and use that as our answer */
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			char sdp[1024];
			/* What is the Opus payload type? */
			participant->opus_pt = 0;
			char *fmtp = strstr(msg->sdp, "opus/48000");
			if(fmtp != NULL) {
				fmtp -= 5;
				fmtp = strstr(fmtp, ":");
				if(fmtp)
					fmtp++;
				participant->opus_pt = atoi(fmtp);
			}
			JANUS_PRINT("Opus payload type is %d\n", participant->opus_pt);
			g_sprintf(sdp, sdp_template,
				g_get_monotonic_time(),			/* We need current time here */
				g_get_monotonic_time(),			/* We need current time here */
				participant->room->room_name,	/* Audio bridge name */
				participant->opus_pt,			/* Opus payload type */
				participant->opus_pt,			/* Opus payload type */
				participant->opus_pt, 			/* Opus payload type and room sampling rate */
				participant->room->sampling_rate);
			/* Did the peer negotiate video? */
			if(strstr(msg->sdp, "m=video") != NULL) {
				/* If so, reject it */
				g_strlcat(sdp, "m=video 0 RTP/SAVPF 0\r\n", 1024);				
			}
			/* How long will the gateway take to push the event? */
			gint64 start = g_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_audiobridge_plugin, msg->transaction, event_text, type, sdp);
			JANUS_PRINT("  >> Pushing event: %d (took %"SCNu64" ms)\n", res, g_get_monotonic_time()-start);
			if(res != JANUS_OK) {
				/* TODO Failed to negotiate? We should remove this participant */
			} else {
				/* Notify all other participants that there's a new boy in town */
				janus_audiobridge_room *audiobridge = participant->room;
				janus_mutex_lock(&audiobridge->mutex);
				json_t *list = json_array();
				json_t *pl = json_object();
				json_object_set_new(pl, "id", json_integer(participant->user_id));
				json_object_set_new(pl, "display", json_string(participant->display));
				//~ json_object_set_new(pl, "muted", json_boolean(!participant->audio_active));
				json_object_set_new(pl, "muted", json_string(participant->audio_active ? "false" : "true"));
				json_array_append_new(list, pl);
				json_t *pub = json_object();
				json_object_set(pub, "audiobridge", json_string("event"));
				json_object_set(pub, "room", json_integer(participant->room->room_id));
				json_object_set_new(pub, "participants", list);
				char *pub_text = json_dumps(pub, JSON_INDENT(3));
				json_decref(list);
				json_decref(pub);
				GList *participants_list = g_hash_table_get_values(participant->room->participants);
				GList *ps = participants_list;
				while(ps) {
					janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
					if(p == participant) {
						ps = ps->next;
						continue;	/* Skip the new participant itself */
					}
					JANUS_PRINT("Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display);
					JANUS_PRINT("  >> %d\n", gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, pub_text, NULL, NULL));
					ps = ps->next;
				}
				g_list_free(participants_list);
				session->started = TRUE;
				janus_mutex_unlock(&audiobridge->mutex);
			}
		}

		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set(event, "audiobridge", json_string("event"));
			json_object_set(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3));
			json_decref(event);
			JANUS_PRINT("Pushing event: %s\n", event_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_audiobridge_plugin, msg->transaction, event_text, NULL, NULL));
		}
	}
	JANUS_DEBUG("Leaving thread\n");
	return NULL;
}

/* FIXME Thread to send RTP packets from the mix */
static void *janus_audiobridge_mixer_thread(void *data) {
	JANUS_PRINT("Audio bridge thread starting...\n");
	janus_audiobridge_room *audiobridge = (janus_audiobridge_room *)data;
	if(!audiobridge) {
		JANUS_PRINT("Invalid room!\n");
		return NULL;
	}
	JANUS_PRINT("Thread is for mixing room %"SCNu64" (%s)...\n", audiobridge->room_id, audiobridge->room_name);
	/* Do we need to record the mix? */
	if(audiobridge->record) {
		char filename[255];
		sprintf(filename, "/tmp/janus-audioroom-%"SCNu64".wav", audiobridge->room_id);
		audiobridge->recording = fopen(filename, "wb");
		if(audiobridge->recording == NULL) {
			JANUS_DEBUG("Recording requested, but could NOT open file %s for writing...\n", filename);
		} else {
			JANUS_PRINT("Recording requested, opened file %s for writing\n", filename);
			/* Write WAV header */
			wav_header header = {
				{'R', 'I', 'F', 'F'},
				0,
				{'W', 'A', 'V', 'E'},
				{'f', 'm', 't', ' '},
				16,
				1,
				1,
				16000,
				16000,
				2,
				16,
				{'d', 'a', 't', 'a'},
				0
			};
			if(fwrite(&header, 1, sizeof(header), audiobridge->recording) != sizeof(header)) {
				JANUS_DEBUG("Error writing WAV header...\n");
			}
		}
	}
	/* Buffer (wideband) */
	opus_int32 buffer[320], sumBuffer[320];
	opus_int16 outBuffer[320], *curBuffer = NULL;
	memset(buffer, 0, 1280);
	memset(sumBuffer, 0, 1280);
	memset(outBuffer, 0, 640);
	/* Timer */
	struct timeval now, before;
	gettimeofday(&before, NULL);
	now.tv_sec = before.tv_sec;
	now.tv_usec = before.tv_usec;
	time_t passed, d_s, d_us;
	/* Output buffer */
	janus_audiobridge_rtp_relay_packet *outpkt = calloc(1, sizeof(janus_audiobridge_rtp_relay_packet));
	if(outpkt == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return NULL;
	}
	outpkt->data = (rtp_header *)calloc(BUFFER_SAMPLES, sizeof(unsigned char));
	if(outpkt->data == NULL) {
		JANUS_DEBUG("Memory error!\n");
		g_free(outpkt);
		return NULL;
	}
	unsigned char *payload = (unsigned char *)outpkt->data;
	memset(payload, 0, BUFFER_SAMPLES);
	/* RTP */
	gint16 seq = 0;
	gint32 ts = 0;
	/* Loop */
	int i=0;
	while(!stopping) {	/* FIXME We need a per-mountpoint watchdog as well */
		/* See if it's time to prepare a frame */
		gettimeofday(&now, NULL);
		d_s = now.tv_sec - before.tv_sec;
		d_us = now.tv_usec - before.tv_usec;
		if(d_us < 0) {
			d_us += 1000000;
			--d_s;
		}
		passed = d_s*1000000 + d_us;
		if(passed < 15000) {	/* Let's wait about 15ms at max */
			usleep(1000);
			continue;
		}
		/* Update the reference time */
		before.tv_usec += 20000;
		if(before.tv_usec > 1000000) {
			before.tv_sec++;
			before.tv_usec -= 1000000;
		}
		/* Update RTP header */
		outpkt->data->version = 2;
		outpkt->data->markerbit = 0;	/* FIXME Should be 1 for the first packet */
		seq++;
		outpkt->data->seq_number = htons(seq);
		ts += 960;
		outpkt->data->timestamp = htonl(ts);
		outpkt->data->ssrc = htonl(1);	/* The gateway will fix this anyway */
		/* Mix all contributions */
		janus_mutex_lock(&audiobridge->mutex);
		GList *participants_list = g_hash_table_get_values(audiobridge->participants);
		janus_mutex_unlock(&audiobridge->mutex);
		for(i=0; i<320; i++)
			buffer[i] = 0;
		GList *ps = participants_list;
		while(ps) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
			if(!p->audio_active || g_queue_is_empty(p->inbuf)) {
				ps = ps->next;
				continue;
			}
			janus_audiobridge_rtp_relay_packet *pkt = g_queue_peek_head(p->inbuf);
			curBuffer = (opus_int16 *)pkt->data;
			for(i=0; i<320; i++)
				buffer[i] += curBuffer[i];
			ps = ps->next;
		}
		/* Are we recording the mix? (only do it if there's someone in, though...) */ 
		if(audiobridge->recording != NULL && g_list_length(participants_list) > 0) { 
			for(i=0; i<320; i++) { 
				/* FIXME Smoothen/Normalize instead of truncating? */ 
				outBuffer[i] = buffer[i]; 
			} 
			fwrite(outBuffer, sizeof(opus_int16), 320, audiobridge->recording); 
		} 
		/* Send proper packet to each participant (remove own contribution) */
		ps = participants_list;
		while(ps) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
			janus_audiobridge_rtp_relay_packet *pkt = NULL;
			if(p->audio_active && !g_queue_is_empty(p->inbuf))
				pkt = g_queue_pop_head(p->inbuf);
			curBuffer = (opus_int16 *)(pkt ? pkt->data : NULL);
			for(i=0; i<320; i++)
				sumBuffer[i] = buffer[i] - (curBuffer ? (curBuffer[i]) : 0);
			for(i=0; i<320; i++)
				/* FIXME Smoothen/Normalize instead of truncating? */
				outBuffer[i] = sumBuffer[i];
			/* Encode raw frame to Opus */
			outpkt->length = opus_encode(p->encoder, outBuffer, 320, payload+12, BUFFER_SAMPLES-12);
			if(outpkt->length < 0) {
				JANUS_PRINT("[Opus] Ops! got an error encoding the Opus frame: %d (%s)\n", outpkt->length, opus_strerror(outpkt->length));
			} else {
				outpkt->length += 12;	/* Take the RTP header into consideration */
				janus_audiobridge_relay_rtp_packet(p->session, outpkt);
			}
			if(pkt) {
				if(pkt->data)
					g_free(pkt->data);
				g_free(pkt);
			}
			ps = ps->next;
		}
		g_list_free(participants_list);
	}
	if(audiobridge->recording)
		fclose(audiobridge->recording);
	JANUS_PRINT("Leaving mixer thread for room %"SCNu64" (%s)...\n", audiobridge->room_id, audiobridge->room_name);
	return NULL;
}

static void janus_audiobridge_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_audiobridge_rtp_relay_packet *packet = (janus_audiobridge_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_PRINT("Invalid packet...\n");
		return;
	}
	janus_audiobridge_session *session = (janus_audiobridge_session *)data;
	if(!session || !session->handle) {
		// JANUS_PRINT("Invalid session...\n");
		return;
	}
	if(!session->started) {
		// JANUS_PRINT("Streaming not started yet for this session...\n");
		return;
	}
	janus_audiobridge_participant *participant = session->participant;
	packet->data->type = participant->opus_pt;
	/* Go */
	if(gateway != NULL)	/* FIXME What about RTCP? */
		gateway->relay_rtp(session->handle, 0, (char *)packet->data, packet->length);
	return;
}
