/*! \file    sctp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SCTP processing for data channels
 * \details  Implementation (based on libusrsctp) of the SCTP Data Channels.
 * The code takes care of the SCTP association between peers and the gateway,
 * and allows for sending and receiving text messages (binary stuff yet to
 * be implemented) after that.
 * 
 * \note Right now, the code is heavily based on the rtcweb.c sample code
 * provided in the \c usrsctp library code, and as such the copyright notice
 * that appears at the beginning of that code is ideally present here as
 * well: http://code.google.com/p/sctp-refimpl/source/browse/trunk/KERN/usrsctp/programs/rtcweb.c 
 * 
 * \note If you want/need to debug SCTP messages for any reason, you can
 * do so by uncommenting the definition of \c DEBUG_SCTP in sctp.h. This
 * will force this code to save all the SCTP messages being exchanged to
 * a separate file for each session. You must choose what folder to save
 * these files in by modifying the \c debug_folder variable. Once a file
 * has been saved, you need to process it using the \c text2pcap tool
 * that is usually shipped with Wireshark, e.g.:
 * 
\verbatim
cd /path/to/sctp
/usr/sbin/text2pcap -n -l 248 -D -t '%H:%M:%S.' sctp-debug-XYZ.txt sctp-debug-XYZ.pcapng
/usr/sbin/wireshark sctp-debug-XYZ.pcapng
\endverbatim
 * 
 * \ingroup protocols
 * \ref protocols
 */

#ifdef HAVE_SCTP
 
#include "sctp.h"
#include "dtls.h"
#include "janus.h"
#include "ice.h"
#include "debug.h"

#ifdef DEBUG_SCTP
/* If we're debugging the SCTP messaging, save the files here (edit path) */
const char *debug_folder = "/path/to/sctp";
#endif


#define SCTP_MAX_PACKET_SIZE (1<<16)

static uint16_t event_types[] = {
	SCTP_ASSOC_CHANGE,
	SCTP_PEER_ADDR_CHANGE,
	SCTP_REMOTE_ERROR,
	SCTP_SHUTDOWN_EVENT,
	SCTP_ADAPTATION_INDICATION,
	SCTP_SEND_FAILED_EVENT,
	SCTP_STREAM_RESET_EVENT,
	SCTP_STREAM_CHANGE_EVENT
};

int janus_sctp_data_to_dtls(void *instance, void *buffer, size_t length, uint8_t tos, uint8_t set_df);
static int janus_sctp_incoming_data(struct socket *sock, union sctp_sockstore addr, void *data, size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info);
janus_sctp_channel *janus_sctp_find_channel_by_stream(janus_sctp_association *sctp, uint16_t stream);
janus_sctp_channel *janus_sctp_find_free_channel(janus_sctp_association *sctp);
uint16_t janus_sctp_find_free_stream(janus_sctp_association *sctp);
void janus_sctp_request_more_streams(janus_sctp_association *sctp);
int janus_sctp_send_open_request_message(struct socket *sock, uint16_t stream, uint8_t unordered, uint16_t pr_policy, uint32_t pr_value);
int janus_sctp_send_open_response_message(struct socket *sock, uint16_t stream);
int janus_sctp_send_open_ack_message(struct socket *sock, uint16_t stream);
void janus_sctp_send_deferred_messages(janus_sctp_association *sctp);
int janus_sctp_open_channel(janus_sctp_association *sctp, uint8_t unordered, uint16_t pr_policy, uint32_t pr_value);
int janus_sctp_send_text(janus_sctp_association *sctp, uint16_t id, char *text, size_t length);
void janus_sctp_reset_outgoing_stream(janus_sctp_association *sctp, uint16_t stream);
void janus_sctp_send_outgoing_stream_reset(janus_sctp_association *sctp);
int janus_sctp_close_channel(janus_sctp_association *sctp, uint16_t id);
void janus_sctp_handle_open_request_message(janus_sctp_association *sctp, janus_datachannel_open_request *req, size_t length, uint16_t stream);
void janus_sctp_handle_open_response_message(janus_sctp_association *sctp, janus_datachannel_open_response *rsp, size_t length, uint16_t stream);
void janus_sctp_handle_open_ack_message(janus_sctp_association *sctp, janus_datachannel_ack *ack, size_t length, uint16_t stream);
void janus_sctp_handle_unknown_message(char *msg, size_t length, uint16_t stream);
void janus_sctp_handle_data_message(janus_sctp_association *sctp, char *buffer, size_t length, uint16_t stream);
void janus_sctp_handle_message(janus_sctp_association *sctp, char *buffer, size_t length, uint32_t ppid, uint16_t stream, int flags);
void janus_sctp_handle_association_change_event(struct sctp_assoc_change *sac);
void janus_sctp_handle_peer_address_change_event(struct sctp_paddr_change *spc);
void janus_sctp_handle_adaptation_indication(struct sctp_adaptation_event *sai);
void janus_sctp_handle_shutdown_event(struct sctp_shutdown_event *sse);
void janus_sctp_handle_stream_reset_event(janus_sctp_association *sctp, struct sctp_stream_reset_event *strrst);
void janus_sctp_handle_remote_error_event(struct sctp_remote_error *sre);
void janus_sctp_handle_send_failed_event(struct sctp_send_failed_event *ssfe);
void janus_sctp_handle_notification(janus_sctp_association *sctp, union sctp_notification *notif, size_t n);

void *janus_sctp_thread(void *data);
janus_sctp_message *janus_sctp_message_create(gboolean incoming, char *buffer, size_t length);
void janus_sctp_message_destroy(janus_sctp_message *message);
static janus_sctp_message exit_message;

static gboolean sctp_running;
int janus_sctp_init(void) {
	/* Initialize the SCTP stack */
	usrsctp_init(0, janus_sctp_data_to_dtls, NULL);
	sctp_running = TRUE;

#ifdef DEBUG_SCTP
	JANUS_LOG(LOG_WARN, "SCTP debugging to files enabled: going to save them in %s\n", debug_folder);
	if(janus_mkdir(debug_folder, 0755) < 0) {
		JANUS_LOG(LOG_ERR, "Error creating folder %s, expect problems...\n", debug_folder);
	}
#endif
	return 0;
}

void janus_sctp_deinit(void) {
	usrsctp_finish();
	sctp_running = FALSE;
}

janus_sctp_association *janus_sctp_association_create(void *dtls, uint64_t handle_id, uint16_t udp_port) {
	if(dtls == NULL || udp_port == 0)
		return NULL;
	
	/* usrsctp provides UDP encapsulation of SCTP, but we need these messages to
	 * be encapsulated in DTLS and actually sent/received by libnice, and not by
	 * usrsctp itself... as such, we make use of the AF_CONN approach */

	janus_sctp_association *sctp = (janus_sctp_association *)g_malloc0(sizeof(janus_sctp_association));
	if(sctp == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	sctp->dtls = dtls;
	sctp->handle_id = handle_id;
	sctp->local_port = 5000;	/* FIXME We always use this one */
	sctp->remote_port = udp_port;
	sctp->sock = NULL;

	struct socket *sock = NULL;
	unsigned int i = 0;
	struct sockaddr_conn sconn;

	/* Now go on with SCTP */
	janus_sctp_channel *channel = NULL;

	for(i = 0; i < NUMBER_OF_CHANNELS; i++) {
		channel = &(sctp->channels[i]);
		channel->id = i;
		channel->state = DATA_CHANNEL_CLOSED;
		channel->pr_policy = SCTP_PR_SCTP_NONE;
		channel->pr_value = 0;
		channel->stream = 0;
		channel->unordered = 0;
		channel->flags = 0;
	}
	for(i = 0; i < NUMBER_OF_STREAMS; i++) {
		sctp->stream_channel[i] = NULL;
		sctp->stream_buffer[i] = 0;
	}
	sctp->stream_buffer_counter = 0;
	sctp->sock = NULL;
	janus_mutex_init(&sctp->mutex);

	usrsctp_register_address((void *)sctp);
	usrsctp_sysctl_set_sctp_ecn_enable(0);
	if((sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, janus_sctp_incoming_data, NULL, 0, (void *)sctp)) == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error creating usrsctp socket... (%d)\n", handle_id, errno);
		g_free(sctp);
		sctp = NULL;
		return NULL;
	}
	/* Set SO_LINGER */
	struct linger linger_opt;
	linger_opt.l_onoff = 1;
	linger_opt.l_linger = 0;
	if(usrsctp_setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt))) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SO_LINGER (%d)\n", handle_id, errno);
		g_free(sctp);
		sctp = NULL;
		return NULL;
	}
	/* Allow resetting streams */
	struct sctp_assoc_value av;
	av.assoc_id = SCTP_ALL_ASSOC;
	av.assoc_value = 1;
	if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(struct sctp_assoc_value)) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_ENABLE_STREAM_RESET (%d)\n", handle_id, errno);
		g_free(sctp);
		sctp = NULL;
		return NULL;
	}
	/* Disable Nagle */
	uint32_t nodelay = 1;
	if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay))) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_NODELAY (%d)\n", handle_id, errno);
		g_free(sctp);
		sctp = NULL;
		return NULL;
	}	
	/* Enable the events of interest */
	struct sctp_event event;
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for(i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_EVENT (%d)\n", handle_id, errno);
			g_free(sctp);
			sctp = NULL;
			return NULL;
		}
	}
	/* Configure our INIT message */
	struct sctp_initmsg initmsg;
	memset(&initmsg, 0, sizeof(struct sctp_initmsg));
	initmsg.sinit_num_ostreams = 16;	/* What Firefox says in the INIT (Chrome says 1023) */
	initmsg.sinit_max_instreams = 2048;	/* What both Chrome and Firefox say in the INIT */
	if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg)) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_INITMSG (%d)\n", handle_id, errno);
		g_free(sctp);
		sctp = NULL;
		return NULL;
	}
	/* Bind our side of the communication, using AF_CONN as we're doing the actual delivery ourselves */
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
	sconn.sconn_port = htons(sctp->local_port);
	sconn.sconn_addr = (void *)sctp;
	if(usrsctp_bind(sock, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error binding client on port %"SCNu16" (%d)\n", handle_id, sctp->local_port, errno);
		g_free(sctp);
		sctp = NULL;
		return NULL;
	}

#ifdef DEBUG_SCTP
	char debug_file[1024];
	g_snprintf(debug_file, 1024, "%s/sctp-debug-%"SCNu64".txt", debug_folder, handle_id);
	sctp->debug_dump = fopen(debug_file, "wt");
#endif

	/* We're done for now, the setup is done elsewhere */
	janus_mutex_lock(&sctp->mutex);
	sctp->sock = sock;
	sctp->messages = g_async_queue_new_full((GDestroyNotify) janus_sctp_message_destroy);
	sctp->buffer = NULL;
	sctp->buflen = 0;
	sctp->offset = 0;
	GError *error = NULL;
	char tname[16];
	g_snprintf(tname, sizeof(tname), "sctp %"SCNu64, sctp->handle_id);
	sctp->thread = g_thread_try_new(tname, &janus_sctp_thread, sctp, &error);
	if(error != NULL) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the SCTP thread...\n", handle_id, error->code, error->message ? error->message : "??");
		g_async_queue_unref(sctp->messages);
		sctp->messages = NULL;
		g_free(sctp);
		sctp = NULL;
		return NULL;
	}
	janus_mutex_unlock(&sctp->mutex);
	return sctp;
}

int janus_sctp_association_setup(janus_sctp_association *sctp) {
	if(sctp == NULL)
		return -1;

	struct socket *sock = sctp->sock;
	struct sockaddr_conn sconn;

	/* Operating as client */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Connecting the SCTP association\n", sctp->handle_id);
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
	sconn.sconn_port = htons(sctp->remote_port);
	sconn.sconn_addr = (void *)sctp;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	if(usrsctp_connect(sock, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error connecting to SCTP server at port %"SCNu16" (%d)\n", sctp->handle_id, sctp->remote_port, errno);
		return -1;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Connected to the DataChannel peer\n", sctp->handle_id);

	janus_mutex_lock(&sctp->mutex);
	sctp->sock = sock;
	janus_mutex_unlock(&sctp->mutex);
	return 0;
}

void janus_sctp_association_destroy(janus_sctp_association *sctp) {
	if(sctp == NULL)
		return;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Destroying SCTP association\n", sctp->handle_id);
	usrsctp_deregister_address(sctp);
	usrsctp_shutdown(sctp->sock, SHUT_RDWR);
	usrsctp_close(sctp->sock);
	janus_mutex_lock(&sctp->mutex);
	sctp->dtls = NULL;	/* This will get rid of the thread */
	g_async_queue_push(sctp->messages, &exit_message);
	janus_mutex_unlock(&sctp->mutex);
}

void janus_sctp_data_from_dtls(janus_sctp_association *sctp, char *buf, int len) {
	if(sctp == NULL || sctp->dtls == NULL || buf == NULL || len <= 0)
		return;
	JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Data from DTLS to SCTP stack: %d bytes\n", sctp->handle_id, len);
	janus_mutex_lock(&sctp->mutex);
	if(sctp->messages != NULL)
		g_async_queue_push(sctp->messages, janus_sctp_message_create(TRUE, buf, len));
	janus_mutex_unlock(&sctp->mutex);
}

int janus_sctp_data_to_dtls(void *instance, void *buffer, size_t length, uint8_t tos, uint8_t set_df) {
	janus_sctp_association *sctp = (janus_sctp_association *)instance;
	if(sctp == NULL || sctp->dtls == NULL)
		return -1;
	JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Data from SCTP to DTLS stack: %zu bytes\n", sctp->handle_id, length);
	janus_mutex_lock(&sctp->mutex);
	if(sctp->messages != NULL)
		g_async_queue_push(sctp->messages, janus_sctp_message_create(FALSE, buffer, length));
	janus_mutex_unlock(&sctp->mutex);
	return 0;
}

static int janus_sctp_incoming_data(struct socket *sock, union sctp_sockstore addr, void *data, size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info) {
	janus_sctp_association *sctp = (janus_sctp_association *)ulp_info;
	if(sctp == NULL || sctp->dtls == NULL)
		return 0;
	if(data) {
		if(flags & MSG_NOTIFICATION) {
			janus_sctp_handle_notification(sctp, (union sctp_notification *)data, datalen);
		} else {
			janus_sctp_handle_message(sctp, data, datalen, ntohl(rcv.rcv_ppid), rcv.rcv_sid, flags);
		}
		free(data);
	}
	return 1;
}

void janus_sctp_send_data(janus_sctp_association *sctp, char *buf, int len) {
	if(sctp == NULL || buf == NULL || len <= 0)
		return;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] SCTP data to send (%d bytes) coming from a plugin: %.*s\n", sctp->handle_id, len, len, buf);
	/* FIXME Is there any open channel we can use? */
	int i = 0, found = 0;
	for(i = 0; i < NUMBER_OF_CHANNELS; i++) {
		if(sctp->channels[i].state != DATA_CHANNEL_CLOSED) {
			found = 1;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Using open channel %i\n", sctp->handle_id, i);
			break;
		}
	}
	if(!found) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Couldn't send data, channel %i is not open yet\n", sctp->handle_id, i);
		return;
		//~ /* FIXME There's no open channel (shouldn't happen, we always create it in janus.js), try opening one now */
		//~ if(janus_sctp_open_channel(sctp, 0, 0, 0) < 0) {
			//~ JANUS_LOG(LOG_ERR, "[%"SCNu64"] Couldn't open channel...\n", sctp->handle_id);
			//~ return;
		//~ }
		//~ for(i = 0; i < NUMBER_OF_CHANNELS; i++) {
			//~ if(sctp->channels[i].state != DATA_CHANNEL_CLOSED) {
				//~ found = 1;
				//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Using open channel %i\n", sctp->handle_id, i);
				//~ break;
			//~ }
		//~ }
		//~ if(!found) {
			//~ JANUS_LOG(LOG_ERR, "[%"SCNu64"] Channel opened but not found?? giving up...\n", sctp->handle_id);
			//~ return;
		//~ }
	}
	/* FIXME We're assuming this is a string (we don't support binary data yet) */
	janus_sctp_send_text(sctp, i, buf, len);
}


/* From now on, it's SCTP stuff */
janus_sctp_channel *janus_sctp_find_channel_by_stream(janus_sctp_association *sctp, uint16_t stream) {
	if(sctp == NULL)
		return NULL;
	if(stream < NUMBER_OF_STREAMS) {
		return (sctp->stream_channel[stream]);
	} else {
		return NULL;
	}
}

janus_sctp_channel *janus_sctp_find_free_channel(janus_sctp_association *sctp) {
	uint32_t i;

	for(i = 0; i < NUMBER_OF_CHANNELS; i++) {
		if(sctp->channels[i].state == DATA_CHANNEL_CLOSED) {
			break;
		}
	}
	if(i == NUMBER_OF_CHANNELS) {
		return NULL;
	} else {
		return (&(sctp->channels[i]));
	}
}

uint16_t janus_sctp_find_free_stream(janus_sctp_association *sctp) {
	struct sctp_status status;
	uint32_t i, limit;
	socklen_t len;

	len = (socklen_t)sizeof(struct sctp_status);
	if(usrsctp_getsockopt(sctp->sock, IPPROTO_SCTP, SCTP_STATUS, &status, &len) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] getsockopt error: SCTP_STATUS\n", sctp->handle_id);
		return 0;
	}
	if(status.sstat_outstrms < NUMBER_OF_STREAMS) {
		limit = status.sstat_outstrms;
	} else {
		limit = NUMBER_OF_STREAMS;
	}
	/* stream id 0 is reserved */
	for(i = 1; i < limit; i++) {
		if(sctp->stream_channel[i] == NULL) {
			break;
		}
	}
	if(i == limit) {
		return 0;
	} else {
		return ((uint16_t)i);
	}
}

void janus_sctp_request_more_streams(janus_sctp_association *sctp) {
	struct sctp_status status;
	struct sctp_add_streams sas;
	uint32_t i, streams_needed;
	socklen_t len;

	streams_needed = 0;
	for(i = 0; i < NUMBER_OF_CHANNELS; i++) {
		if((sctp->channels[i].state == DATA_CHANNEL_CONNECTING) &&
		    (sctp->channels[i].stream == 0)) {
			streams_needed++;
		}
	}
	len = (socklen_t)sizeof(struct sctp_status);
	if(usrsctp_getsockopt(sctp->sock, IPPROTO_SCTP, SCTP_STATUS, &status, &len) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] getsockopt error: SCTP_STATUS\n", sctp->handle_id);
		return;
	}
	if(status.sstat_outstrms + streams_needed > NUMBER_OF_STREAMS) {
		streams_needed = NUMBER_OF_STREAMS - status.sstat_outstrms;
	}
	if(streams_needed == 0) {
		return;
	}
	memset(&sas, 0, sizeof(struct sctp_add_streams));
	sas.sas_instrms = 0;
	sas.sas_outstrms = (uint16_t)streams_needed; /* XXX eror handling */
	if(usrsctp_setsockopt(sctp->sock, IPPROTO_SCTP, SCTP_ADD_STREAMS, &sas, (socklen_t)sizeof(struct sctp_add_streams)) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_ADD_STREAMS\n", sctp->handle_id);
	}
	return;
}

int janus_sctp_send_open_request_message(struct socket *sock, uint16_t stream, uint8_t unordered, uint16_t pr_policy, uint32_t pr_value) {
	/* XXX: This should be encoded in a better way */
	janus_datachannel_open_request *req = NULL;
	struct sctp_sndinfo sndinfo;

	/* FIXME For open requests we send, we always use this label */
	const char *label = "JanusDataChannel";
	guint label_size = (strlen(label)+3) & ~3;
	JANUS_LOG(LOG_VERB, "Using label '%s' (%zu, %u with padding)\n", label, strlen(label), label_size);

	req = g_malloc0(sizeof(janus_datachannel_open_request) + label_size);
	memset(req, 0, sizeof(janus_datachannel_open_request) + label_size);
	req->msg_type = DATA_CHANNEL_OPEN_REQUEST;
	switch (pr_policy) {
		case SCTP_PR_SCTP_NONE:
			/* XXX: What about DATA_CHANNEL_RELIABLE_STREAM */
			req->channel_type = DATA_CHANNEL_RELIABLE;
			break;
		case SCTP_PR_SCTP_TTL:
			/* XXX: What about DATA_CHANNEL_UNRELIABLE */
			req->channel_type = DATA_CHANNEL_PARTIAL_RELIABLE_TIMED;
			break;
		case SCTP_PR_SCTP_RTX:
			req->channel_type = DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT;
			break;
		default:
			return 0;
	}
	req->priority = htons(0); /* XXX: add support */
	req->reliability_params = htonl((uint32_t)pr_value);
	req->label_length = htons(label_size);
	memcpy(&req->label, label, strlen(label));

	memset(&sndinfo, 0, sizeof(struct sctp_sndinfo));
	sndinfo.snd_sid = stream;
	sndinfo.snd_flags = SCTP_EOR;
	sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_CONTROL);

	if(usrsctp_sendv(sock,
	                  req, sizeof(janus_datachannel_open_request) + label_size,
	                  NULL, 0,
	                  &sndinfo, (socklen_t)sizeof(struct sctp_sndinfo),
	                  SCTP_SENDV_SNDINFO, 0) < 0) {
		JANUS_LOG(LOG_ERR, "usrsctp_sendv error (%d)\n", errno);
		g_free(req);
		req = NULL;
		return 0;
	} else {
		g_free(req);
		req = NULL;
		return 1;
	}
}

int janus_sctp_send_open_response_message(struct socket *sock, uint16_t stream) {
	/* XXX: This should be encoded in a better way */
	janus_datachannel_open_response rsp;
	struct sctp_sndinfo sndinfo;

	memset(&rsp, 0, sizeof(janus_datachannel_open_response));
	rsp.msg_type = DATA_CHANNEL_OPEN_RESPONSE;
	rsp.error = 0;
	rsp.flags = htons(0);
	rsp.reverse_stream = htons(stream);
	memset(&sndinfo, 0, sizeof(struct sctp_sndinfo));
	sndinfo.snd_sid = stream;
	sndinfo.snd_flags = SCTP_EOR;
	sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_CONTROL);
	if(usrsctp_sendv(sock,
	                  &rsp, sizeof(janus_datachannel_open_response),
	                  NULL, 0,
	                  &sndinfo, (socklen_t)sizeof(struct sctp_sndinfo),
	                  SCTP_SENDV_SNDINFO, 0) < 0) {
		JANUS_LOG(LOG_ERR, "usrsctp_sendv error (%d)\n", errno);
		return 0;
	} else {
		return 1;
	}
}

int janus_sctp_send_open_ack_message(struct socket *sock, uint16_t stream) {
	/* XXX: This should be encoded in a better way */
	janus_datachannel_ack ack;
	struct sctp_sndinfo sndinfo;

	memset(&ack, 0, sizeof(janus_datachannel_ack));
	ack.msg_type = DATA_CHANNEL_ACK;
	memset(&sndinfo, 0, sizeof(struct sctp_sndinfo));
	sndinfo.snd_sid = stream;
	sndinfo.snd_flags = SCTP_EOR;
	sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_CONTROL);
	if(usrsctp_sendv(sock,
	                  &ack, sizeof(janus_datachannel_ack),
	                  NULL, 0,
	                  &sndinfo, (socklen_t)sizeof(struct sctp_sndinfo),
	                  SCTP_SENDV_SNDINFO, 0) < 0) {
		JANUS_LOG(LOG_ERR, "usrsctp_sendv error (%d)\n", errno);
		return 0;
	} else {
		return 1;
	}
}

void janus_sctp_send_deferred_messages(janus_sctp_association *sctp) {
	uint32_t i;
	janus_sctp_channel *channel;

	for(i = 0; i < NUMBER_OF_CHANNELS; i++) {
		channel = &(sctp->channels[i]);
		if(channel->flags & DATA_CHANNEL_FLAGS_SEND_REQ) {
			if(janus_sctp_send_open_request_message(sctp->sock, channel->stream, channel->unordered, channel->pr_policy, channel->pr_value)) {
				channel->flags &= ~DATA_CHANNEL_FLAGS_SEND_REQ;
			} else {
				if(errno != EAGAIN) {
					/* XXX: error handling */
				}
			}
		}
		if(channel->flags & DATA_CHANNEL_FLAGS_SEND_RSP) {
			if(janus_sctp_send_open_response_message(sctp->sock, channel->stream)) {
				channel->flags &= ~DATA_CHANNEL_FLAGS_SEND_RSP;
			} else {
				if(errno != EAGAIN) {
					/* XXX: error handling */
				}
			}
		}
		if(channel->flags & DATA_CHANNEL_FLAGS_SEND_ACK) {
			if(janus_sctp_send_open_ack_message(sctp->sock, channel->stream)) {
				channel->flags &= ~DATA_CHANNEL_FLAGS_SEND_ACK;
			} else {
				if(errno != EAGAIN) {
					/* XXX: error handling */
				}
			}
		}
	}
	return;
}

int janus_sctp_open_channel(janus_sctp_association *sctp, uint8_t unordered, uint16_t pr_policy, uint32_t pr_value) {
	if(sctp == NULL)
		return -1;
	janus_sctp_channel *channel;
	uint16_t stream;

	if((pr_policy != SCTP_PR_SCTP_NONE) &&
			(pr_policy != SCTP_PR_SCTP_TTL) &&
			(pr_policy != SCTP_PR_SCTP_RTX)) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid pr_policy %"SCNu32"\n", sctp->handle_id, pr_policy);
		return -1;
	}
	if((pr_policy == SCTP_PR_SCTP_NONE) && (pr_value != 0)) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid pr_value %"SCNu32" for SCTP_PR_SCTP_NONE\n", sctp->handle_id, pr_value);
		return -1;
	}
	if((channel = janus_sctp_find_free_channel(sctp)) == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No more free channels available\n", sctp->handle_id);
		return -1;
	}
	stream = janus_sctp_find_free_stream(sctp);
	channel->state = DATA_CHANNEL_CONNECTING;
	channel->unordered = unordered ? 1 : 0;
	channel->pr_policy = pr_policy;
	channel->pr_value = pr_value;
	channel->stream = stream;
	channel->flags = 0;
	if(stream == 0) {
		janus_sctp_request_more_streams(sctp);
	} else {
		if(janus_sctp_send_open_request_message(sctp->sock, stream, unordered, pr_policy, pr_value)) {
			sctp->stream_channel[stream] = channel;
		} else {
			if(errno == EAGAIN) {
				sctp->stream_channel[stream] = channel;
				channel->flags |= DATA_CHANNEL_FLAGS_SEND_REQ;
			} else {
				channel->state = DATA_CHANNEL_CLOSED;
				channel->unordered = 0;
				channel->pr_policy = 0;
				channel->pr_value = 0;
				channel->stream = 0;
				channel->flags = 0;
				channel = NULL;
			}
		}
	}
	return 0;
}

int janus_sctp_send_text(janus_sctp_association *sctp, uint16_t id, char *text, size_t length) {
	if(id >= NUMBER_OF_CHANNELS || text == NULL)
		return -1;
	struct sctp_sendv_spa spa;
	janus_sctp_channel *channel = &sctp->channels[id];
	if(channel == NULL) {
		/* No such channel */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such channel %"SCNu16"...\n", sctp->handle_id, id);
		return -1;
	}
	if((channel->state != DATA_CHANNEL_OPEN) && (channel->state != DATA_CHANNEL_CONNECTING)) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Channel %"SCNu16" is neither open nor connecting (state=%d)...\n", sctp->handle_id, id, channel->state);
		return -1;
	}

	memset(&spa, 0, sizeof(struct sctp_sendv_spa));
	spa.sendv_sndinfo.snd_sid = channel->stream;
	if((channel->state == DATA_CHANNEL_OPEN) && (channel->unordered)) {
		spa.sendv_sndinfo.snd_flags = SCTP_EOR | SCTP_UNORDERED;
	} else {
		spa.sendv_sndinfo.snd_flags = SCTP_EOR;
	}
	spa.sendv_sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_DOMSTRING);
	spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
	if((channel->pr_policy == SCTP_PR_SCTP_TTL) || (channel->pr_policy == SCTP_PR_SCTP_RTX)) {
		spa.sendv_prinfo.pr_policy = channel->pr_policy;
		spa.sendv_prinfo.pr_value = channel->pr_value;
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
	}
	if(usrsctp_sendv(sctp->sock, text, length, NULL, 0,
			&spa, (socklen_t)sizeof(struct sctp_sendv_spa),
			SCTP_SENDV_SPA, 0) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] sctp_sendv error (%d)\n", sctp->handle_id, errno);
		return -1;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Message sent on channel %"SCNu16"\n", sctp->handle_id, id); 
	return 0;
}

void janus_sctp_reset_outgoing_stream(janus_sctp_association *sctp, uint16_t stream) {
	uint32_t i;

	for(i = 0; i < sctp->stream_buffer_counter; i++) {
		if(sctp->stream_buffer[i] == stream) {
			return;
		}
	}
	sctp->stream_buffer[sctp->stream_buffer_counter++] = stream;
	return;
}

void janus_sctp_send_outgoing_stream_reset(janus_sctp_association *sctp) {
	struct sctp_reset_streams *srs;
	uint32_t i;
	size_t len;

	if(sctp->stream_buffer_counter == 0) {
		return;
	}
	len = sizeof(sctp_assoc_t) + (2 + sctp->stream_buffer_counter) * sizeof(uint16_t);
	srs = (struct sctp_reset_streams *)g_malloc0(len);
	if(srs == NULL) {
		return;
	}
	memset(srs, 0, len);
	srs->srs_flags = SCTP_STREAM_RESET_OUTGOING;
	srs->srs_number_streams = sctp->stream_buffer_counter;
	for(i = 0; i < sctp->stream_buffer_counter; i++) {
		srs->srs_stream_list[i] = sctp->stream_buffer[i];
	}
	if(usrsctp_setsockopt(sctp->sock, IPPROTO_SCTP, SCTP_RESET_STREAMS, srs, (socklen_t)len) < 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_RESET_STREAMS (%d)\n", sctp->handle_id, errno);
	} else {
		for(i = 0; i < sctp->stream_buffer_counter; i++) {
			srs->srs_stream_list[i] = 0;
		}
		sctp->stream_buffer_counter = 0;
	}
	g_free(srs);
	return;
}

int janus_sctp_close_channel(janus_sctp_association *sctp, uint16_t id) {
	if(id >= NUMBER_OF_CHANNELS)
		return -1;
	janus_sctp_channel *channel = &sctp->channels[id];
	if(channel == NULL) {
		return -1;
	}
	if(channel->state != DATA_CHANNEL_OPEN) {
		return -1;
	}
	janus_sctp_reset_outgoing_stream(sctp, channel->stream);
	janus_sctp_send_outgoing_stream_reset(sctp);
	channel->state = DATA_CHANNEL_CLOSING;
	return 0;
}

void janus_sctp_handle_open_request_message(janus_sctp_association *sctp, janus_datachannel_open_request *req, size_t length, uint16_t stream) {
	janus_sctp_channel *channel;
	uint32_t pr_value;
	uint16_t pr_policy;
	uint8_t unordered;

	if((channel = janus_sctp_find_channel_by_stream(sctp, stream))) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] channel %d is in state %d instead of CLOSED.\n", sctp->handle_id, channel->id, channel->state);
		/* XXX: some error handling */
		return;
	}
	if((channel = janus_sctp_find_free_channel(sctp)) == NULL) {
		/* XXX: some error handling */
		return;
	}
	switch (req->channel_type) {
		case DATA_CHANNEL_RELIABLE:
			pr_policy = SCTP_PR_SCTP_NONE;
			unordered = 0;
			break;
		case DATA_CHANNEL_RELIABLE_UNORDERED:
			pr_policy = SCTP_PR_SCTP_NONE;
			unordered = 1;
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED:
			pr_policy = SCTP_PR_SCTP_TTL;
			unordered = 0;
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED:
			pr_policy = SCTP_PR_SCTP_TTL;
			unordered = 1;
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT:
			pr_policy = SCTP_PR_SCTP_RTX;
			unordered = 1;
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED:
			pr_policy = SCTP_PR_SCTP_RTX;
			unordered = 1;
			break;
		default:
			pr_policy = SCTP_PR_SCTP_NONE;
			unordered = 0;
			/* FIXME Should we handle some error, here? */
			break;
	}
	pr_value = ntohs(req->reliability_params);
	channel->state = DATA_CHANNEL_CONNECTING;
	channel->unordered = unordered;
	channel->pr_policy = pr_policy;
	channel->pr_value = pr_value;
	channel->stream = stream;
	channel->flags = 0;
	sctp->stream_channel[stream] = channel;
	if(stream == 0) {
		janus_sctp_request_more_streams(sctp);
	} else {
		if(janus_sctp_send_open_ack_message(sctp->sock, stream)) {
			sctp->stream_channel[stream] = channel;
		} else {
			if(errno == EAGAIN) {
				channel->flags |= DATA_CHANNEL_FLAGS_SEND_ACK;
				sctp->stream_channel[stream] = channel;
			} else {
				/* XXX: Signal error to the other end */
				sctp->stream_channel[stream] = NULL;
				channel->state = DATA_CHANNEL_CLOSED;
				channel->unordered = 0;
				channel->pr_policy = 0;
				channel->pr_value = 0;
				channel->stream = 0;
				channel->flags = 0;
			}
		}
	}
	/* Read label, if available */
	char *label = NULL;
	guint len = ntohs(req->label_length);
	if(len > 0 && len < length) {
		label = g_malloc0(len+1);
		memcpy(label, req->label, len);
		label[len] = '\0'; 
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Opened channel '%s' (id=%"SCNu16") (%d/%d/%d)\n", sctp->handle_id,
		label ? label : "??",
		channel->stream, channel->unordered, channel->pr_policy, channel->pr_value);
	if(label)
		g_free(label);
}

void janus_sctp_handle_open_response_message(janus_sctp_association *sctp, janus_datachannel_open_response *rsp, size_t length, uint16_t stream) {
	janus_sctp_channel *channel;

	channel = janus_sctp_find_channel_by_stream(sctp, stream);
	if(channel == NULL) {
		/* XXX: improve error handling */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Can't find channel for outgoing steam %d.\n", sctp->handle_id, stream);
		return;
	}
	if(channel->state != DATA_CHANNEL_CONNECTING) {
		/* XXX: improve error handling */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Channel with id %d for outgoing steam %d is in state %d.\n", sctp->handle_id, channel->id, stream, channel->state);
		return;
	}
	if(janus_sctp_find_channel_by_stream(sctp, stream)) {
		/* XXX: improve error handling */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Channel collision for channel with id %d and streams (in/out) = (%d/%d).\n", sctp->handle_id, channel->id, stream, stream);
		return;
	}
	channel->stream = stream;
	channel->state = DATA_CHANNEL_OPEN;
	sctp->stream_channel[stream] = channel;
	if(janus_sctp_send_open_ack_message(sctp->sock, stream)) {
		channel->flags = 0;
	} else {
		channel->flags |= DATA_CHANNEL_FLAGS_SEND_ACK;
	}
	return;
}

void janus_sctp_handle_open_ack_message(janus_sctp_association *sctp, janus_datachannel_ack *ack, size_t length, uint16_t stream) {
	janus_sctp_channel *channel;

	channel = janus_sctp_find_channel_by_stream(sctp, stream);
	if(channel == NULL) {
		/* XXX: some error handling */
		JANUS_LOG(LOG_ERR, "Ops, no channel with stream %"SCNu16"?\n", stream);
		return;
	}
	if(channel->state == DATA_CHANNEL_OPEN) {
		return;
	}
	if(channel->state != DATA_CHANNEL_CONNECTING) {
		/* XXX: error handling */
		return;
	}
	channel->state = DATA_CHANNEL_OPEN;
	return;
}

void janus_sctp_handle_unknown_message(char *msg, size_t length, uint16_t stream) {
	/* XXX: Send an error message */
	return;
}

void janus_sctp_handle_data_message(janus_sctp_association *sctp, char *buffer, size_t length, uint16_t stream) {
	janus_sctp_channel *channel;

	channel = janus_sctp_find_channel_by_stream(sctp, stream);
	if(channel == NULL) {
		/* XXX: Some error handling */
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Got data from this SCTP association but there is no channel with stream %"SCNu16"...\n", sctp->handle_id, stream);
		return;
	}
	if(channel->state == DATA_CHANNEL_CONNECTING) {
		/* Implicit ACK */
		channel->state = DATA_CHANNEL_OPEN;
	}
	if(channel->state != DATA_CHANNEL_OPEN) {
		/* XXX: What about other states? */
		/* XXX: Some error handling */
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Got data from this SCTP association but channel isn't open yet...\n", sctp->handle_id);
		return;
	} else {
		/* Assuming DATA_CHANNEL_PPID_DOMSTRING */
		/* XXX: Protect for non 0 terminated buffer */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Message received of length %zu on channel with id %d: %.*s\n",
		       sctp->handle_id, length, channel->id, (int)length, buffer);
		/* FIXME: notify this to the core */
		janus_dtls_notify_data((janus_dtls_srtp *)sctp->dtls, buffer, (int)length);
	}
	return;
}

void janus_sctp_handle_message(janus_sctp_association *sctp, char *buffer, size_t length, uint32_t ppid, uint16_t stream, int flags) {
	janus_datachannel_open_request *req;
	janus_datachannel_open_response *rsp;
	janus_datachannel_ack *ack, *msg;

	switch (ppid) {
		case DATA_CHANNEL_PPID_CONTROL:
			if(length < sizeof(janus_datachannel_ack)) {
				return;
			}
			msg = (janus_datachannel_ack *)buffer;
			switch (msg->msg_type) {
				case DATA_CHANNEL_OPEN_REQUEST:
					if(length < sizeof(janus_datachannel_open_request)) {
						/* XXX: error handling? */
						return;
					}
					req = (janus_datachannel_open_request *)buffer;
					janus_sctp_handle_open_request_message(sctp, req, length, stream);
					break;
				case DATA_CHANNEL_OPEN_RESPONSE:
					if(length < sizeof(janus_datachannel_open_response)) {
						/* XXX: error handling? */
						return;
					}
					rsp = (janus_datachannel_open_response *)buffer;
					janus_sctp_handle_open_response_message(sctp, rsp, length, stream);
					break;
				case DATA_CHANNEL_ACK:
					if(length < sizeof(janus_datachannel_ack)) {
						/* XXX: error handling? */
						return;
					}
					ack = (janus_datachannel_ack *)buffer;
					janus_sctp_handle_open_ack_message(sctp, ack, length, stream);
					break;
				default:
					janus_sctp_handle_unknown_message(buffer, length, stream);
					break;
			}
			break;
		case DATA_CHANNEL_PPID_DOMSTRING:
		case DATA_CHANNEL_PPID_BINARY:
		case DATA_CHANNEL_PPID_DOMSTRING_PARTIAL:
		case DATA_CHANNEL_PPID_BINARY_PARTIAL:
			if((flags & MSG_EOR) &&
					ppid != DATA_CHANNEL_PPID_DOMSTRING_PARTIAL &&
					ppid != DATA_CHANNEL_PPID_BINARY_PARTIAL) {
				/* Message is complete, send it */
				if(sctp->offset > 0) {
					/* We buffered multiple partial messages */
					janus_sctp_handle_data_message(sctp, sctp->buffer, sctp->offset, stream);
					sctp->offset = 0;
				} else {
					/* No buffering done, send this message as it is */
					janus_sctp_handle_data_message(sctp, buffer, length, stream);
				}
			} else {
				/* Partial message, buffer only for now */
				if(length > (sctp->buflen - sctp->offset)) {
					/* (re)Allocate the buffer */
					int newlen = sctp->buflen + (length - (sctp->buflen - sctp->offset));
					sctp->buffer = g_realloc(sctp->buffer, newlen);
					sctp->buflen = newlen;
				}
				memcpy(sctp->buffer + sctp->offset, buffer, length);
				sctp->offset += length;
			}
			break;
		default:
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Message of length %zu, PPID %u on stream %u received.\n",
				   sctp->handle_id, length, ppid, stream);
			break;
	}
}

void janus_sctp_handle_association_change_event(struct sctp_assoc_change *sac) {
	unsigned int i, n;

	JANUS_LOG(LOG_VERB, "Association change ");
	switch (sac->sac_state) {
		case SCTP_COMM_UP:
			JANUS_LOG(LOG_VERB, "SCTP_COMM_UP");
			break;
		case SCTP_COMM_LOST:
			JANUS_LOG(LOG_VERB, "SCTP_COMM_LOST");
			break;
		case SCTP_RESTART:
			JANUS_LOG(LOG_VERB, "SCTP_RESTART");
			break;
		case SCTP_SHUTDOWN_COMP:
			JANUS_LOG(LOG_VERB, "SCTP_SHUTDOWN_COMP");
			break;
		case SCTP_CANT_STR_ASSOC:
			JANUS_LOG(LOG_VERB, "SCTP_CANT_STR_ASSOC");
			break;
		default:
			JANUS_LOG(LOG_VERB, "UNKNOWN");
			break;
	}
	JANUS_LOG(LOG_VERB, ", streams (in/out) = (%u/%u)",
	       sac->sac_inbound_streams, sac->sac_outbound_streams);
	n = sac->sac_length - sizeof(struct sctp_assoc_change);
	if(((sac->sac_state == SCTP_COMM_UP) ||
	     (sac->sac_state == SCTP_RESTART)) && (n > 0)) {
		JANUS_LOG(LOG_VERB, ", supports");
		for(i = 0; i < n; i++) {
			switch (sac->sac_info[i]) {
				case SCTP_ASSOC_SUPPORTS_PR:
					JANUS_LOG(LOG_VERB, " PR");
					break;
				case SCTP_ASSOC_SUPPORTS_AUTH:
					JANUS_LOG(LOG_VERB, " AUTH");
					break;
				case SCTP_ASSOC_SUPPORTS_ASCONF:
					JANUS_LOG(LOG_VERB, " ASCONF");
					break;
				case SCTP_ASSOC_SUPPORTS_MULTIBUF:
					JANUS_LOG(LOG_VERB, " MULTIBUF");
					break;
				case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
					JANUS_LOG(LOG_VERB, " RE-CONFIG");
					break;
				default:
					JANUS_LOG(LOG_VERB, " UNKNOWN(0x%02x)", sac->sac_info[i]);
					break;
			}
		}
	} else if(((sac->sac_state == SCTP_COMM_LOST) ||
	            (sac->sac_state == SCTP_CANT_STR_ASSOC)) && (n > 0)) {
		JANUS_LOG(LOG_VERB, ", ABORT =");
		for(i = 0; i < n; i++) {
			JANUS_LOG(LOG_VERB, " 0x%02x", sac->sac_info[i]);
		}
	}
	JANUS_LOG(LOG_VERB, ".\n");
	if((sac->sac_state == SCTP_CANT_STR_ASSOC) ||
			(sac->sac_state == SCTP_SHUTDOWN_COMP) ||
			(sac->sac_state == SCTP_COMM_LOST)) {
		/* FIXME Should we notify the application that data channels were lost? */
	}
	return;
}

void janus_sctp_handle_peer_address_change_event(struct sctp_paddr_change *spc) {
	char addr_buf[INET6_ADDRSTRLEN];
	const char *addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (spc->spc_aaddr.ss_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET, &sin->sin_addr, addr_buf, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, INET6_ADDRSTRLEN);
			break;
		default:
			snprintf(addr_buf, INET6_ADDRSTRLEN, "Unknown family %d", spc->spc_aaddr.ss_family);
			addr = addr_buf;
			break;
	}
	JANUS_LOG(LOG_VERB, "Peer address %s is now ", addr);
	switch (spc->spc_state) {
		case SCTP_ADDR_AVAILABLE:
			JANUS_LOG(LOG_VERB, "SCTP_ADDR_AVAILABLE");
			break;
		case SCTP_ADDR_UNREACHABLE:
			JANUS_LOG(LOG_VERB, "SCTP_ADDR_UNREACHABLE");
			break;
		case SCTP_ADDR_REMOVED:
			JANUS_LOG(LOG_VERB, "SCTP_ADDR_REMOVED");
			break;
		case SCTP_ADDR_ADDED:
			JANUS_LOG(LOG_VERB, "SCTP_ADDR_ADDED");
			break;
		case SCTP_ADDR_MADE_PRIM:
			JANUS_LOG(LOG_VERB, "SCTP_ADDR_MADE_PRIM");
			break;
		case SCTP_ADDR_CONFIRMED:
			JANUS_LOG(LOG_VERB, "SCTP_ADDR_CONFIRMED");
			break;
		default:
			JANUS_LOG(LOG_VERB, "UNKNOWN");
			break;
	}
	JANUS_LOG(LOG_VERB, " (error = 0x%08x).\n", spc->spc_error);
	return;
}

void janus_sctp_handle_adaptation_indication(struct sctp_adaptation_event *sai) {
	JANUS_LOG(LOG_VERB, "Adaptation indication: %x.\n", sai-> sai_adaptation_ind);
	return;
}

void janus_sctp_handle_shutdown_event(struct sctp_shutdown_event *sse) {
	JANUS_LOG(LOG_VERB, "Shutdown event.\n");
	/* XXX: notify all channels */
	return;
}

void janus_sctp_handle_stream_reset_event(janus_sctp_association *sctp, struct sctp_stream_reset_event *strrst) {
	uint32_t n, i;
	janus_sctp_channel *channel;

	n = (strrst->strreset_length - sizeof(struct sctp_stream_reset_event)) / sizeof(uint16_t);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Stream reset event: flags = %x, ", sctp->handle_id, strrst->strreset_flags);
	if(strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
		if(strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
			JANUS_LOG(LOG_VERB, "incoming/");
		}
		JANUS_LOG(LOG_VERB, "incoming ");
	}
	if(strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
		JANUS_LOG(LOG_VERB, "outgoing ");
	}
	JANUS_LOG(LOG_VERB, "stream ids = ");
	for(i = 0; i < n; i++) {
		if(i > 0) {
			JANUS_LOG(LOG_VERB, ", ");
		}
		JANUS_LOG(LOG_VERB, "%d", strrst->strreset_stream_list[i]);
	}
	JANUS_LOG(LOG_VERB, ".\n");	
	if(!(strrst->strreset_flags & SCTP_STREAM_RESET_DENIED) &&
	    !(strrst->strreset_flags & SCTP_STREAM_RESET_FAILED)) {
		for(i = 0; i < n; i++) {
			if(strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN ||
					strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
				channel = janus_sctp_find_channel_by_stream(sctp, strrst->strreset_stream_list[i]);
				if(channel != NULL) {
					sctp->stream_channel[channel->stream] = NULL;
					if(channel->stream == 0) {
						channel->pr_policy = SCTP_PR_SCTP_NONE;
						channel->pr_value = 0;
						channel->unordered = 0;
						channel->flags = 0;
						channel->state = DATA_CHANNEL_CLOSED;
					} else {
						if(channel->state == DATA_CHANNEL_OPEN) {
							janus_sctp_reset_outgoing_stream(sctp, channel->stream);
							channel->state = DATA_CHANNEL_CLOSING;
						} else {
							/* XXX: What to do? */
						}
					}
				}
			}
		}
	}
	return;
}

void janus_sctp_handle_remote_error_event(struct sctp_remote_error *sre) {
	size_t i, n;

	n = sre->sre_length - sizeof(struct sctp_remote_error);
	JANUS_LOG(LOG_VERB, "Remote Error (error = 0x%04x): ", sre->sre_error);
	for(i = 0; i < n; i++) {
		JANUS_LOG(LOG_VERB, " 0x%02x", sre-> sre_data[i]);
	}
	JANUS_LOG(LOG_VERB, ".\n");
	return;
}

void janus_sctp_handle_send_failed_event(struct sctp_send_failed_event *ssfe) {
	size_t i, n;

	if(ssfe->ssfe_flags & SCTP_DATA_UNSENT) {
		JANUS_LOG(LOG_VERB, "Unsent ");
	}
	if(ssfe->ssfe_flags & SCTP_DATA_SENT) {
		JANUS_LOG(LOG_VERB, "Sent ");
	}
	if(ssfe->ssfe_flags & ~(SCTP_DATA_SENT | SCTP_DATA_UNSENT)) {
		JANUS_LOG(LOG_VERB, "(flags = %x) ", ssfe->ssfe_flags);
	}
	JANUS_LOG(LOG_VERB, "message with PPID = %d, SID = %d, flags: 0x%04x due to error = 0x%08x",
	       ntohl(ssfe->ssfe_info.snd_ppid), ssfe->ssfe_info.snd_sid,
	       ssfe->ssfe_info.snd_flags, ssfe->ssfe_error);
	n = ssfe->ssfe_length - sizeof(struct sctp_send_failed_event);
	for(i = 0; i < n; i++) {
		JANUS_LOG(LOG_VERB, " 0x%02x", ssfe->ssfe_data[i]);
	}
	JANUS_LOG(LOG_VERB, ".\n");
	return;
}

void janus_sctp_handle_notification(janus_sctp_association *sctp, union sctp_notification *notif, size_t n) {
	if(notif->sn_header.sn_length != (uint32_t)n) {
		return;
	}
	switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			janus_sctp_handle_association_change_event(&(notif->sn_assoc_change));
			break;
		case SCTP_PEER_ADDR_CHANGE:
			janus_sctp_handle_peer_address_change_event(&(notif->sn_paddr_change));
			break;
		case SCTP_REMOTE_ERROR:
			janus_sctp_handle_remote_error_event(&(notif->sn_remote_error));
			break;
		case SCTP_SHUTDOWN_EVENT:
			janus_sctp_handle_shutdown_event(&(notif->sn_shutdown_event));
			break;
		case SCTP_ADAPTATION_INDICATION:
			janus_sctp_handle_adaptation_indication(&(notif->sn_adaptation_event));
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			break;
		case SCTP_AUTHENTICATION_EVENT:
			break;
		case SCTP_SENDER_DRY_EVENT:
			break;
		case SCTP_NOTIFICATIONS_STOPPED_EVENT:
			break;
		case SCTP_SEND_FAILED_EVENT:
			janus_sctp_handle_send_failed_event(&(notif->sn_send_failed_event));
			break;
		case SCTP_STREAM_RESET_EVENT:
			janus_sctp_handle_stream_reset_event(sctp, &(notif->sn_strreset_event));
			janus_sctp_send_deferred_messages(sctp);
			janus_sctp_send_outgoing_stream_reset(sctp);
			janus_sctp_request_more_streams(sctp);
			break;
		case SCTP_ASSOC_RESET_EVENT:
			break;
		case SCTP_STREAM_CHANGE_EVENT:
			break;
		default:
			break;
	}
}


void *janus_sctp_thread(void *data) {
	janus_sctp_association *sctp = (janus_sctp_association *)data;
	if(sctp == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid SCTP association, closing thread\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Starting thread for SCTP association\n", sctp->handle_id);
	janus_sctp_message *message = NULL;
	gboolean sent_data = FALSE;
	while(sctp->dtls != NULL && sctp_running) {
		/* Anything to do at all? */
		message = g_async_queue_pop(sctp->messages);
		if(message == NULL)
			continue;
		if(message == &exit_message)
			break;
		janus_mutex_lock(&sctp->mutex);
		if(sctp->dtls == NULL) {
			/* No DTLS stack anymore, we're done */
			janus_sctp_message_destroy(message);
			message = NULL;
			janus_mutex_unlock(&sctp->mutex);
			break;
		}
		/* Check incoming/outgoing messages */
		if(!message->incoming) {
#ifdef DEBUG_SCTP
			if(sctp->debug_dump != NULL) {
				/* Dump outgoing message */
				char *dump = usrsctp_dumppacket(message->buffer, message->length, SCTP_DUMP_OUTBOUND);
				if(dump != NULL) {
					fwrite(dump, sizeof(char), strlen(dump), sctp->debug_dump);
					fflush(sctp->debug_dump);
					usrsctp_freedumpbuffer(dump);
				}
			}
#endif
			/* Encapsulate this data in DTLS and send it */
			janus_dtls_send_sctp_data((janus_dtls_srtp *)sctp->dtls, message->buffer, message->length);
			janus_sctp_message_destroy(message);
			message = NULL;
			if(!sent_data)
				sent_data = TRUE;
		} else if(message->incoming && sent_data) {
#ifdef DEBUG_SCTP
			if(sctp->debug_dump != NULL) {
				/* Dump incoming message */
				char *dump = usrsctp_dumppacket(message->buffer, message->length, SCTP_DUMP_INBOUND);
				if(dump != NULL) {
					fwrite(dump, sizeof(char), strlen(dump), sctp->debug_dump);
					fflush(sctp->debug_dump);
					usrsctp_freedumpbuffer(dump);
				}
			}
#endif
			/* Pass this data to the SCTP association */
			janus_mutex_unlock(&sctp->mutex);
			usrsctp_conninput((void *)sctp, message->buffer, message->length, 0);
			janus_mutex_lock(&sctp->mutex);
		}
		janus_mutex_unlock(&sctp->mutex);
		janus_sctp_message_destroy(message);
		message = NULL;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Leaving SCTP association thread\n", sctp->handle_id);
	/* This association has been destroyed, wait a bit and then free all the resources */
	g_usleep (1*G_USEC_PER_SEC);
	g_async_queue_unref(sctp->messages);
	sctp->messages = NULL;
	sctp->thread = NULL;
#ifdef DEBUG_SCTP
	if(sctp->debug_dump != NULL)
		fclose(sctp->debug_dump);
	sctp->debug_dump = NULL;
#endif
	g_free(sctp->buffer);
	g_free(sctp);
	sctp = NULL;
	g_thread_unref(g_thread_self());
	return NULL;
}

janus_sctp_message *janus_sctp_message_create(gboolean incoming, char *buffer, size_t length) {
	if(buffer == NULL || length == 0)
		return NULL;
	janus_sctp_message *message = g_malloc0(sizeof(janus_sctp_message));
	if(message == NULL)
		return NULL;
	message->buffer = g_malloc0(length);
	if(message->buffer == NULL) {
		g_free(message);
		message = NULL;
		return NULL;
	}
	memcpy(message->buffer, buffer, length);
	message->length = length;
	message->incoming = incoming;
	return message;
}

void janus_sctp_message_destroy(janus_sctp_message *message) {
	if(message == NULL || message == &exit_message)
		return;
	if(message->buffer != NULL)
		g_free(message->buffer);
	message->buffer = NULL;
	g_free(message);
	message = NULL;
}

#endif
