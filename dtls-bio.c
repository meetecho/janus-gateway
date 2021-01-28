/*! \file    dtls-bio.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    OpenSSL BIO agent writer
 * \details  OpenSSL BIO that writes packets to a libnice agent.
 *
 * \ingroup protocols
 * \ref protocols
 */

#include <glib.h>

#include "dtls-bio.h"
#include "debug.h"
#include "ice.h"
#include "mutex.h"

/* Starting MTU value for the DTLS BIO agent writer */
static int mtu = 1200;
void janus_dtls_bio_agent_set_mtu(int start_mtu) {
	if(start_mtu < 0) {
		JANUS_LOG(LOG_ERR, "Invalid MTU...\n");
		return;
	}
	mtu = start_mtu;
	JANUS_LOG(LOG_VERB, "Setting starting MTU in the DTLS BIO writer: %d\n", mtu);
}
int janus_dtls_bio_agent_get_mtu(void) {
	return mtu;
}

/* BIO implementation */
static int janus_dtls_bio_agent_write(BIO *h, const char *buf, int num);
static long janus_dtls_bio_agent_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int janus_dtls_bio_agent_new(BIO *h);
static int janus_dtls_bio_agent_free(BIO *data);

/* BIO initialization */
#if JANUS_USE_OPENSSL_PRE_1_1_API
static BIO_METHOD janus_dtls_bio_agent_methods = {
	BIO_TYPE_BIO,
	"janus agent writer",
	janus_dtls_bio_agent_write,
	NULL,
	NULL,
	NULL,
	janus_dtls_bio_agent_ctrl,
	janus_dtls_bio_agent_new,
	janus_dtls_bio_agent_free,
	NULL
};
#else
static BIO_METHOD *janus_dtls_bio_agent_methods = NULL;
#endif
int janus_dtls_bio_agent_init(void) {
#if JANUS_USE_OPENSSL_PRE_1_1_API
	/* No initialization needed for OpenSSL pre-1.1.0 */
#else
	janus_dtls_bio_agent_methods = BIO_meth_new(BIO_TYPE_BIO, "janus agent writer");
	if(!janus_dtls_bio_agent_methods) {
		return -1;
	}
	BIO_meth_set_write(janus_dtls_bio_agent_methods, janus_dtls_bio_agent_write);
	BIO_meth_set_ctrl(janus_dtls_bio_agent_methods, janus_dtls_bio_agent_ctrl);
	BIO_meth_set_create(janus_dtls_bio_agent_methods, janus_dtls_bio_agent_new);
	BIO_meth_set_destroy(janus_dtls_bio_agent_methods, janus_dtls_bio_agent_free);
#endif
	return 0;
}

static BIO_METHOD *BIO_janus_dtls_agent_method(void) {
#if JANUS_USE_OPENSSL_PRE_1_1_API
	return(&janus_dtls_bio_agent_methods);
#else
	return janus_dtls_bio_agent_methods;
#endif
}

BIO *BIO_janus_dtls_agent_new(void *dtls) {
	BIO* bio = BIO_new(BIO_janus_dtls_agent_method());
	if(bio == NULL) {
		return NULL;
	}
#if JANUS_USE_OPENSSL_PRE_1_1_API
	bio->ptr = dtls;
#else
	BIO_set_data(bio, dtls);
#endif
	return bio;
}

static int janus_dtls_bio_agent_new(BIO *bio) {
#if JANUS_USE_OPENSSL_PRE_1_1_API
	bio->init = 1;
	bio->ptr = NULL;
	bio->flags = 0;
#else
	BIO_set_init(bio, 1);
	BIO_set_data(bio, NULL);
	BIO_set_shutdown(bio, 0);
#endif
	return 1;
}

static int janus_dtls_bio_agent_free(BIO *bio) {
	if(bio == NULL) {
		return 0;
	}
#if JANUS_USE_OPENSSL_PRE_1_1_API
	bio->ptr = NULL;
#else
	BIO_set_data(bio, NULL);
#endif
	return 1;
}

static int janus_dtls_bio_agent_write(BIO *bio, const char *in, int inl) {
	JANUS_LOG(LOG_HUGE, "janus_dtls_bio_agent_write: %p, %d\n", in, inl);
	/* Forward data to the write BIO */
	if(inl <= 0) {
		/* ... unless the size is negative or zero */
		JANUS_LOG(LOG_WARN, "janus_dtls_bio_agent_write failed: negative size (%d)\n", inl);
		return inl;
	}
	janus_dtls_srtp *dtls;
#if JANUS_USE_OPENSSL_PRE_1_1_API
	dtls = (janus_dtls_srtp *)bio->ptr;
#else
	dtls = (janus_dtls_srtp *)BIO_get_data(bio);
#endif
	if(dtls == NULL) {
		JANUS_LOG(LOG_ERR, "No DTLS-SRTP stack, no DTLS bridge...\n");
		return -1;
	}
	janus_ice_component *component = (janus_ice_component *)dtls->component;
	if(component == NULL) {
		JANUS_LOG(LOG_ERR, "No component, no DTLS bridge...\n");
		return -1;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No stream, no DTLS bridge...\n");
		return -1;
	}
	janus_ice_handle *handle = stream->handle;
	if(!handle || !handle->agent || !dtls->write_bio) {
		JANUS_LOG(LOG_ERR, "No handle/agent/bio, no DTLS bridge...\n");
		return -1;
	}

	if(inl > 1500) {
		/* FIXME Just a warning for now, this will need to be solved with proper fragmentation */
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] The DTLS stack is trying to send a packet of %d bytes, this may be larger than the MTU and get dropped!\n", handle->handle_id, inl);
	}
	int bytes = nice_agent_send(handle->agent, component->stream_id, component->component_id, inl, in);
	if(bytes < inl) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error sending DTLS message on component %d of stream %d (%d)\n", handle->handle_id, component->component_id, stream->stream_id, bytes);
	} else {
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] >> >> ... and sent %d of those bytes on the socket\n", handle->handle_id, bytes);
	}
	/* Update stats (TODO Do the same for the last second window as well)
	 * FIXME: the Data stats includes the bytes used for the handshake */
	if(bytes > 0) {
		component->out_stats.data.packets++;
		component->out_stats.data.bytes += bytes;
	}
	return bytes;
}

static long janus_dtls_bio_agent_ctrl(BIO *bio, int cmd, long num, void *ptr) {
	switch(cmd) {
		case BIO_CTRL_FLUSH:
			/* The OpenSSL library needs this */
			return 1;
		case BIO_CTRL_DGRAM_QUERY_MTU:
			/* Let's force the MTU that was configured */
			JANUS_LOG(LOG_HUGE, "Advertizing MTU: %d\n", mtu);
			return mtu;
		case BIO_CTRL_WPENDING:
		case BIO_CTRL_PENDING:
			return 0L;
		default:
			JANUS_LOG(LOG_HUGE, "janus_dtls_bio_agent_ctrl: %d\n", cmd);
	}
	return 0;
}
