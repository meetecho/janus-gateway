/*! \file    dtls-bio.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    OpenSSL BIO filter for fragmentation
 * \details  Implementation of an OpenSSL BIO filter to fix the broken
 * behaviour of fragmented packets when using mem BIOs (as we do in
 * Janus). See https://mta.openssl.org/pipermail/openssl-users/2015-June/001503.html
 * and https://github.com/meetecho/janus-gateway/issues/252 for more details. 
 * 
 * \ingroup protocols
 * \ref protocols
 */

#include <glib.h>

#include "dtls-bio.h"
#include "debug.h"
#include "mutex.h"


/* Starting MTU value for the DTLS BIO filter */
static int mtu = 1200;
void janus_dtls_bio_filter_set_mtu(int start_mtu) {
	if(start_mtu < 0) {
		JANUS_LOG(LOG_ERR, "Invalid MTU...\n");
		return;
	}
	mtu = start_mtu;
	JANUS_LOG(LOG_VERB, "Setting starting MTU in the DTLS BIO filter: %d\n", mtu);
}

/* Filter implementation */
int janus_dtls_bio_filter_write(BIO *h, const char *buf,int num);
long janus_dtls_bio_filter_ctrl(BIO *h, int cmd, long arg1, void *arg2);
int janus_dtls_bio_filter_new(BIO *h);
int janus_dtls_bio_filter_free(BIO *data);

/* Filter initialization */
#if JANUS_USE_OPENSSL_PRE_1_1_API
static BIO_METHOD janus_dtls_bio_filter_methods = {
	BIO_TYPE_FILTER,
	"janus filter",
	janus_dtls_bio_filter_write,
	NULL,
	NULL,
	NULL,
	janus_dtls_bio_filter_ctrl,
	janus_dtls_bio_filter_new,
	janus_dtls_bio_filter_free,
	NULL
};
#else
static BIO_METHOD *janus_dtls_bio_filter_methods = NULL;
#endif
int janus_dtls_bio_filter_init(void) {
#if JANUS_USE_OPENSSL_PRE_1_1_API
	/* No initialization needed for OpenSSL pre-1.1.0 */
#else
	janus_dtls_bio_filter_methods = BIO_meth_new(BIO_TYPE_FILTER | BIO_get_new_index(), "janus filter");
	if(!janus_dtls_bio_filter_methods)
		return -1;
	BIO_meth_set_write(janus_dtls_bio_filter_methods, janus_dtls_bio_filter_write);
	BIO_meth_set_ctrl(janus_dtls_bio_filter_methods, janus_dtls_bio_filter_ctrl);
	BIO_meth_set_create(janus_dtls_bio_filter_methods, janus_dtls_bio_filter_new);
	BIO_meth_set_destroy(janus_dtls_bio_filter_methods, janus_dtls_bio_filter_free);
#endif
	return 0;
}
BIO_METHOD *BIO_janus_dtls_filter(void) {
#if JANUS_USE_OPENSSL_PRE_1_1_API
	return(&janus_dtls_bio_filter_methods);
#else
	return janus_dtls_bio_filter_methods;
#endif
}

/* Helper struct to keep the filter state */
typedef struct janus_dtls_bio_filter {
	GList *packets;
	janus_mutex mutex;
} janus_dtls_bio_filter;


int janus_dtls_bio_filter_new(BIO *bio) {
	/* Create a filter state struct */
	janus_dtls_bio_filter *filter = g_malloc0(sizeof(janus_dtls_bio_filter));
	filter->packets = NULL;
	janus_mutex_init(&filter->mutex);
	
	/* Set the BIO as initialized */
#if JANUS_USE_OPENSSL_PRE_1_1_API
	bio->init = 1;
	bio->ptr = filter;
	bio->flags = 0;
#else
	BIO_set_init(bio, 1);
	BIO_set_data(bio, filter);
#endif
	
	return 1;
}

int janus_dtls_bio_filter_free(BIO *bio) {
	if(bio == NULL)
		return 0;
		
	/* Get rid of the filter state */
#if JANUS_USE_OPENSSL_PRE_1_1_API
	janus_dtls_bio_filter *filter = (janus_dtls_bio_filter *)bio->ptr;
#else
	janus_dtls_bio_filter *filter = (janus_dtls_bio_filter *)BIO_get_data(bio);
#endif
	if(filter != NULL) {
		g_list_free(filter->packets);
		filter->packets = NULL;
		g_free(filter);
	}
#if JANUS_USE_OPENSSL_PRE_1_1_API
	bio->ptr = NULL;
	bio->init = 0;
	bio->flags = 0;
#else
	BIO_set_data(bio, NULL);
	BIO_set_init(bio, 0);
#endif
	return 1;
}
	
int janus_dtls_bio_filter_write(BIO *bio, const char *in, int inl) {
	JANUS_LOG(LOG_HUGE, "janus_dtls_bio_filter_write: %p, %d\n", in, inl);
	/* Forward data to the write BIO */
	if(inl <= 0) {
		/* ... unless the size is negative or zero */
		JANUS_LOG(LOG_WARN, "janus_dtls_bio_filter_write failed: negative size (%d)\n", inl);
		return inl;
	}
#if JANUS_USE_OPENSSL_PRE_1_1_API
	long ret = BIO_write(bio->next_bio, in, inl);
#else
	long ret = BIO_write(BIO_next(bio), in, inl);
#endif
	JANUS_LOG(LOG_HUGE, "  -- %ld\n", ret);
	
	/* Keep track of the packet, as we'll advertize them one by one after a pending check */
#if JANUS_USE_OPENSSL_PRE_1_1_API
	janus_dtls_bio_filter *filter = (janus_dtls_bio_filter *)bio->ptr;
#else
	janus_dtls_bio_filter *filter = (janus_dtls_bio_filter *)BIO_get_data(bio);
#endif
	if(filter != NULL) {
		janus_mutex_lock(&filter->mutex);
		filter->packets = g_list_append(filter->packets, GINT_TO_POINTER(ret));
		janus_mutex_unlock(&filter->mutex);
		JANUS_LOG(LOG_HUGE, "New list length: %d\n", g_list_length(filter->packets));
	}
	return ret;
}

long janus_dtls_bio_filter_ctrl(BIO *bio, int cmd, long num, void *ptr) {
	switch(cmd) {
		case BIO_CTRL_FLUSH:
			/* The OpenSSL library needs this */
			return 1;
		case BIO_CTRL_DGRAM_QUERY_MTU:
			/* Let's force the MTU that was configured */
			JANUS_LOG(LOG_HUGE, "Advertizing MTU: %d\n", mtu);
			return mtu;
		case BIO_CTRL_WPENDING:
			return 0L;
		case BIO_CTRL_PENDING: {
			/* We only advertize one packet at a time, as they may be fragmented */
#if JANUS_USE_OPENSSL_PRE_1_1_API
			janus_dtls_bio_filter *filter = (janus_dtls_bio_filter *)bio->ptr;
#else
			janus_dtls_bio_filter *filter = (janus_dtls_bio_filter *)BIO_get_data(bio);
#endif
			if(filter == NULL)
				return 0;
			janus_mutex_lock(&filter->mutex);
			if(g_list_length(filter->packets) == 0) {
				janus_mutex_unlock(&filter->mutex);
				return 0;
			}
			/* Get the first packet that hasn't been read yet */
			GList *first = g_list_first(filter->packets);
			filter->packets = g_list_remove_link(filter->packets, first);
			int pending = GPOINTER_TO_INT(first->data);
			g_list_free(first);
			janus_mutex_unlock(&filter->mutex);
			/* We return its size so that only part of the buffer is read from the write BIO */
			return pending;
		}
		default:
			JANUS_LOG(LOG_HUGE, "janus_dtls_bio_filter_ctrl: %d\n", cmd);
	}
	return 0;
}
