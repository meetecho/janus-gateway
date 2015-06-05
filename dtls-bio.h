/*! \file    dtls-bio.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    OpenSSL BIO filter for fragmentation (headers)
 * \details  Implementation of an OpenSSL BIO filter to fix the broken
 * behaviour of fragmented packets when using mem BIOs (as we do in
 * Janus). See https://mta.openssl.org/pipermail/openssl-users/2015-June/001503.html
 * and https://github.com/meetecho/janus-gateway/issues/252 for more details. 
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#ifndef _JANUS_DTLS_BIO_H
#define _JANUS_DTLS_BIO_H

#include <openssl/err.h>
#include <openssl/ssl.h>

int janus_dtls_bio_filter_write(BIO *h, const char *buf,int num);
long janus_dtls_bio_filter_ctrl(BIO *h, int cmd, long arg1, void *arg2);
int janus_dtls_bio_filter_new(BIO *h);
int janus_dtls_bio_filter_free(BIO *data);

/*! \brief OpenSSL BIO filter for fragmentation constructor */
BIO_METHOD *BIO_janus_dtls_filter(void);

#endif
