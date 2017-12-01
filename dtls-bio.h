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

#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/*! \brief OpenSSL BIO filter for fragmentation initialization */
int janus_dtls_bio_filter_init(void);

/*! \brief OpenSSL BIO filter for fragmentation constructor */
BIO_METHOD *BIO_janus_dtls_filter(void);

/*! \brief Set the MTU for the BIO filter
 * \note The default starting MTU is 1472, in case fragmentation is needed
 * the OpenSSL DTLS stack automatically decreases it. That said, if
 * you know for sure the MTU in the network Janus is deployed in is
 * smaller than that, it makes sense to configure an according value to
 * start from
 * @param start_mtu The MTU to start from (1472 by default)
 */
void janus_dtls_bio_filter_set_mtu(int start_mtu);

#if defined(LIBRESSL_VERSION_NUMBER)
#define JANUS_USE_OPENSSL_PRE_1_1_API (1)
#else
#define JANUS_USE_OPENSSL_PRE_1_1_API (OPENSSL_VERSION_NUMBER < 0x10100000L)
#endif

#endif
