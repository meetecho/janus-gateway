/*! \file    dtls-bio.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    OpenSSL BIO agent writer
 * \details  OpenSSL BIO that writes packets to a libnice agent.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_DTLS_BIO_H
#define JANUS_DTLS_BIO_H

#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/*! \brief OpenSSL BIO agent writer initialization */
int janus_dtls_bio_agent_init(void);

/*! \brief OpenSSL BIO agent writer constructor */
BIO *BIO_janus_dtls_agent_new(void *dtls);

/*! \brief Set the MTU for the BIO agent writer
 * \note The default starting MTU is 1472, in case fragmentation is needed
 * the OpenSSL DTLS stack automatically decreases it. That said, if
 * you know for sure the MTU in the network Janus is deployed in is
 * smaller than that, it makes sense to configure an according value to
 * start from
 * @param start_mtu The MTU to start from (1472 by default)
 */
void janus_dtls_bio_agent_set_mtu(int start_mtu);

#if defined(LIBRESSL_VERSION_NUMBER)
#define JANUS_USE_OPENSSL_PRE_1_1_API (1)
#else
#define JANUS_USE_OPENSSL_PRE_1_1_API (OPENSSL_VERSION_NUMBER < 0x10100000L)
#endif

#endif
