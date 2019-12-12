/*! \file    rtpsrtp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SRTP definitions (headers)
 * \details  Definitions of the SRTP usage. This header tries to abstract
 * the differences there may be between libsrtp and libsrtp2, with respect
 * to the structs and defines (e.g., errors), plus adding some helpers.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_RTPSRTP_H
#define JANUS_RTPSRTP_H

#ifdef HAVE_SRTP_2
#include <srtp2/srtp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/srtp.h>
int srtp_crypto_get_random(uint8_t *key, int len);
#else
#include <srtp/srtp.h>
#include <srtp/crypto_kernel.h>
#define srtp_err_status_t err_status_t
#define srtp_err_status_ok err_status_ok
#define srtp_err_status_replay_fail err_status_replay_fail
#define srtp_err_status_replay_old err_status_replay_old
#define srtp_crypto_policy_set_rtp_default crypto_policy_set_rtp_default
#define srtp_crypto_policy_set_rtcp_default crypto_policy_set_rtcp_default
#define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32 crypto_policy_set_aes_cm_128_hmac_sha1_32
#define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80 crypto_policy_set_aes_cm_128_hmac_sha1_80
#define srtp_crypto_policy_set_aes_gcm_256_16_auth crypto_policy_set_aes_gcm_256_16_auth
#define srtp_crypto_policy_set_aes_gcm_128_16_auth crypto_policy_set_aes_gcm_128_16_auth
#define srtp_crypto_get_random crypto_get_random
#endif

/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
#define SRTP_MASTER_KEY_LENGTH	16
#define SRTP_MASTER_SALT_LENGTH	14
#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)
/* AES-GCM stuff (http://tools.ietf.org/html/rfc7714) */
#define SRTP_AESGCM128_MASTER_KEY_LENGTH	16
#define SRTP_AESGCM128_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM128_MASTER_LENGTH (SRTP_AESGCM128_MASTER_KEY_LENGTH + SRTP_AESGCM128_MASTER_SALT_LENGTH)
#define SRTP_AESGCM256_MASTER_KEY_LENGTH	32
#define SRTP_AESGCM256_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM256_MASTER_LENGTH (SRTP_AESGCM256_MASTER_KEY_LENGTH + SRTP_AESGCM256_MASTER_SALT_LENGTH)

/* SRTP profiles */
typedef enum janus_srtp_profile {
	JANUS_SRTP_AES128_CM_SHA1_32 = 1,
	JANUS_SRTP_AES128_CM_SHA1_80,
	JANUS_SRTP_AEAD_AES_128_GCM,
	JANUS_SRTP_AEAD_AES_256_GCM
} janus_srtp_profile;

#ifndef SRTP_AEAD_AES_256_GCM
	#undef HAVE_SRTP_AESGCM
#endif

/*! \brief Helper method to get a string representation of a libsrtp error code
 * @param[in] error The libsrtp error code
 * @returns A string representation of the error code */
const char *janus_srtp_error_str(int error);

#endif
