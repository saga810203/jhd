#ifndef JHD_TLS_HMAC_DRBG_H
#define JHD_TLS_HMAC_DRBG_H

#include <tls/jhd_tls_md_internal.h>
#include <tls/jhd_tls_sha512.h>

/*
 * Error codes
 */
#define JHD_TLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG              -0x0003  /**< Too many random requested in single call. */
#define JHD_TLS_ERR_HMAC_DRBG_INPUT_TOO_BIG                -0x0005  /**< Input too large (Entropy + additional). */
#define JHD_TLS_ERR_HMAC_DRBG_FILE_IO_ERROR                -0x0007  /**< Read/write error in file. */
#define JHD_TLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED        -0x0009  /**< The entropy source failed. */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(JHD_TLS_HMAC_DRBG_RESEED_INTERVAL)
#define JHD_TLS_HMAC_DRBG_RESEED_INTERVAL   10000   /**< Interval before reseed is performed by default */
#endif

#if !defined(JHD_TLS_HMAC_DRBG_MAX_INPUT)
#define JHD_TLS_HMAC_DRBG_MAX_INPUT         256     /**< Maximum number of additional input bytes */
#endif

#if !defined(JHD_TLS_HMAC_DRBG_MAX_REQUEST)
#define JHD_TLS_HMAC_DRBG_MAX_REQUEST       1024    /**< Maximum number of requested bytes per call */
#endif

#if !defined(JHD_TLS_HMAC_DRBG_MAX_SEED_INPUT)
#define JHD_TLS_HMAC_DRBG_MAX_SEED_INPUT    384     /**< Maximum size of (re)seed buffer */
#endif

/* \} name SECTION: Module settings */

#define JHD_TLS_HMAC_DRBG_PR_OFF   0   /**< No prediction resistance       */
#define JHD_TLS_HMAC_DRBG_PR_ON    1   /**< Prediction resistance enabled  */

/**
 * HMAC_DRBG context.
 */
typedef struct {
	unsigned char V[JHD_TLS_MD_MAX_SIZE]; /*!< V in the spec          */
	const jhd_tls_md_info_t *md_info;
	unsigned char md_ctx[sizeof(jhd_tls_sha512_context)];
	unsigned char hmac_ctx[256];

} jhd_tls_hmac_drbg_context;

void jhd_tls_hmac_drbg_seed_buf(jhd_tls_hmac_drbg_context *ctx,const jhd_tls_md_info_t * md_info,  const unsigned char *data, size_t data_len);

/**
 * \brief               HMAC_DRBG generate random
 *
 * Note: Automatically reseeds if reseed_counter is reached or PR is enabled.
 *
 * \param p_rng         HMAC_DRBG context
 * \param output        Buffer to fill
 * \param out_len       Length of the buffer
 *
 * \return              0 if successful, or
 *                      JHD_TLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      JHD_TLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG
 */
void jhd_tls_hmac_drbg_random(void *p_rng, unsigned char *output, size_t out_len);

#endif /* hmac_drbg.h */
