#ifndef JHD_TLS_CTR_DRBG_H
#define JHD_TLS_CTR_DRBG_H

#include <tls/jhd_tls_aes.h>
#include <tls/jhd_tls_entropy.h>

//#define JHD_TLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED        -0x0034  /**< The entropy source failed. */
//#define JHD_TLS_ERR_CTR_DRBG_REQUEST_TOO_BIG              -0x0036  /**< The requested random buffer length is too big. */
//#define JHD_TLS_ERR_CTR_DRBG_INPUT_TOO_BIG                -0x0038  /**< The input (entropy + additional data) is too large. */
//#define JHD_TLS_ERR_CTR_DRBG_FILE_IO_ERROR                -0x003A  /**< Read or write error in file. */
//
//#define JHD_TLS_CTR_DRBG_BLOCKSIZE          16 /**< The block size used by the cipher. */
//#define JHD_TLS_CTR_DRBG_KEYSIZE            32 /**< The key size used by the cipher. */
//#define JHD_TLS_CTR_DRBG_KEYBITS            ( JHD_TLS_CTR_DRBG_KEYSIZE * 8 ) /**< The key size for the DRBG operation, in bits. */
//#define JHD_TLS_CTR_DRBG_SEEDLEN            ( JHD_TLS_CTR_DRBG_KEYSIZE + JHD_TLS_CTR_DRBG_BLOCKSIZE ) /**< The seed length, calculated as (counter + AES key). */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them using the compiler command
 * line.
 * \{
 */

//#define JHD_TLS_CTR_DRBG_ENTROPY_LEN        48
//
//#if !defined(JHD_TLS_CTR_DRBG_RESEED_INTERVAL)
//#define JHD_TLS_CTR_DRBG_RESEED_INTERVAL    10000
///**< The interval before reseed is performed by default. */
//#endif
//
//#if !defined(JHD_TLS_CTR_DRBG_MAX_INPUT)
//#define JHD_TLS_CTR_DRBG_MAX_INPUT          256
///**< The maximum number of additional input Bytes. */
//#endif
//
//#if !defined(JHD_TLS_CTR_DRBG_MAX_REQUEST)
//#define JHD_TLS_CTR_DRBG_MAX_REQUEST        1024
///**< The maximum number of requested Bytes per call. */
//#endif
//
//#if !defined(JHD_TLS_CTR_DRBG_MAX_SEED_INPUT)
//#define JHD_TLS_CTR_DRBG_MAX_SEED_INPUT     64
///**< The maximum size of seed or reseed buffer. */
//#endif
//
///* \} name SECTION: Module settings */
//
//#define JHD_TLS_CTR_DRBG_PR_OFF             0
///**< Prediction resistance is disabled. */
//#define JHD_TLS_CTR_DRBG_PR_ON              1
///**< Prediction resistance is enabled. */

/**
 * \brief          The CTR_DRBG context structure.
 */
typedef struct {
	unsigned char counter[16]; /*!< The counter (V). */
	int reseed_counter; /*!< The reseed counter. */
	int prediction_resistance; /*!< This determines whether prediction
	 resistance is enabled, that is
	 whether to systematically reseed before
	 each random generation. */
	int reseed_interval; /*!< The reseed interval. */

	jhd_tls_aes_context aes_ctx; /*!< The AES context. */
} jhd_tls_ctr_drbg_context;

#if defined(JHD_TLS_INLINE)
#define jhd_tls_ctr_drbg_init(ctx) memset(ctx, 0, sizeof(jhd_tls_ctr_drbg_context))
#else

/**
 * \brief               This function initializes the CTR_DRBG context,
 *                      and prepares it for jhd_tls_ctr_drbg_seed()
 *                      or jhd_tls_ctr_drbg_free().
 *
 * \param ctx           The CTR_DRBG context to initialize.
 */
void jhd_tls_ctr_drbg_init(jhd_tls_ctr_drbg_context *ctx);
#endif

/**
 * \brief               This function reseeds the CTR_DRBG context, that is
 *                      extracts data from the entropy source.
 *
 * \param ctx           The CTR_DRBG context.
 */
void jhd_tls_ctr_drbg_reseed(jhd_tls_ctr_drbg_context *ctx);

/**
 * \brief   This function uses CTR_DRBG to generate random data.
 *
 * \note    The function automatically reseeds if the reseed counter is exceeded.
 *
 * \param p_rng         The CTR_DRBG context. This must be a pointer to a
 *                      #jhd_tls_ctr_drbg_context structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer(max 1024).
 *
 */
void jhd_tls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len);

void jhd_tls_random_init();

#if !defined(JHD_TLS_INLINE)
void jhd_tls_random32_with_time(unsigned char *p);
void jhd_tls_random(unsigned char* p,size_t len);

#else
#define jhd_tls_random32_with_time(p) (p)[0] = (unsigned char) (jhd_cache_time >> 24);		\
		(p)[1] = (unsigned char) (jhd_cache_time >> 16);									\
		(p)[2] = (unsigned char) (jhd_cache_time >> 8);										\
		(p)[3] = (unsigned char) (jhd_cache_time);											\
		jhd_tls_ctr_drbg_random((void*) &s_g_jhd_tls_ctr_drbg, &((p)[4]), 28);

#define jhd_tls_random(p,len)  jhd_tls_ctr_drbg_random((void*) &s_g_jhd_tls_ctr_drbg, (p),len);
#endif


extern jhd_tls_ctr_drbg_context s_g_jhd_tls_ctr_drbg;

#endif /* ctr_drbg.h */
