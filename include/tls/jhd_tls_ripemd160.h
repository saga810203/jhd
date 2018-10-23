#ifndef JHD_TLS_RIPEMD160_H
#define JHD_TLS_RIPEMD160_H

#include <tls/jhd_tls_config.h>

#include <stddef.h>
#include <stdint.h>

#define JHD_TLS_ERR_RIPEMD160_HW_ACCEL_FAILED             -0x0031  /**< RIPEMD160 hardware accelerator failed */

// Regular implementation
//

/**
 * \brief          RIPEMD-160 context structure
 */
typedef struct {
	uint32_t total[2]; /*!< number of bytes processed  */
	uint32_t state[5]; /*!< intermediate digest state  */
	unsigned char buffer[64]; /*!< data block being processed */
} jhd_tls_ripemd160_context;

#if !defined(JHD_TLS_INLINE)
/**
 * \brief          Initialize RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be initialized
 */
void jhd_tls_ripemd160_init(jhd_tls_ripemd160_context *ctx);
#else
#define jhd_tls_ripemd160_init(ctx) (jhd_tls_platform_zeroize(ctx,sizeof(jhd_tls_ripemd160_context)))
#endif

/**
 * \brief          Clone (the state of) an RIPEMD-160 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void jhd_tls_ripemd160_clone(/*jhd_tls_ripemd160_context*/ void *dst, const /*jhd_tls_ripemd160_context*/ void *src);

/**
 * \brief          RIPEMD-160 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 */
void jhd_tls_ripemd160_starts_ret(/*jhd_tls_ripemd160_context*/ void *ctx);

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 */
void jhd_tls_ripemd160_update_ret(/*jhd_tls_ripemd160_context*/ void *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief          RIPEMD-160 final digest
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
void jhd_tls_ripemd160_finish_ret(/*jhd_tls_ripemd160_context*/ void *ctx, unsigned char output[20]);

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 */
void jhd_tls_internal_ripemd160_process(/*jhd_tls_ripemd160_context*/ void *ctx, const unsigned char data[64]);


/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
void jhd_tls_ripemd160_ret(const unsigned char *input, size_t ilen, unsigned char output[20]);


/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int jhd_tls_ripemd160_self_test(int verbose);



#endif /* jhd_tls_ripemd160.h */
