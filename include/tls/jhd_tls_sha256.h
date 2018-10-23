#ifndef JHD_TLS_SHA256_H
#define JHD_TLS_SHA256_H

#include <tls/jhd_tls_config.h>

#include <stddef.h>
#include <stdint.h>

#define JHD_TLS_ERR_SHA256_HW_ACCEL_FAILED                -0x0037  /**< SHA-256 hardware accelerator failed */

// Regular implementation
//

/**
 * \brief          The SHA-256 context structure.
 *
 *                 The structure is used both for SHA-256 and for SHA-224
 *                 checksum calculations. The choice between these two is
 *                 made in the call to jhd_tls_sha256_starts_ret().
 */
typedef struct {
	uint32_t total[2]; /*!< The number of Bytes processed.  */
	uint32_t state[8]; /*!< The intermediate digest state.  */
	unsigned char buffer[64]; /*!< The data block being processed. */
	unsigned char is224; /*!< Determines which function to use:
	 0: Use SHA-256, or 1: Use SHA-224. */
} jhd_tls_sha256_context;

#if !defined(JHD_TLS_INLINE)
/**
 * \brief          This function initializes a SHA-256 context.
 *
 * \param ctx      The SHA-256 context to initialize.
 */
void jhd_tls_sha256_init(jhd_tls_sha256_context *ctx);
#else
#define jhd_tls_sha256_init(ctx) (jhd_tls_platform_zeroize(ctx,sizeof(jhd_tls_sha256_context)))
#endif
/**
 * \brief          This function clones the state of a SHA-256 context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void jhd_tls_sha256_clone(/*jhd_tls_sha256_context*/ void *dst, const /*jhd_tls_sha256_context*/ void *src);

/**
 * \brief          This function starts a SHA-224 or SHA-256 checksum
 *                 calculation.Use SHA-224.
 *
 * \param ctx      The context to initialize.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha256_starts_ret_with_224(/*jhd_tls_sha256_context*/ void *ctx);

/**
 * \brief          This function starts a SHA-224 or SHA-256 checksum
 *                 calculation.Use SHA-256
 *
 * \param ctx      The context to initialize.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha256_starts_ret_with_256(/*jhd_tls_sha256_context*/ void *ctx);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-256 checksum calculation.
 *
 * \param ctx      The SHA-256 context.
 * \param input    The buffer holding the data.
 * \param ilen     The length of the input data.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha256_update_ret(/*jhd_tls_sha256_context*/ void *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief          This function finishes the SHA-256 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-256 context.
 * \param output   The SHA-224 or SHA-256 checksum result.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha256_finish_ret(/*jhd_tls_sha256_context*/ void *ctx, unsigned char output[32]);

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SHA-256 computation. This function is for
 *                 internal use only.
 *
 * \param ctx      The SHA-256 context.
 * \param data     The buffer holding one block of data.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_internal_sha256_process(/*jhd_tls_sha256_context*/ void *ctx, const unsigned char data[64]);



/**
 * \brief          This function calculates the SHA-224 or SHA-256
 *                 checksum of a buffer.Use SHA-224
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-256 result is calculated as
 *                 output = SHA-256(input buffer).
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-224 or SHA-256 checksum result.
 */
void jhd_tls_sha256_ret_with_224(const unsigned char *input, size_t ilen, unsigned char output[32] );

/**
 * \brief          This function calculates the SHA-224 or SHA-256
 *                 checksum of a buffer.Use SHA-256
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-256 result is calculated as
 *                 output = SHA-256(input buffer).
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-224 or SHA-256 checksum result.
 */
void jhd_tls_sha256_ret_with_256(const unsigned char *input, size_t ilen, unsigned char output[32] );


/**
 * \brief          The SHA-224 and SHA-256 checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int jhd_tls_sha256_self_test(int verbose);

#endif /* jhd_tls_sha256.h */
