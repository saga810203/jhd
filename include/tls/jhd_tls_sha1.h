#ifndef JHD_TLS_SHA1_H
#define JHD_TLS_SHA1_H

#include <tls/jhd_tls_config.h>

#include <stddef.h>
#include <stdint.h>

#define JHD_TLS_ERR_SHA1_HW_ACCEL_FAILED                  -0x0035  /**< SHA-1 hardware accelerator failed */

// Regular implementation
//

/**
 * \brief          The SHA-1 context structure.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
typedef struct {
	uint32_t total[2]; /*!< The number of Bytes processed.  */
	uint32_t state[5]; /*!< The intermediate digest state.  */
	unsigned char buffer[64]; /*!< The data block being processed. */
} jhd_tls_sha1_context;

#if !defined(JHD_TLS_INLINE)
/**
 * \brief          This function initializes a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to initialize.
 *
 */
void jhd_tls_sha1_init(jhd_tls_sha1_context *ctx);

#else
#define jhd_tls_sha1_init(ctx) jhd_tls_platform_zeroize((ctx),sizeof(jhd_tls_sha1_context))

#endif

/**
 * \brief          This function clones the state of a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param dst      The SHA-1 context to clone to.
 * \param src      The SHA-1 context to clone from.
 *
 */
void jhd_tls_sha1_clone( /*jhd_tls_sha1_context*/void *dst, const /*jhd_tls_sha1_context*/void *src);

/**
 * \brief          This function starts a SHA-1 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to initialize.
 *
 * \return         \c 0 on success.
 *
 */
void jhd_tls_sha1_starts_ret( /*jhd_tls_sha1_context*/void *ctx);

/**
 * \brief          This function feeds an input buffer into an ongoing SHA-1
 *                 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha1_update_ret( /*jhd_tls_sha1_context*/void *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief          This function finishes the SHA-1 operation, and writes
 *                 the result to the output buffer.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context.
 * \param output   The SHA-1 checksum result.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha1_finish_ret( /*jhd_tls_sha1_context*/void *ctx, unsigned char output[20]);

/**
 * \brief          SHA-1 process data block (internal use only).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context.
 * \param data     The data block being processed.
 *
 * \return         \c 0 on success.
 *
 */
void jhd_tls_internal_sha1_process( /*jhd_tls_sha1_context*/void *ctx, const unsigned char data[64]);

/**
 * \brief          This function calculates the SHA-1 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-1 result is calculated as
 *                 output = SHA-1(input buffer).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-1 checksum result.
 *
 * \return         \c 0 on success.
 *
 */
void jhd_tls_sha1_ret(const unsigned char *input, size_t ilen, unsigned char output[20]);

/**
 * \brief          The SHA-1 checkup routine.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 *
 */
int jhd_tls_sha1_self_test(int verbose);

#endif /* jhd_tls_sha1.h */
