#ifndef JHD_TLS_SHA512_H
#define JHD_TLS_SHA512_H

#include <tls/jhd_tls_config.h>

#include <stddef.h>
#include <stdint.h>

#define JHD_TLS_ERR_SHA512_HW_ACCEL_FAILED                -0x0039  /**< SHA-512 hardware accelerator failed */

// Regular implementation
//

/**
 * \brief          The SHA-512 context structure.
 *
 *                 The structure is used both for SHA-384 and for SHA-512
 *                 checksum calculations. The choice between these two is
 *                 made in the call to jhd_tls_sha512_starts_ret().
 */
typedef struct {
	uint64_t total[2]; /*!< The number of Bytes processed. */
	uint64_t state[8]; /*!< The intermediate digest state. */
	unsigned char buffer[128]; /*!< The data block being processed. */
	unsigned char is384; /*!< Determines which function to use:
	 0: Use SHA-512, or 1: Use SHA-384. */
} jhd_tls_sha512_context;

#if !defined(JHD_TLS_INLINE)
/**
 * \brief          This function initializes a SHA-512 context.
 *
 * \param ctx      The SHA-512 context to initialize.
 */
void jhd_tls_sha512_init(jhd_tls_sha512_context *ctx);
#else
#define jhd_tls_sha512_init(ctx) (jhd_tls_platform_zeroize(ctx,sizeof(jhd_tls_sha512_context)))
#endif

/**
 * \brief          This function clones the state of a SHA-512 context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void jhd_tls_sha512_clone( /*jhd_tls_sha512_context*/void *dst, const /*jhd_tls_sha512_context*/void *src);

/**
 * \brief          This function starts a SHA-384 or SHA-512 checksum
 *                 calculation.Use SHA-384.
 *
 * \param ctx      The SHA-512 context to initialize.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha512_starts_ret_with_384( /*jhd_tls_sha512_context*/void *ctx);

/**
 * \brief          This function starts a SHA-384 or SHA-512 checksum
 *                 calculation.Use SHA-512
 *
 * \param ctx      The SHA-512 context to initialize.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha512_starts_ret( /*jhd_tls_sha512_context*/void *ctx);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-512 checksum calculation.
 *
 * \param ctx      The SHA-512 context.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha512_update_ret( /*jhd_tls_sha512_context*/void *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief          This function finishes the SHA-512 operation, and writes
 *                 the result to the output buffer. This function is for
 *                 internal use only.
 *
 * \param ctx      The SHA-512 context.
 * \param output   The SHA-384 or SHA-512 checksum result.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha512_finish_ret( /*jhd_tls_sha512_context*/void *ctx, unsigned char output[64]);

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SHA-512 computation.
 *
 * \param ctx      The SHA-512 context.
 * \param data     The buffer holding one block of data.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_internal_sha512_process( /*jhd_tls_sha512_context*/void *ctx, const unsigned char data[128]);

/**
 * \brief          This function calculates the SHA-512 or SHA-384
 *                 checksum of a buffer.Use SHA-512
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-512 result is calculated as
 *                 output = SHA-512(input buffer).
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-384 or SHA-512 checksum result.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha512_ret(const unsigned char *input, size_t ilen, unsigned char output[64]);

/**
 * \brief          This function calculates the SHA-512 or SHA-384
 *                 checksum of a buffer. Use SHA-384.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-512 result is calculated as
 *                 output = SHA-512(input buffer).
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-384 or SHA-512 checksum result.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_sha512_ret_with_384(const unsigned char *input, size_t ilen, unsigned char output[64]);

/**
 * \brief          The SHA-384 or SHA-512 checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int jhd_tls_sha512_self_test(int verbose);

#endif /* jhd_tls_sha512.h */
