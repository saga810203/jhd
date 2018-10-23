#ifndef JHD_TLS_MD5_H
#define JHD_TLS_MD5_H
#include <tls/jhd_tls_config.h>
#include <stddef.h>
#include <stdint.h>



#define JHD_TLS_ERR_MD5_HW_ACCEL_FAILED                   -0x002F  /**< MD5 hardware accelerator failed */

// Regular implementation
//

/**
 * \brief          MD5 context structure
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
typedef struct {
	uint32_t total[2]; /*!< number of bytes processed  */
	uint32_t state[4]; /*!< intermediate digest state  */
	unsigned char buffer[64]; /*!< data block being processed */
} jhd_tls_md5_context;

#if !defined(JHD_TLS_INLINE)
/**
 * \brief          Initialize MD5 context
 *
 * \param ctx      MD5 context to be initialized
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md5_init(jhd_tls_md5_context *ctx);
#else
#define jhd_tls_md5_init(ctx) jhd_tls_platform_zeroize((ctx),sizeof(jhd_tls_md5_context))
#endif

/**
 * \brief          Clone (the state of) an MD5 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md5_clone( /*jhd_tls_md5_context*/void *dst, const /*jhd_tls_md5_context*/void *src);

/**
 * \brief          MD5 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md5_starts_ret( /*jhd_tls_md5_context*/void *ctx);

/**
 * \brief          MD5 process buffer
 *
 * \param ctx      MD5 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md5_update_ret( /*jhd_tls_md5_context*/void *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief          MD5 final digest
 *
 * \param ctx      MD5 context
 * \param output   MD5 checksum result
 *
 * \return         0 if successful
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md5_finish_ret( /*jhd_tls_md5_context*/ void *ctx, unsigned char output[16]);

/**
 * \brief          MD5 process data block (internal use only)
 *
 * \param ctx      MD5 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_internal_md5_process( /*jhd_tls_md5_context*/ void *ctx, const unsigned char data[64]);

/**
 * \brief          Output = MD5( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD5 checksum result
 *
 * \return         0 if successful
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md5_ret(const unsigned char *input, size_t ilen, unsigned char output[16]);

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int jhd_tls_md5_self_test(int verbose);
#endif /* jhd_tls_md5.h */
