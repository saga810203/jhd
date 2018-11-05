#ifndef JHD_TLS_MD_H
#define JHD_TLS_MD_H

#include <stddef.h>

#include <tls/jhd_tls_config.h>

/*
 * Supported Signature and Hash algorithms (For TLS 1.2)
 * RFC 5246 section 7.4.1.4.1
 */

#define JHD_TLS_SSL_HASH_NONE                0
#define JHD_TLS_SSL_HASH_MD5                 1
#define JHD_TLS_SSL_HASH_SHA1                2
#define JHD_TLS_SSL_HASH_SHA224              3
#define JHD_TLS_SSL_HASH_SHA256              4
#define JHD_TLS_SSL_HASH_SHA384              5
#define JHD_TLS_SSL_HASH_SHA512              6


#define JHD_TLS_ERR_MD_FEATURE_UNAVAILABLE                -0x5080  /**< The selected feature is not available. */
#define JHD_TLS_ERR_MD_BAD_INPUT_DATA                     -0x5100  /**< Bad input parameters to function. */
#define JHD_TLS_ERR_MD_ALLOC_FAILED                       -0x5180  /**< Failed to allocate memory. */
#define JHD_TLS_ERR_MD_FILE_IO_ERROR                      -0x5200  /**< Opening or reading of file failed. */
#define JHD_TLS_ERR_MD_HW_ACCEL_FAILED                    -0x5280  /**< MD hardware accelerator failed. */



#define JHD_TLS_MD_CONTEXT_DEFINE(var)  unsigned char var[sizeof(jhd_tls_sha512_context)];




///**
// * \brief     Supported message digests.
// *
// * \warning   MD2, MD4, MD5 and SHA-1 are considered weak message digests and
// *            their use constitutes a security risk. We recommend considering
// *            stronger message digests instead.
// *
// */
//typedef enum {
//	JHD_TLS_MD_NONE = 0, /**< None. */
//	JHD_TLS_MD_MD2, /**< The MD2 message digest. */
//	JHD_TLS_MD_MD4, /**< The MD4 message digest. */
//	JHD_TLS_MD_MD5, /**< The MD5 message digest. */
//	JHD_TLS_MD_SHA1, /**< The SHA-1 message digest. */
//	JHD_TLS_MD_SHA224, /**< The SHA-224 message digest. */
//	JHD_TLS_MD_SHA256, /**< The SHA-256 message digest. */
//	JHD_TLS_MD_SHA384, /**< The SHA-384 message digest. */
//	JHD_TLS_MD_SHA512, /**< The SHA-512 message digest. */
//	JHD_TLS_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
//} jhd_tls_md_type_t;

#define JHD_TLS_MD_MAX_SIZE         64  /* longest known is SHA512 */

/**
 * Opaque struct defined in md_internal.h.
 */
typedef struct jhd_tls_md_info_t jhd_tls_md_info_t;


#if !defined(JHD_TLS_INLINE)




/**
 * \brief           This function extracts the message-digest size from the
 *                  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 *
 * \return          The size of the message-digest output in Bytes.
 */
uint8_t jhd_tls_md_get_size(const jhd_tls_md_info_t *md_info);

/**
 * \brief           This function extracts the message-digest name from the
 *                  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 *
 * \return          The name of the message digest.
 */
const char *jhd_tls_md_get_name(const jhd_tls_md_info_t *md_info);








/**
 * \brief           This function starts a message-digest computation.
 *
 *                  You must call this function after setting up the context
 *                  with jhd_tls_md_setup(), and before passing data with
 *                  jhd_tls_md_update().
 *
 * \param ctx       The generic message-digest context.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
void jhd_tls_md_starts(jhd_tls_md_info_t *md_info,void *md_ctx);

/**
 * \brief           This function feeds an input buffer into an ongoing
 *                  message-digest computation.
 *
 *                  You must call jhd_tls_md_starts() before calling this
 *                  function. You may call this function multiple times.
 *                  Afterwards, call jhd_tls_md_finish().
 *
 * \param ctx       The generic message-digest context.
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
void jhd_tls_md_update(jhd_tls_md_info_t *md_info,void *md_ctx, const unsigned char *input, size_t ilen);

/**
 * \brief           This function finishes the digest operation,
 *                  and writes the result to the output buffer.
 *
 *                  Call this function after a call to jhd_tls_md_starts(),
 *                  followed by any number of calls to jhd_tls_md_update().
 *                  Afterwards, you may either clear the context with
 *                  jhd_tls_md_free(), or call jhd_tls_md_starts() to reuse
 *                  the context for another digest operation with the same
 *                  algorithm.
 *
 * \param ctx       The generic message-digest context.
 * \param output    The buffer for the generic message-digest checksum result.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
void jhd_tls_md_finish(jhd_tls_md_info_t *md_info,void *md_ctx, unsigned char *output);

/**
 * \brief          This function calculates the message-digest of a buffer,
 *                 with respect to a configurable message-digest algorithm
 *                 in a single call.
 *
 *                 The result is calculated as
 *                 Output = message_digest(input buffer).
 *
 * \param md_info  The information structure of the message-digest algorithm
 *                 to use.
 * \param input    The buffer holding the data.
 * \param ilen     The length of the input data.
 * \param output   The generic message-digest checksum result.
 *
 * \return         \c 0 on success.
 * \return         #JHD_TLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                 failure.
 */
void jhd_tls_md(const jhd_tls_md_info_t *md_info, const unsigned char *input, size_t ilen, unsigned char *output);

/* Internal use */
void jhd_tls_md_process(jhd_tls_md_info_t *md_info,void *md_ctx, const unsigned char *data);

#else


#define jhd_tls_md_starts(MI,MC) (MI)->starts_func(MC)

#define jhd_tls_md_update(MI,MC,input,ilen )  (MI)->update_func(MC, input, ilen)

#define jhd_tls_md_finish(MI,MC,output) (MI)->finish_func(MC, output)

#define jhd_tls_md(md_info,input,ilen,output)   (((jhd_tls_md_info_t*)md_info)->digest_func(input, ilen, output))

#define jhd_tls_md_process(MI,MC,data)  (MI)->process_func(MC, data))


#define jhd_tls_md_get_size(md_info)  (md_info)->size


#define jhd_tls_md_get_name(md_info) (NULL==(md_info)?(JHD_TLS_MD_NONE):((jhd_tls_md_info_t*)(md_info))->name)
#endif




void jhd_tls_md_hmac(const jhd_tls_md_info_t *md_info, const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char *output);



void jhd_tls_md_hmac_init(const jhd_tls_md_info_t *md_info,const unsigned char *key, size_t keylen,unsigned char *hmac_ctx);


#if !defined(JHD_TLS_INLINE)

void jhd_tls_md_hmac_starts(const jhd_tls_md_info_t *md_info,void *md_ctx,unsigned char *hmac_ctx);
void jhd_tls_md_hmac_update(const jhd_tls_md_info_t *md_info,void *md_ctx,const unsigned char *input, size_t ilen);
void jhd_tls_md_hmac_finish(const jhd_tls_md_info_t *md_info,void *md_ctx,unsigned char *hmac_ctx,unsigned char *output,unsigned char *temp);

#else
#define jhd_tls_md_hmac_starts(MI,MC,HC) (MI)->starts_func(MC);(MI)->update_func(MC, HC,(MI)->block_size)
#define jhd_tls_md_hmac_update(MI,MC,IN,LEN) (MI)->update_func(MC, IN,LEN)
#define jhd_tls_md_hmac_finish(MI,MC,HC,O,T) (MI)->finish_func(MC,T); \
	(MI)->starts_func(MC);\
	(MI)->update_func(MC,(HC) + (MI)->block_size,(MI)->block_size);\
	(MI)->update_func(MC, T,(MI)->size); \
	(MI)->finish_func(MC,O)
#endif





#if defined(JHD_TLS_INLINE)
extern int* supported_digests;
#endif

#endif /* JHD_TLS_MD_H */
