#ifndef JHD_TLS_ARIA_H
#define JHD_TLS_ARIA_H

#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher.h>
#include <stddef.h>
#include <stdint.h>

#define JHD_TLS_ARIA_BLOCKSIZE   16 /**< ARIA block size in bytes. */
#define JHD_TLS_ARIA_MAX_ROUNDS  16 /**< Maxiumum number of rounds in ARIA. */
#define JHD_TLS_ARIA_MAX_KEYSIZE 32 /**< Maximum size of an ARIA key in bytes. */

#define JHD_TLS_ERR_ARIA_INVALID_KEY_LENGTH   -0x005C  /**< Invalid key length. */
#define JHD_TLS_ERR_ARIA_INVALID_INPUT_LENGTH -0x005E  /**< Invalid data input length. */
#define JHD_TLS_ERR_ARIA_FEATURE_UNAVAILABLE  -0x005A  /**< Feature not available. For example, an unsupported ARIA key size. */
#define JHD_TLS_ERR_ARIA_HW_ACCEL_FAILED      -0x0058  /**< ARIA hardware accelerator failed. */

/**
 * \brief The ARIA context-type definition.
 */
typedef struct {
	unsigned char nr; /*!< The number of rounds (12, 14 or 16) */
	/*! The ARIA round keys. */
	uint32_t rk[JHD_TLS_ARIA_MAX_ROUNDS + 1][JHD_TLS_ARIA_BLOCKSIZE / 4];
} jhd_tls_aria_context;



/**
 * \brief          This function sets the encryption key.
 *
 * \param ctx      The ARIA context to which the key should be bound.
 * \param key      The encryption key.
 * \param keybits  The size of data passed in bits. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>192 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success or #JHD_TLS_ERR_ARIA_INVALID_KEY_LENGTH
 *                 on failure.
 */
void jhd_tls_aria_setkey_enc(jhd_tls_aria_context *ctx, const unsigned char *key, unsigned int keybits);

/**
 * \brief          This function sets the decryption key.
 *
 * \param ctx      The ARIA context to which the key should be bound.
 * \param key      The decryption key.
 * \param keybits  The size of data passed. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>192 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success, or #JHD_TLS_ERR_ARIA_INVALID_KEY_LENGTH on failure.
 */
void jhd_tls_aria_setkey_dec(jhd_tls_aria_context *ctx, const unsigned char *key, unsigned int keybits);

/**
 * \brief          This function performs an ARIA single-block encryption or
 *                 decryption operation.
 *
 *                 It performs encryption or decryption (depending on whether
 *                 the key was set for encryption on decryption) on the input
 *                 data buffer defined in the \p input parameter.
 *
 *                  jhd_tls_aria_setkey_enc() or
 *                 jhd_tls_aria_setkey_dec() must be called before the first
 *                 call to this API with the same context.
 *
 * \param ctx      The ARIA context to use for encryption or decryption.
 * \param mode 	   ignore
 * \param input    The 16-Byte buffer holding the input data.
 * \param output   The 16-Byte buffer holding the output data.

 * \return         \c 0 on success.
 */
void jhd_tls_aria_crypt_ecb(jhd_tls_aria_context *ctx, jhd_tls_operation_t mode,const unsigned char input[16], unsigned char output[16]);
void jhd_tls_aria_ecb_func(jhd_tls_aria_context *ctx,const unsigned char input[16], unsigned char output[16]);
#define jhd_tls_aria_ecb_encrypt jhd_tls_aria_ecb_func
#define jhd_tls_aria_ecb_decrypt jhd_tls_aria_ecb_func

/**
 * \brief  This function performs an ARIA-CBC encryption or decryption operation
 *         on full blocks.
 *
 *         It performs the operation defined in the \p mode
 *         parameter (encrypt/decrypt), on the input data buffer defined in
 *         the \p input parameter.
 *
 *         It can be called as many times as needed, until all the input
 *         data is processed.
 *         jhd_tls_aria_setkey_enc() or jhd_tls_aria_setkey_dec() must be called
 *         before the first call to this API with the same context.
 *
 * \note   This function operates on aligned blocks, that is, the input size
 *         must be a multiple of the ARIA block size of 16 Bytes.
 *
 * \note   Upon exit, the content of the IV is updated so that you can
 *         call the same function again on the next
 *         block(s) of data and get the same result as if it was
 *         encrypted in one call. This allows a "streaming" usage.
 *         If you need to retain the contents of the IV, you should
 *         either save it manually or use the cipher module instead.
 *
 *
 * \param ctx      The ARIA context to use for encryption or decryption.
 * \param mode     The ARIA operation: #JHD_TLS_ARIA_ENCRYPT or
 *                 #JHD_TLS_ARIA_DECRYPT.
 * \param length   The length of the input data in Bytes. This must be a
 *                 multiple of the block size (16 Bytes).
 * \param iv       Initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         \c 0 on success, or #JHD_TLS_ERR_ARIA_INVALID_INPUT_LENGTH
 *                 on failure.
 */
void jhd_tls_aria_crypt_cbc(jhd_tls_aria_context *ctx, jhd_tls_operation_t mode, size_t length, unsigned char iv[16], const unsigned char *input,
        unsigned char *output);
void jhd_tls_aria_cbc_encrypt(jhd_tls_aria_context *ctx, size_t length, unsigned char iv[16], const unsigned char *input,
        unsigned char *output);
void jhd_tls_aria_cbc_decrypt(jhd_tls_aria_context *ctx, size_t length, unsigned char iv[16], const unsigned char *input,
        unsigned char *output);


/**
 * \brief This function performs an ARIA-CFB128 encryption or decryption
 *        operation.
 *
 *        It performs the operation defined in the \p mode
 *        parameter (encrypt or decrypt), on the input data buffer
 *        defined in the \p input parameter.
 *
 *        For CFB, you must set up the context with jhd_tls_aria_setkey_enc(),
 *        regardless of whether you are performing an encryption or decryption
 *        operation, that is, regardless of the \p mode parameter. This is
 *        because CFB mode uses the same key schedule for encryption and
 *        decryption.
 *
 * \note  Upon exit, the content of the IV is updated so that you can
 *        call the same function again on the next
 *        block(s) of data and get the same result as if it was
 *        encrypted in one call. This allows a "streaming" usage.
 *        If you need to retain the contents of the
 *        IV, you must either save it manually or use the cipher
 *        module instead.
 *
 *
 * \param ctx      The ARIA context to use for encryption or decryption.
 * \param mode     The ARIA operation: #JHD_TLS_ARIA_ENCRYPT or
 *                 #JHD_TLS_ARIA_DECRYPT.
 * \param length   The length of the input data.
 * \param iv_off   The offset in IV (updated after use).
 * \param iv       The initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         \c 0 on success.
 */
void jhd_tls_aria_crypt_cfb128(jhd_tls_aria_context *ctx, jhd_tls_operation_t mode, size_t length, size_t *iv_off, unsigned char iv[JHD_TLS_ARIA_BLOCKSIZE],
        const unsigned char *input, unsigned char *output);


/**
 * \brief      This function performs an ARIA-CTR encryption or decryption
 *             operation.
 *
 *             This function performs the operation defined in the \p mode
 *             parameter (encrypt/decrypt), on the input data buffer
 *             defined in the \p input parameter.
 *
 *             Due to the nature of CTR, you must use the same key schedule
 *             for both encryption and decryption operations. Therefore, you
 *             must use the context initialized with jhd_tls_aria_setkey_enc()
 *             for both #JHD_TLS_ARIA_ENCRYPT and #JHD_TLS_ARIA_DECRYPT.
 *
 * \warning    You must never reuse a nonce value with the same key. Doing so
 *             would void the encryption for the two messages encrypted with
 *             the same nonce and key.
 *
 *             There are two common strategies for managing nonces with CTR:
 *
 *             1. You can handle everything as a single message processed over
 *             successive calls to this function. In that case, you want to
 *             set \p nonce_counter and \p nc_off to 0 for the first call, and
 *             then preserve the values of \p nonce_counter, \p nc_off and \p
 *             stream_block across calls to this function as they will be
 *             updated by this function.
 *
 *             With this strategy, you must not encrypt more than 2**128
 *             blocks of data with the same key.
 *
 *             2. You can encrypt separate messages by dividing the \p
 *             nonce_counter buffer in two areas: the first one used for a
 *             per-message nonce, handled by yourself, and the second one
 *             updated by this function internally.
 *
 *             For example, you might reserve the first 12 bytes for the
 *             per-message nonce, and the last 4 bytes for internal use. In that
 *             case, before calling this function on a new message you need to
 *             set the first 12 bytes of \p nonce_counter to your chosen nonce
 *             value, the last 4 to 0, and \p nc_off to 0 (which will cause \p
 *             stream_block to be ignored). That way, you can encrypt at most
 *             2**96 messages of up to 2**32 blocks each with the same key.
 *
 *             The per-message nonce (or information sufficient to reconstruct
 *             it) needs to be communicated with the ciphertext and must be unique.
 *             The recommended way to ensure uniqueness is to use a message
 *             counter. An alternative is to generate random nonces, but this
 *             limits the number of messages that can be securely encrypted:
 *             for example, with 96-bit random nonces, you should not encrypt
 *             more than 2**32 messages with the same key.
 *
 *             Note that for both stategies, sizes are measured in blocks and
 *             that an ARIA block is 16 bytes.
 *
 * \warning    Upon return, \p stream_block contains sensitive data. Its
 *             content must not be written to insecure storage and should be
 *             securely discarded as soon as it's no longer needed.
 *
 * \param ctx              The ARIA context to use for encryption or decryption.
 * \param length           The length of the input data.
 * \param nc_off           The offset in the current \p stream_block, for
 *                         resuming within the current cipher stream. The
 *                         offset pointer should be 0 at the start of a stream.
 * \param nonce_counter    The 128-bit nonce and counter.
 * \param stream_block     The saved stream block for resuming. This is
 *                         overwritten by the function.
 * \param input            The buffer holding the input data.
 * \param output           The buffer holding the output data.
 *
 * \return     \c 0 on success.
 */
void jhd_tls_aria_crypt_ctr(jhd_tls_aria_context *ctx, size_t length, size_t *nc_off, unsigned char nonce_counter[JHD_TLS_ARIA_BLOCKSIZE],
        unsigned char stream_block[JHD_TLS_ARIA_BLOCKSIZE], const unsigned char *input, unsigned char *output);


#if defined(JHD_TLS_SELF_TEST)
/**
 * \brief          Checkup routine.
 *
 * \return         \c 0 on success, or \c 1 on failure.
 */
int jhd_tls_aria_self_test(int verbose);
#endif /* JHD_TLS_SELF_TEST */

#endif /* aria.h */
