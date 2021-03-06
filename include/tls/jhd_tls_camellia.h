#ifndef JHD_TLS_CAMELLIA_H
#define JHD_TLS_CAMELLIA_H

#include <tls/jhd_tls_config.h>


#include <stddef.h>
#include <stdint.h>
#include <tls/jhd_tls_cipher.h>

#define JHD_TLS_ERR_CAMELLIA_INVALID_KEY_LENGTH           -0x0024  /**< Invalid key length. */
#define JHD_TLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH         -0x0026  /**< Invalid data input length. */
#define JHD_TLS_ERR_CAMELLIA_HW_ACCEL_FAILED              -0x0027  /**< Camellia hardware accelerator failed. */


// Regular implementation
//

/**
 * \brief          CAMELLIA context structure
 */
typedef struct {
	int nr; /*!<  number of rounds  */
	uint32_t rk[68]; /*!<  CAMELLIA round keys    */
} jhd_tls_camellia_context;


/**
 * \brief          CAMELLIA key schedule (encryption)
 *
 * \param ctx      CAMELLIA context to be initialized
 * \param key      encryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or JHD_TLS_ERR_CAMELLIA_INVALID_KEY_LENGTH
 */
void jhd_tls_camellia_setkey_enc(jhd_tls_camellia_context *ctx, const unsigned char *key, unsigned int keybits);

/**
 * \brief          CAMELLIA key schedule (decryption)
 *
 * \param ctx      CAMELLIA context to be initialized
 * \param key      decryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or JHD_TLS_ERR_CAMELLIA_INVALID_KEY_LENGTH
 */
void jhd_tls_camellia_setkey_dec(jhd_tls_camellia_context *ctx, const unsigned char *key, unsigned int keybits);

/**
 * \brief          CAMELLIA-ECB block encryption/decryption
 *
 * \param ctx      CAMELLIA context
 * \param mode     JHD_TLS_CAMELLIA_ENCRYPT or JHD_TLS_CAMELLIA_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful
 */
void jhd_tls_camellia_crypt_ecb(jhd_tls_camellia_context *ctx, jhd_tls_operation_t mode, const unsigned char input[16], unsigned char output[16]);


void jhd_tls_camellia_ecb_func(jhd_tls_camellia_context *ctx, const unsigned char input[16], unsigned char output[16]);

#define jhd_tls_camellia_ecb_encrypt jhd_tls_camellia_ecb_func
#define jhd_tls_camellia_ecb_decrypt jhd_tls_camellia_ecb_func


/**
 * \brief          CAMELLIA-CBC buffer encryption/decryption
 *                 Length should be a multiple of the block
 *                 size (16 bytes)
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      CAMELLIA context
 * \param mode     JHD_TLS_CAMELLIA_ENCRYPT or JHD_TLS_CAMELLIA_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or
 *                 JHD_TLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH
 */
void jhd_tls_camellia_crypt_cbc(jhd_tls_camellia_context *ctx, jhd_tls_operation_t mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output);

void jhd_tls_camellia_cbc_encrypt(jhd_tls_camellia_context *ctx, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output);
void jhd_tls_camellia_cbc_decrypt(jhd_tls_camellia_context *ctx, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output);

/**
 * \brief          CAMELLIA-CFB128 buffer encryption/decryption
 *
 * Note: Due to the nature of CFB you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * jhd_tls_camellia_setkey_enc() for both JHD_TLS_CAMELLIA_ENCRYPT and CAMELLIE_DECRYPT.
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      CAMELLIA context
 * \param mode     JHD_TLS_CAMELLIA_ENCRYPT or JHD_TLS_CAMELLIA_DECRYPT
 * \param length   length of the input data
 * \param iv_off   offset in IV (updated after use)
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or
 *                 JHD_TLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH
 */
void jhd_tls_camellia_crypt_cfb128(jhd_tls_camellia_context *ctx, jhd_tls_operation_t mode, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input,
        unsigned char *output);



/**
 * \brief               CAMELLIA-CTR buffer encryption/decryption
 *
 * Note: Due to the nature of CTR you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * jhd_tls_camellia_setkey_enc() for both JHD_TLS_CAMELLIA_ENCRYPT and JHD_TLS_CAMELLIA_DECRYPT.
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
 *             that a CAMELLIA block is 16 bytes.
 *
 * \warning    Upon return, \p stream_block contains sensitive data. Its
 *             content must not be written to insecure storage and should be
 *             securely discarded as soon as it's no longer needed.
 *
 * \param ctx           CAMELLIA context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 128-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return         0 if successful
 */
void jhd_tls_camellia_crypt_ctr(jhd_tls_camellia_context *ctx, size_t length, size_t *nc_off, unsigned char nonce_counter[16], unsigned char stream_block[16],
        const unsigned char *input, unsigned char *output);


/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int jhd_tls_camellia_self_test(int verbose);

#endif /* camellia.h */
