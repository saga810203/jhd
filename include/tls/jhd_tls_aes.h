#ifndef JHD_TLS_AES_H
#define JHD_TLS_AES_H

#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher.h>
#include <stddef.h>
#include <stdint.h>


/* Error codes in range 0x0020-0x0022 */
#define JHD_TLS_ERR_AES_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define JHD_TLS_ERR_AES_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */

/* Error codes in range 0x0021-0x0025 */
#define JHD_TLS_ERR_AES_BAD_INPUT_DATA                    -0x0021  /**< Invalid input data. */
#define JHD_TLS_ERR_AES_FEATURE_UNAVAILABLE               -0x0023  /**< Feature not available. For example, an unsupported AES key size. */
#define JHD_TLS_ERR_AES_HW_ACCEL_FAILED                   -0x0025  /**< AES hardware accelerator failed. */

#define jhd_tls_aes_free(ctx)  jhd_tls_noop_free(ctx)

/**
 * \brief The AES context-type definition.
 */
typedef struct {
	int nr; /*!< The number of rounds. */
	uint32_t *rk; /*!< AES round keys. */
	uint32_t buf[68]; /*!< Unaligned data buffer. This buffer can
	 hold 32 extra Bytes, which can be used for
	 one of the following purposes:
	 <ul><li>Alignment if VIA padlock is
	 used.</li>
	 <li>Simplifying key expansion in the 256-bit
	 case by generating an extra round key.
	 </li></ul> */
} jhd_tls_aes_context;

/**
 * \brief The AES XTS context-type definition.
 */
typedef struct {
	jhd_tls_aes_context crypt; /*!< The AES context to use for AES block
	 encryption or decryption. */
	jhd_tls_aes_context tweak; /*!< The AES context used for tweak
	 computation. */
} jhd_tls_aes_xts_context;


void jhd_tls_aes_init();

void jhd_tls_aes_setkey_enc_auto(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits);

void jhd_tls_aes_setkey_dec_auto(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits);

void jhd_tls_aes_setkey_enc_without_aesni(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits);

void jhd_tls_aes_setkey_dec_without_aesni(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits);

void jhd_tls_aes_setkey_enc_with_aesni(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits);

void jhd_tls_aes_setkey_dec_with_aesni(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits);


void jhd_tls_aes_crypt_ecb(jhd_tls_aes_context *ctx, jhd_tls_operation_t mode, const unsigned char input[16], unsigned char output[16]);


/**
 * \brief  This function performs an AES-CBC encryption or decryption operation
 *         on full blocks.
 *
 *         It performs the operation defined in the \p mode
 *         parameter (encrypt/decrypt), on the input data buffer defined in
 *         the \p input parameter.
 *
 *         It can be called as many times as needed, until all the input
 *         data is processed. jhd_tls_aes_setkey_enc() or jhd_tls_aes_setkey_dec() must be called
 *         before the first call to this API with the same context.
 *
 * \note   This function operates on aligned blocks, that is, the input size
 *         must be a multiple of the AES block size of 16 Bytes.
 *
 * \note   Upon exit, the content of the IV is updated so that you can
 *         call the same function again on the next
 *         block(s) of data and get the same result as if it was
 *         encrypted in one call. This allows a "streaming" usage.
 *         If you need to retain the contents of the IV, you should
 *         either save it manually or use the cipher module instead.
 *
 *
 * \param ctx      The AES context to use for encryption or decryption.
 * \param mode     The AES operation: #JHD_TLS_AES_ENCRYPT or
 *                 #JHD_TLS_AES_DECRYPT.
 * \param length   The length of the input data in Bytes. This must be a
 *                 multiple of the block size (16 Bytes).
 * \param iv       Initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         \c 0 on success.
 * \return         #JHD_TLS_ERR_AES_INVALID_INPUT_LENGTH
 *                 on failure.
 */
void jhd_tls_aes_crypt_cbc(jhd_tls_aes_context *ctx, jhd_tls_operation_t mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output);



void jhd_tls_aes_ecb_encrypt_without_aesni(jhd_tls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]);

void jhd_tls_aes_ecb_decrypt_without_aesni(jhd_tls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]);


void jhd_tls_aes_cbc_encrypt_with_aesni(jhd_tls_aes_context *ctx,size_t length, unsigned char iv[16], const unsigned char *input,unsigned char *output);

void jhd_tls_aes_cbc_decrypt_with_aesni(jhd_tls_aes_context *ctx,size_t length, unsigned char iv[16], const unsigned char *input,unsigned char *output);

void jhd_tls_aes_cbc_encrypt_without_aesni(jhd_tls_aes_context *ctx,size_t length, unsigned char iv[16], const unsigned char *input,unsigned char *output);

void jhd_tls_aes_cbc_decrypt_without_aesni(jhd_tls_aes_context *ctx,size_t length, unsigned char iv[16], const unsigned char *input,unsigned char *output);



extern jhd_tls_cipher_base_t aes_info;


#endif /* aes.h */
