#ifndef JHD_TLS_DES_H
#define JHD_TLS_DES_H

#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher.h>
#include <stddef.h>
#include <stdint.h>



#define JHD_TLS_ERR_DES_INVALID_INPUT_LENGTH              -0x0032  /**< The data input has an invalid length. */
#define JHD_TLS_ERR_DES_HW_ACCEL_FAILED                   -0x0033  /**< DES hardware accelerator failed. */

#define JHD_TLS_DES_KEY_SIZE    8

// Regular implementation
//

/**
 * \brief          DES context structure
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
typedef struct {
	uint32_t sk[32]; /*!<  DES subkeys       */
} jhd_tls_des_context;

/**
 * \brief          Triple-DES context structure
 */
typedef struct {
	uint32_t sk[96]; /*!<  3DES subkeys      */
} jhd_tls_des3_context;


/**
 * \brief          Set key parity on the given key to odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void jhd_tls_des_key_set_parity(unsigned char key[JHD_TLS_DES_KEY_SIZE]);

/**
 * \brief          Check that key parity on the given key is odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \return         0 is parity was ok, 1 if parity was not correct.
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
int jhd_tls_des_key_check_key_parity(const unsigned char key[JHD_TLS_DES_KEY_SIZE]);

/**
 * \brief          Check that key is not a weak or semi-weak DES key
 *
 * \param key      8-byte secret key
 *
 * \return         0 if no weak key was found, 1 if a weak key was identified.
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
int jhd_tls_des_key_check_weak(const unsigned char key[JHD_TLS_DES_KEY_SIZE]);

/**
 * \brief          DES key schedule (56-bit, encryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 * \param key_bitlen ignore
 *
 * \return         0
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void jhd_tls_des_setkey_enc(jhd_tls_des_context *ctx, const unsigned char key[JHD_TLS_DES_KEY_SIZE],unsigned int key_bitlen);

/**
 * \brief          DES key schedule (56-bit, decryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 * \param key_bitlen ignore
 *
 * \return         0
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void jhd_tls_des_setkey_dec(jhd_tls_des_context *ctx, const unsigned char key[JHD_TLS_DES_KEY_SIZE],unsigned int key_bitlen);

/**
 * \brief          Triple-DES key schedule (112-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 * \param key_bitlen ignore
 *
 * \return         0
 */
void jhd_tls_des3_set2key_enc(jhd_tls_des3_context *ctx, const unsigned char key[JHD_TLS_DES_KEY_SIZE * 2],unsigned int key_bitlen);

/**
 * \brief          Triple-DES key schedule (112-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 * \param key_bitlen ignore
 *
 * \return         0
 */
void jhd_tls_des3_set2key_dec(jhd_tls_des3_context *ctx, const unsigned char key[JHD_TLS_DES_KEY_SIZE * 2],unsigned int key_bitlen);

/**
 * \brief          Triple-DES key schedule (168-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 * \param key_bitlen ignore
 *
 * \return         0
 */
void jhd_tls_des3_set3key_enc(jhd_tls_des3_context *ctx, const unsigned char key[JHD_TLS_DES_KEY_SIZE * 3],unsigned int key_bitlen);

/**
 * \brief          Triple-DES key schedule (168-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 * \param key_bitlen ignore
 *
 * \return         0
 */
void jhd_tls_des3_set3key_dec(jhd_tls_des3_context *ctx, const unsigned char key[JHD_TLS_DES_KEY_SIZE * 3],unsigned int key_bitlen);

/**
 * \brief          DES-ECB block encryption/decryption
 *
 * \param ctx      DES context
 * \param operation ignore
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void jhd_tls_des_crypt_ecb(jhd_tls_des_context *ctx,jhd_tls_operation_t operation, const unsigned char input[8], unsigned char output[8]);
void jhd_tls_des_ecb_func(jhd_tls_des_context *ctx, const unsigned char input[8], unsigned char output[8]);
#define jhd_tls_des_ecb_encrypt jhd_tls_des_ecb_func
#define jhd_tls_des_ecb_decrypt jhd_tls_des_ecb_func
/**
 * \brief          DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      DES context
 * \param mode     JHD_TLS_DES_ENCRYPT or JHD_TLS_DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void jhd_tls_des_crypt_cbc(jhd_tls_des_context *ctx, jhd_tls_operation_t mode, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);
void jhd_tls_des_cbc_encrypt(jhd_tls_des_context *ctx, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);
void jhd_tls_des_cbc_decrypt(jhd_tls_des_context *ctx, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);


/**
 * \brief          3DES-ECB block encryption/decryption
 *
 * \param ctx      3DES context
 * \param mode	   ignore
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 */
void jhd_tls_des3_crypt_ecb(jhd_tls_des3_context *ctx,jhd_tls_operation_t mode, const unsigned char input[8], unsigned char output[8]);
void jhd_tls_des3_ecb_func(jhd_tls_des3_context *ctx,const unsigned char input[8], unsigned char output[8]);
#define jhd_tls_des3_ecb_encrypt jhd_tls_des3_ecb_func
#define jhd_tls_des3_ecb_decrypt jhd_tls_des3_ecb_func

/**
 * \brief          3DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      3DES context
 * \param mode     JHD_TLS_DES_ENCRYPT or JHD_TLS_DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or JHD_TLS_ERR_DES_INVALID_INPUT_LENGTH
 */
void jhd_tls_des3_crypt_cbc(jhd_tls_des3_context *ctx, jhd_tls_operation_t mode, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);
void jhd_tls_des3_cbc_encrypt(jhd_tls_des3_context *ctx,size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);
void jhd_tls_des3_cbc_decrypt(jhd_tls_des3_context *ctx,size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);



/**
 * \brief          Internal function for key expansion.
 *                 (Only exposed to allow overriding it,
 *                 see JHD_TLS_DES_SETKEY_ALT)
 *
 * \param SK       Round keys
 * \param key      Base key
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void jhd_tls_des_setkey(uint32_t SK[32], const unsigned char key[JHD_TLS_DES_KEY_SIZE]);

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int jhd_tls_des_self_test(int verbose);

#endif /* des.h */
