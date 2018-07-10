#ifndef JHD_TLS_AES_H
#define JHD_TLS_AES_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include "jhd_tls_config.h"
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

/* padlock.c and aesni.c rely on these values! */
#define JHD_TLS_AES_ENCRYPT     1 /**< AES encryption. */
#define JHD_TLS_AES_DECRYPT     0 /**< AES decryption. */

/* Error codes in range 0x0020-0x0022 */
#define JHD_TLS_ERR_AES_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define JHD_TLS_ERR_AES_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */

/* Error codes in range 0x0021-0x0025 */
#define JHD_TLS_ERR_AES_BAD_INPUT_DATA                    -0x0021  /**< Invalid input data. */
#define JHD_TLS_ERR_AES_FEATURE_UNAVAILABLE               -0x0023  /**< Feature not available. For example, an unsupported AES key size. */
#define JHD_TLS_ERR_AES_HW_ACCEL_FAILED                   -0x0025  /**< AES hardware accelerator failed. */

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif



#if !defined(JHD_TLS_AES_ALT)
// Regular implementation
//

/**
 * \brief The AES context-type definition.
 */
typedef struct
{
    int nr;                     /*!< The number of rounds. */
    uint32_t *rk;               /*!< AES round keys. */
    uint32_t buf[68];           /*!< Unaligned data buffer. This buffer can
                                     hold 32 extra Bytes, which can be used for
                                     one of the following purposes:
                                     <ul><li>Alignment if VIA padlock is
                                             used.</li>
                                     <li>Simplifying key expansion in the 256-bit
                                         case by generating an extra round key.
                                         </li></ul> */
}
jhd_tls_aes_context;

#if defined(JHD_TLS_CIPHER_MODE_XTS)
/**
 * \brief The AES XTS context-type definition.
 */
typedef struct
{
    jhd_tls_aes_context crypt; /*!< The AES context to use for AES block
                                        encryption or decryption. */
    jhd_tls_aes_context tweak; /*!< The AES context used for tweak
                                        computation. */
} jhd_tls_aes_xts_context;
#endif /* JHD_TLS_CIPHER_MODE_XTS */

#else  /* JHD_TLS_AES_ALT */
#include "jhd_tls_aes_alt.h"
#endif /* JHD_TLS_AES_ALT */

/**
 * \brief          This function initializes the specified AES context.
 *
 *                 It must be the first API called before using
 *                 the context.
 *
 * \param ctx      The AES context to initialize.
 */
void jhd_tls_aes_init( jhd_tls_aes_context *ctx );

/**
 * \brief          This function releases and clears the specified AES context.
 *
 * \param ctx      The AES context to clear.
 */
void jhd_tls_aes_free( jhd_tls_aes_context *ctx );

#if defined(JHD_TLS_CIPHER_MODE_XTS)
/**
 * \brief          This function initializes the specified AES XTS context.
 *
 *                 It must be the first API called before using
 *                 the context.
 *
 * \param ctx      The AES XTS context to initialize.
 */
void jhd_tls_aes_xts_init( jhd_tls_aes_xts_context *ctx );

/**
 * \brief          This function releases and clears the specified AES XTS context.
 *
 * \param ctx      The AES XTS context to clear.
 */
void jhd_tls_aes_xts_free( jhd_tls_aes_xts_context *ctx );
#endif /* JHD_TLS_CIPHER_MODE_XTS */

/**
 * \brief          This function sets the encryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 * \param key      The encryption key.
 * \param keybits  The size of data passed in bits. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>192 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #JHD_TLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
int jhd_tls_aes_setkey_enc( jhd_tls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/**
 * \brief          This function sets the decryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 * \param key      The decryption key.
 * \param keybits  The size of data passed. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>192 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #JHD_TLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
int jhd_tls_aes_setkey_dec( jhd_tls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

#if defined(JHD_TLS_CIPHER_MODE_XTS)
/**
 * \brief          This function prepares an XTS context for encryption and
 *                 sets the encryption key.
 *
 * \param ctx      The AES XTS context to which the key should be bound.
 * \param key      The encryption key. This is comprised of the XTS key1
 *                 concatenated with the XTS key2.
 * \param keybits  The size of \p key passed in bits. Valid options are:
 *                 <ul><li>256 bits (each of key1 and key2 is a 128-bit key)</li>
 *                 <li>512 bits (each of key1 and key2 is a 256-bit key)</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #JHD_TLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
int jhd_tls_aes_xts_setkey_enc( jhd_tls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits );

/**
 * \brief          This function prepares an XTS context for decryption and
 *                 sets the decryption key.
 *
 * \param ctx      The AES XTS context to which the key should be bound.
 * \param key      The decryption key. This is comprised of the XTS key1
 *                 concatenated with the XTS key2.
 * \param keybits  The size of \p key passed in bits. Valid options are:
 *                 <ul><li>256 bits (each of key1 and key2 is a 128-bit key)</li>
 *                 <li>512 bits (each of key1 and key2 is a 256-bit key)</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #JHD_TLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
int jhd_tls_aes_xts_setkey_dec( jhd_tls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits );
#endif /* JHD_TLS_CIPHER_MODE_XTS */

/**
 * \brief          This function performs an AES single-block encryption or
 *                 decryption operation.
 *
 *                 It performs the operation defined in the \p mode parameter
 *                 (encrypt or decrypt), on the input data buffer defined in
 *                 the \p input parameter.
 *
 *                 jhd_tls_aes_init(), and either jhd_tls_aes_setkey_enc() or
 *                 jhd_tls_aes_setkey_dec() must be called before the first
 *                 call to this API with the same context.
 *
 * \param ctx      The AES context to use for encryption or decryption.
 * \param mode     The AES operation: #JHD_TLS_AES_ENCRYPT or
 *                 #JHD_TLS_AES_DECRYPT.
 * \param input    The 16-Byte buffer holding the input data.
 * \param output   The 16-Byte buffer holding the output data.

 * \return         \c 0 on success.
 */
int jhd_tls_aes_crypt_ecb( jhd_tls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] );

#if defined(JHD_TLS_CIPHER_MODE_CBC)
/**
 * \brief  This function performs an AES-CBC encryption or decryption operation
 *         on full blocks.
 *
 *         It performs the operation defined in the \p mode
 *         parameter (encrypt/decrypt), on the input data buffer defined in
 *         the \p input parameter.
 *
 *         It can be called as many times as needed, until all the input
 *         data is processed. jhd_tls_aes_init(), and either
 *         jhd_tls_aes_setkey_enc() or jhd_tls_aes_setkey_dec() must be called
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
int jhd_tls_aes_crypt_cbc( jhd_tls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /* JHD_TLS_CIPHER_MODE_CBC */

#if defined(JHD_TLS_CIPHER_MODE_XTS)
/**
 * \brief      This function performs an AES-XTS encryption or decryption
 *             operation for an entire XTS data unit.
 *
 *             AES-XTS encrypts or decrypts blocks based on their location as
 *             defined by a data unit number. The data unit number must be
 *             provided by \p data_unit.
 *
 *             NIST SP 800-38E limits the maximum size of a data unit to 2^20
 *             AES blocks. If the data unit is larger than this, this function
 *             returns #JHD_TLS_ERR_AES_INVALID_INPUT_LENGTH.
 *
 * \param ctx          The AES XTS context to use for AES XTS operations.
 * \param mode         The AES operation: #JHD_TLS_AES_ENCRYPT or
 *                     #JHD_TLS_AES_DECRYPT.
 * \param length       The length of a data unit in bytes. This can be any
 *                     length between 16 bytes and 2^24 bytes inclusive
 *                     (between 1 and 2^20 block cipher blocks).
 * \param data_unit    The address of the data unit encoded as an array of 16
 *                     bytes in little-endian format. For disk encryption, this
 *                     is typically the index of the block device sector that
 *                     contains the data.
 * \param input        The buffer holding the input data (which is an entire
 *                     data unit). This function reads \p length bytes from \p
 *                     input.
 * \param output       The buffer holding the output data (which is an entire
 *                     data unit). This function writes \p length bytes to \p
 *                     output.
 *
 * \return             \c 0 on success.
 * \return             #JHD_TLS_ERR_AES_INVALID_INPUT_LENGTH if \p length is
 *                     smaller than an AES block in size (16 bytes) or if \p
 *                     length is larger than 2^20 blocks (16 MiB).
 */
int jhd_tls_aes_crypt_xts( jhd_tls_aes_xts_context *ctx,
                           int mode,
                           size_t length,
                           const unsigned char data_unit[16],
                           const unsigned char *input,
                           unsigned char *output );
#endif /* JHD_TLS_CIPHER_MODE_XTS */

#if defined(JHD_TLS_CIPHER_MODE_CFB)
/**
 * \brief This function performs an AES-CFB128 encryption or decryption
 *        operation.
 *
 *        It performs the operation defined in the \p mode
 *        parameter (encrypt or decrypt), on the input data buffer
 *        defined in the \p input parameter.
 *
 *        For CFB, you must set up the context with jhd_tls_aes_setkey_enc(),
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
 * \param ctx      The AES context to use for encryption or decryption.
 * \param mode     The AES operation: #JHD_TLS_AES_ENCRYPT or
 *                 #JHD_TLS_AES_DECRYPT.
 * \param length   The length of the input data.
 * \param iv_off   The offset in IV (updated after use).
 * \param iv       The initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         \c 0 on success.
 */
int jhd_tls_aes_crypt_cfb128( jhd_tls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output );

/**
 * \brief This function performs an AES-CFB8 encryption or decryption
 *        operation.
 *
 *        It performs the operation defined in the \p mode
 *        parameter (encrypt/decrypt), on the input data buffer defined
 *        in the \p input parameter.
 *
 *        Due to the nature of CFB, you must use the same key schedule for
 *        both encryption and decryption operations. Therefore, you must
 *        use the context initialized with jhd_tls_aes_setkey_enc() for
 *        both #JHD_TLS_AES_ENCRYPT and #JHD_TLS_AES_DECRYPT.
 *
 * \note  Upon exit, the content of the IV is updated so that you can
 *        call the same function again on the next
 *        block(s) of data and get the same result as if it was
 *        encrypted in one call. This allows a "streaming" usage.
 *        If you need to retain the contents of the
 *        IV, you should either save it manually or use the cipher
 *        module instead.
 *
 *
 * \param ctx      The AES context to use for encryption or decryption.
 * \param mode     The AES operation: #JHD_TLS_AES_ENCRYPT or
 *                 #JHD_TLS_AES_DECRYPT
 * \param length   The length of the input data.
 * \param iv       The initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         \c 0 on success.
 */
int jhd_tls_aes_crypt_cfb8( jhd_tls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /*JHD_TLS_CIPHER_MODE_CFB */

#if defined(JHD_TLS_CIPHER_MODE_OFB)
/**
 * \brief       This function performs an AES-OFB (Output Feedback Mode)
 *              encryption or decryption operation.
 *
 *              For OFB, you must set up the context with
 *              jhd_tls_aes_setkey_enc(), regardless of whether you are
 *              performing an encryption or decryption operation. This is
 *              because OFB mode uses the same key schedule for encryption and
 *              decryption.
 *
 *              The OFB operation is identical for encryption or decryption,
 *              therefore no operation mode needs to be specified.
 *
 * \note        Upon exit, the content of iv, the Initialisation Vector, is
 *              updated so that you can call the same function again on the next
 *              block(s) of data and get the same result as if it was encrypted
 *              in one call. This allows a "streaming" usage, by initialising
 *              iv_off to 0 before the first call, and preserving its value
 *              between calls.
 *
 *              For non-streaming use, the iv should be initialised on each call
 *              to a unique value, and iv_off set to 0 on each call.
 *
 *              If you need to retain the contents of the initialisation vector,
 *              you must either save it manually or use the cipher module
 *              instead.
 *
 * \warning     For the OFB mode, the initialisation vector must be unique
 *              every encryption operation. Reuse of an initialisation vector
 *              will compromise security.
 *
 * \param ctx      The AES context to use for encryption or decryption.
 * \param length   The length of the input data.
 * \param iv_off   The offset in IV (updated after use).
 * \param iv       The initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         \c 0 on success.
 */
int jhd_tls_aes_crypt_ofb( jhd_tls_aes_context *ctx,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output );

#endif /* JHD_TLS_CIPHER_MODE_OFB */

#if defined(JHD_TLS_CIPHER_MODE_CTR)
/**
 * \brief      This function performs an AES-CTR encryption or decryption
 *             operation.
 *
 *             This function performs the operation defined in the \p mode
 *             parameter (encrypt/decrypt), on the input data buffer
 *             defined in the \p input parameter.
 *
 *             Due to the nature of CTR, you must use the same key schedule
 *             for both encryption and decryption operations. Therefore, you
 *             must use the context initialized with jhd_tls_aes_setkey_enc()
 *             for both #JHD_TLS_AES_ENCRYPT and #JHD_TLS_AES_DECRYPT.
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
 *             that an AES block is 16 bytes.
 *
 * \warning    Upon return, \p stream_block contains sensitive data. Its
 *             content must not be written to insecure storage and should be
 *             securely discarded as soon as it's no longer needed.
 *
 * \param ctx              The AES context to use for encryption or decryption.
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
 * \return                 \c 0 on success.
 */
int jhd_tls_aes_crypt_ctr( jhd_tls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output );
#endif /* JHD_TLS_CIPHER_MODE_CTR */

/**
 * \brief           Internal AES block encryption function. This is only
 *                  exposed to allow overriding it using
 *                  \c JHD_TLS_AES_ENCRYPT_ALT.
 *
 * \param ctx       The AES context to use for encryption.
 * \param input     The plaintext block.
 * \param output    The output (ciphertext) block.
 *
 * \return          \c 0 on success.
 */
int jhd_tls_internal_aes_encrypt( jhd_tls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] );

/**
 * \brief           Internal AES block decryption function. This is only
 *                  exposed to allow overriding it using see
 *                  \c JHD_TLS_AES_DECRYPT_ALT.
 *
 * \param ctx       The AES context to use for decryption.
 * \param input     The ciphertext block.
 * \param output    The output (plaintext) block.
 *
 * \return          \c 0 on success.
 */
int jhd_tls_internal_aes_decrypt( jhd_tls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] );

#if !defined(JHD_TLS_DEPRECATED_REMOVED)
#if defined(JHD_TLS_DEPRECATED_WARNING)
#define JHD_TLS_DEPRECATED      __attribute__((deprecated))
#else
#define JHD_TLS_DEPRECATED
#endif
/**
 * \brief           Deprecated internal AES block encryption function
 *                  without return value.
 *
 * \deprecated      Superseded by jhd_tls_aes_encrypt_ext() in 2.5.0.
 *
 * \param ctx       The AES context to use for encryption.
 * \param input     Plaintext block.
 * \param output    Output (ciphertext) block.
 */
JHD_TLS_DEPRECATED void jhd_tls_aes_encrypt( jhd_tls_aes_context *ctx,
                                             const unsigned char input[16],
                                             unsigned char output[16] );

/**
 * \brief           Deprecated internal AES block decryption function
 *                  without return value.
 *
 * \deprecated      Superseded by jhd_tls_aes_decrypt_ext() in 2.5.0.
 *
 * \param ctx       The AES context to use for decryption.
 * \param input     Ciphertext block.
 * \param output    Output (plaintext) block.
 */
JHD_TLS_DEPRECATED void jhd_tls_aes_decrypt( jhd_tls_aes_context *ctx,
                                             const unsigned char input[16],
                                             unsigned char output[16] );

#undef JHD_TLS_DEPRECATED
#endif /* !JHD_TLS_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int jhd_tls_aes_self_test( int verbose );



#endif /* aes.h */
