#ifndef JHD_TLS_CIPHER_H
#define JHD_TLS_CIPHER_H

#include <tls/jhd_tls_config.h>

#include <stddef.h>

#define JHD_TLS_CIPHER_MODE_AEAD


#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#define JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE  -0x6080  /**< The selected feature is not available. */
#define JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA       -0x6100  /**< Bad input parameters. */
#define JHD_TLS_ERR_CIPHER_ALLOC_FAILED         -0x6180  /**< Failed to allocate memory. */
#define JHD_TLS_ERR_CIPHER_INVALID_PADDING      -0x6200  /**< Input data contains invalid padding and is rejected. */
#define JHD_TLS_ERR_CIPHER_FULL_BLOCK_EXPECTED  -0x6280  /**< Decryption of block requires a full block. */
#define JHD_TLS_ERR_CIPHER_AUTH_FAILED          -0x6300  /**< Authentication failed (for AEAD modes). */
#define JHD_TLS_ERR_CIPHER_INVALID_CONTEXT      -0x6380  /**< The context is invalid. For example, because it was freed. */
#define JHD_TLS_ERR_CIPHER_HW_ACCEL_FAILED      -0x6400  /**< Cipher hardware accelerator failed. */

#define JHD_TLS_CIPHER_VARIABLE_IV_LEN     0x01    /**< Cipher accepts IVs of variable length. */
#define JHD_TLS_CIPHER_VARIABLE_KEY_LEN    0x02    /**< Cipher accepts keys of variable length. */


typedef enum {
	JHD_TLS_CIPHER_ID_NONE = 0, /**< Placeholder to mark the end of cipher ID lists. */
	JHD_TLS_CIPHER_ID_NULL, /**< The identity cipher, treated as a stream cipher. */
	JHD_TLS_CIPHER_ID_AES, /**< The AES cipher. */
	JHD_TLS_CIPHER_ID_DES, /**< The DES cipher. */
	JHD_TLS_CIPHER_ID_3DES, /**< The Triple DES cipher. */
	JHD_TLS_CIPHER_ID_CAMELLIA, /**< The Camellia cipher. */
	JHD_TLS_CIPHER_ID_BLOWFISH, /**< The Blowfish cipher. */
	JHD_TLS_CIPHER_ID_ARC4, /**< The RC4 cipher. */
	JHD_TLS_CIPHER_ID_ARIA, /**< The Aria cipher. */
} jhd_tls_cipher_id_t;

typedef enum {
	JHD_TLS_CIPHER_NONE = 0, /**< Placeholder to mark the end of cipher-pair lists. */
	JHD_TLS_CIPHER_NULL, /**< The identity stream cipher. */
	JHD_TLS_CIPHER_AES_128_ECB, /**< AES cipher with 128-bit ECB mode. */
	JHD_TLS_CIPHER_AES_192_ECB, /**< AES cipher with 192-bit ECB mode. */
	JHD_TLS_CIPHER_AES_256_ECB, /**< AES cipher with 256-bit ECB mode. */
	JHD_TLS_CIPHER_AES_128_CBC, /**< AES cipher with 128-bit CBC mode. */
	JHD_TLS_CIPHER_AES_192_CBC, /**< AES cipher with 192-bit CBC mode. */
	JHD_TLS_CIPHER_AES_256_CBC, /**< AES cipher with 256-bit CBC mode. */
	JHD_TLS_CIPHER_AES_128_GCM, /**< AES cipher with 128-bit GCM mode. */
	JHD_TLS_CIPHER_AES_192_GCM, /**< AES cipher with 192-bit GCM mode. */
	JHD_TLS_CIPHER_AES_256_GCM, /**< AES cipher with 256-bit GCM mode. */
	JHD_TLS_CIPHER_CAMELLIA_128_ECB, /**< Camellia cipher with 128-bit ECB mode. */
	JHD_TLS_CIPHER_CAMELLIA_192_ECB, /**< Camellia cipher with 192-bit ECB mode. */
	JHD_TLS_CIPHER_CAMELLIA_256_ECB, /**< Camellia cipher with 256-bit ECB mode. */
	JHD_TLS_CIPHER_CAMELLIA_128_CBC, /**< Camellia cipher with 128-bit CBC mode. */
	JHD_TLS_CIPHER_CAMELLIA_192_CBC, /**< Camellia cipher with 192-bit CBC mode. */
	JHD_TLS_CIPHER_CAMELLIA_256_CBC, /**< Camellia cipher with 256-bit CBC mode. */
	JHD_TLS_CIPHER_CAMELLIA_128_GCM, /**< Camellia cipher with 128-bit GCM mode. */
	JHD_TLS_CIPHER_CAMELLIA_192_GCM, /**< Camellia cipher with 192-bit GCM mode. */
	JHD_TLS_CIPHER_CAMELLIA_256_GCM, /**< Camellia cipher with 256-bit GCM mode. */
	JHD_TLS_CIPHER_DES_ECB, /**< DES cipher with ECB mode. */
	JHD_TLS_CIPHER_DES_CBC, /**< DES cipher with CBC mode. */
	JHD_TLS_CIPHER_DES_EDE_ECB, /**< DES cipher with EDE ECB mode. */
	JHD_TLS_CIPHER_DES_EDE_CBC, /**< DES cipher with EDE CBC mode. */
	JHD_TLS_CIPHER_DES_EDE3_ECB, /**< DES cipher with EDE3 ECB mode. */
	JHD_TLS_CIPHER_DES_EDE3_CBC, /**< DES cipher with EDE3 CBC mode. */
	JHD_TLS_CIPHER_AES_128_CCM, /**< AES cipher with 128-bit CCM mode. */
	JHD_TLS_CIPHER_AES_192_CCM, /**< AES cipher with 192-bit CCM mode. */
	JHD_TLS_CIPHER_AES_256_CCM, /**< AES cipher with 256-bit CCM mode. */
	JHD_TLS_CIPHER_CAMELLIA_128_CCM, /**< Camellia cipher with 128-bit CCM mode. */
	JHD_TLS_CIPHER_CAMELLIA_192_CCM, /**< Camellia cipher with 192-bit CCM mode. */
	JHD_TLS_CIPHER_CAMELLIA_256_CCM, /**< Camellia cipher with 256-bit CCM mode. */
	JHD_TLS_CIPHER_ARIA_128_ECB, /**< Aria cipher with 128-bit key and ECB mode. */
	JHD_TLS_CIPHER_ARIA_192_ECB, /**< Aria cipher with 192-bit key and ECB mode. */
	JHD_TLS_CIPHER_ARIA_256_ECB, /**< Aria cipher with 256-bit key and ECB mode. */
	JHD_TLS_CIPHER_ARIA_128_CBC, /**< Aria cipher with 128-bit key and CBC mode. */
	JHD_TLS_CIPHER_ARIA_192_CBC, /**< Aria cipher with 192-bit key and CBC mode. */
	JHD_TLS_CIPHER_ARIA_256_CBC, /**< Aria cipher with 256-bit key and CBC mode. */
	JHD_TLS_CIPHER_ARIA_128_GCM, /**< Aria cipher with 128-bit key and GCM mode. */
	JHD_TLS_CIPHER_ARIA_192_GCM, /**< Aria cipher with 192-bit key and GCM mode. */
	JHD_TLS_CIPHER_ARIA_256_GCM, /**< Aria cipher with 256-bit key and GCM mode. */
	JHD_TLS_CIPHER_ARIA_128_CCM, /**< Aria cipher with 128-bit key and CCM mode. */
	JHD_TLS_CIPHER_ARIA_192_CCM, /**< Aria cipher with 192-bit key and CCM mode. */
	JHD_TLS_CIPHER_ARIA_256_CCM, /**< Aria cipher with 256-bit key and CCM mode. */
} jhd_tls_cipher_type_t;

/** Supported cipher modes. */
typedef enum {
	JHD_TLS_MODE_NONE = 0, /**< None. */
	JHD_TLS_MODE_ECB, /**< The ECB cipher mode. */
	JHD_TLS_MODE_CBC, /**< The CBC cipher mode. */
	JHD_TLS_MODE_CFB, /**< The CFB cipher mode. */
	JHD_TLS_MODE_OFB, /**< The OFB cipher mode. */
	JHD_TLS_MODE_CTR, /**< The CTR cipher mode. */
	JHD_TLS_MODE_GCM, /**< The GCM cipher mode. */
	JHD_TLS_MODE_STREAM, /**< The stream cipher mode. */
	JHD_TLS_MODE_CCM, /**< The CCM cipher mode. */
	JHD_TLS_MODE_XTS, /**< The XTS cipher mode. */
} jhd_tls_cipher_mode_t;

/** Type of operation. */
typedef enum {
	JHD_TLS_OPERATION_NONE = -1, JHD_TLS_DECRYPT = 0, JHD_TLS_ENCRYPT,
} jhd_tls_operation_t;

enum {
	/** Undefined key length. */
	JHD_TLS_KEY_LENGTH_NONE = 0,
	/** Key length, in bits (including parity), for DES keys. */
	JHD_TLS_KEY_LENGTH_DES = 64,
	/** Key length in bits, including parity, for DES in two-key EDE. */
	JHD_TLS_KEY_LENGTH_DES_EDE = 128,
	/** Key length in bits, including parity, for DES in three-key EDE. */
	JHD_TLS_KEY_LENGTH_DES_EDE3 = 192,
};

/** Maximum length of any IV, in Bytes. */
#define JHD_TLS_MAX_IV_LENGTH      16
/** Maximum block size of any cipher, in Bytes. */
#define JHD_TLS_MAX_BLOCK_LENGTH   16

/**
 * Base cipher information (opaque struct).
 */
typedef struct jhd_tls_cipher_base_t jhd_tls_cipher_base_t;



/**
 * Cipher information. Allows calling cipher functions
 * in a generic way.
 */
typedef struct {
	jhd_tls_cipher_type_t type;
	jhd_tls_cipher_mode_t mode;
	unsigned int key_bitlen;
	const char * name;
	uint8_t block_size;
	const jhd_tls_cipher_base_t *base;
} jhd_tls_cipher_info_t;

/**
 * Generic cipher context.
 */
typedef struct {
	const jhd_tls_cipher_info_t *cipher_info;
	void *cipher_ctx;
} jhd_tls_cipher_context_t;

/** Encrypt using ECB */
typedef void (*jhd_tls_cipher_ecb_pt)(void *ctx, jhd_tls_operation_t mode, const unsigned char *input, unsigned char *output);

/** Encrypt using CBC */
typedef void (*jhd_tls_cipher_cbc_pt)(void *ctx, jhd_tls_operation_t mode, size_t length, unsigned char *iv, const unsigned char *input, unsigned char *output);


/** Encrypt using ECB */
typedef void (*jhd_tls_cipher_ecb_encrypt_pt)(void *ctx,const unsigned char *input, unsigned char *output);

/** Encrypt using CBC */
typedef void (*jhd_tls_cipher_cbc_encrypt_pt)(void *ctx,size_t length, unsigned char *iv, const unsigned char *input, unsigned char *output);

/** Encrypt using ECB */
typedef void (*jhd_tls_cipher_ecb_decrypt_pt)(void *ctx,const unsigned char *input, unsigned char *output);

/** Encrypt using CBC */
typedef void (*jhd_tls_cipher_cbc_decrypt_pt)(void *ctx,size_t length, unsigned char *iv, const unsigned char *input, unsigned char *output);




typedef void (*jhd_tls_cipher_setkey_enc_pt)(void *ctx, const unsigned char *key, unsigned int key_bitlen);

/** Set key for decryption purposes */
typedef void (*jhd_tls_cipher_setkey_dec_pt)(void *ctx, const unsigned char *key, unsigned int key_bitlen);

/** Allocate a new context */
typedef void * (*jhd_tls_cipher_ctx_alloc_pt)(void);

/** Free the given context */
typedef void (*jhd_tls_cipher_ctx_free_pt)(void *ctx);

typedef void (*jhd_tls_cipher_init_pt)(void *ctx,const jhd_tls_cipher_info_t* info);


void jhd_tls_cipher_size_init(void *ctx,const jhd_tls_cipher_info_t *info);
void jhd_tls_ciphers_init();

#if !defined(JHD_TLS_INLINE)
/**
 * \brief This function retrieves the list of ciphers supported by the generic
 * cipher module.
 *
 * \return      A statically-allocated array of ciphers. The last entry
 *              is zero.
 */
const int *jhd_tls_cipher_list();

#else
#define jhd_tls_cipher_list() jhd_tls_cipher_supported

#endif
/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher name.
 *
 * \param cipher_name   Name of the cipher to search for.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_name.
 * \return              NULL if the associated cipher information is not found.
 */
const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_string(const char *cipher_name);

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher type.
 *
 * \param cipher_type   Type of the cipher to search for.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_type.
 * \return              NULL if the associated cipher information is not found.
 */
const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_type(const jhd_tls_cipher_type_t cipher_type);

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher ID,
 *                      key size and mode.
 *
 * \param cipher_id     The ID of the cipher to search for. For example,
 *                      #JHD_TLS_CIPHER_ID_AES.
 * \param key_bitlen    The length of the key in bits.
 * \param mode          The cipher mode. For example, #JHD_TLS_MODE_CBC.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_id.
 * \return              NULL if the associated cipher information is not found.
 */
const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_values(const jhd_tls_cipher_id_t cipher_id, int key_bitlen, const jhd_tls_cipher_mode_t mode);

///**
// * \brief               This function initializes a \p cipher_context as NONE.
// */
//void jhd_tls_cipher_init(jhd_tls_cipher_context_t *ctx);
//
///**
// * \brief               This function frees and clears the cipher-specific
// *                      context of \p ctx. Freeing \p ctx itself remains the
// *                      responsibility of the caller.
// */
//void jhd_tls_cipher_free(jhd_tls_cipher_context_t *ctx);

///**
// * \brief               This function initializes and fills the cipher-context
// *                      structure with the appropriate values. It also clears
// *                      the structure.
// *
// * \param ctx           The context to initialize. May not be NULL.
// * \param cipher_info   The cipher to use.
// *
// * \return              \c 0 on success.
// * \return              #JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA on
// *                      parameter-verification failure.
// * \return              #JHD_TLS_ERR_CIPHER_ALLOC_FAILED if allocation of the
// *                      cipher-specific context fails.
// *
// * \internal Currently, the function also clears the structure.
// * In future versions, the caller will be required to call
// * jhd_tls_cipher_init() on the structure first.
// */
//int jhd_tls_cipher_setup(jhd_tls_cipher_context_t *ctx, const jhd_tls_cipher_info_t *cipher_info);

/**
 * \brief        This function returns the block size of the given cipher.
 *
 * \param ctx    The context of the cipher. Must be initialized.
 *
 * \return       The size of the blocks of the cipher.
 * \return       0 if \p ctx has not been initialized.
 */
static inline unsigned int jhd_tls_cipher_get_block_size(const jhd_tls_cipher_context_t *ctx) {
	return ctx->cipher_info->block_size;
}




/**
 * \brief               This function returns the type of the given cipher.
 *
 * \param ctx           The context of the cipher. Must be initialized.
 *
 * \return              The type of the cipher.
 * \return              #JHD_TLS_CIPHER_NONE if \p ctx has not been initialized.
 */
static inline jhd_tls_cipher_type_t jhd_tls_cipher_get_type(const jhd_tls_cipher_context_t *ctx) {
	return ctx->cipher_info->type;
}

/**
 * \brief               This function returns the name of the given cipher
 *                      as a string.
 *
 * \param ctx           The context of the cipher. Must be initialized.
 *
 * \return              The name of the cipher.
 * \return              NULL if \p ctx has not been not initialized.
 */
static inline const char *jhd_tls_cipher_get_name(const jhd_tls_cipher_context_t *ctx) {
	return ctx->cipher_info->name;
}


///**
// * \brief          This function returns the operation of the given cipher.
// *
// * \param ctx      The context of the cipher. Must be initialized.
// *
// * \return         The type of operation: #JHD_TLS_ENCRYPT or #JHD_TLS_DECRYPT.
// * \return         #JHD_TLS_OPERATION_NONE if \p ctx has not been initialized.
// */
//static inline jhd_tls_operation_t jhd_tls_cipher_get_operation(const jhd_tls_cipher_context_t *ctx) {
//	return ctx->operation;
//}

#endif /* JHD_TLS_CIPHER_H */
