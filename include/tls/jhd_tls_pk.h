#ifndef JHD_TLS_PK_H
#define JHD_TLS_PK_H


#include <tls/jhd_tls_config.h>


#include <tls/jhd_tls_md.h>

#include <tls/jhd_tls_rsa.h>


#include <tls/jhd_tls_ecp.h>


#include <tls/jhd_tls_ecdsa.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#define JHD_TLS_ERR_PK_ALLOC_FAILED        -0x3F80  /**< Memory allocation failed. */
#define JHD_TLS_ERR_PK_TYPE_MISMATCH       -0x3F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define JHD_TLS_ERR_PK_BAD_INPUT_DATA      -0x3E80  /**< Bad input parameters to function. */
#define JHD_TLS_ERR_PK_FILE_IO_ERROR       -0x3E00  /**< Read/write of file failed. */
#define JHD_TLS_ERR_PK_KEY_INVALID_VERSION -0x3D80  /**< Unsupported key version */
#define JHD_TLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00  /**< Invalid key tag or value. */
#define JHD_TLS_ERR_PK_UNKNOWN_PK_ALG      -0x3C80  /**< Key algorithm is unsupported (only RSA and EC are supported). */
#define JHD_TLS_ERR_PK_PASSWORD_REQUIRED   -0x3C00  /**< Private key password can't be empty. */
#define JHD_TLS_ERR_PK_PASSWORD_MISMATCH   -0x3B80  /**< Given private key password does not allow for correct decryption. */
#define JHD_TLS_ERR_PK_INVALID_PUBKEY      -0x3B00  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
#define JHD_TLS_ERR_PK_INVALID_ALG         -0x3A80  /**< The algorithm tag or value is invalid. */
#define JHD_TLS_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00  /**< Elliptic curve is unsupported (only NIST curves are supported). */
#define JHD_TLS_ERR_PK_FEATURE_UNAVAILABLE -0x3980  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
#define JHD_TLS_ERR_PK_SIG_LEN_MISMATCH    -0x3900  /**< The buffer contains a valid signature followed by more data. */
#define JHD_TLS_ERR_PK_HW_ACCEL_FAILED     -0x3880  /**< PK hardware accelerator failed. */




/**
 * \brief           Options for RSASSA-PSS signature verification.
 *                  See \c jhd_tls_rsa_rsassa_pss_verify_ext()
 */
typedef struct {
	jhd_tls_md_info_t  *md_info;
	int expected_salt_len;

} jhd_tls_pk_rsassa_pss_options;

/**
 * \brief           Types for interfacing with the debug module
 */
typedef enum {
	JHD_TLS_PK_DEBUG_NONE = 0, JHD_TLS_PK_DEBUG_MPI, JHD_TLS_PK_DEBUG_ECP,
} jhd_tls_pk_debug_type;

/**
 * \brief           Item to send to the debug module
 */
typedef struct {
	jhd_tls_pk_debug_type type;
	const char *name;
	void *value;
} jhd_tls_pk_debug_item;

/** Maximum number of item send for debugging, plus 1 */
#define JHD_TLS_PK_DEBUG_MAX_ITEMS 3

/**
 * \brief           Public key information and operations
 */
typedef struct jhd_tls_pk_info_t jhd_tls_pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct {
	const jhd_tls_pk_info_t * pk_info; /**< Public key informations        */
	void * pk_ctx; /**< Underlying public key context  */
} jhd_tls_pk_context;

/**
 * Quick access to an RSA context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an RSA context
 * before using this function!
 */
static inline jhd_tls_serializa_rsa_context *jhd_tls_pk_rsa(const jhd_tls_pk_context pk) {
	return ((jhd_tls_serializa_rsa_context *) (pk).pk_ctx);
}


/**
 * Quick access to an EC context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an EC context
 * before using this function!
 */
static inline jhd_tls_ecp_keypair *jhd_tls_pk_ec(const jhd_tls_pk_context pk) {
	return ((jhd_tls_ecp_keypair *) (pk).pk_ctx);
}





#if !defined(JHD_TLS_INLINE)
/**
 * \brief           Initialize a jhd_tls_pk_context (as NONE)
 */
void jhd_tls_pk_init(jhd_tls_pk_context *ctx);


/**
 * \brief           Tell if a context can do the operation given by type
 *
 * \param ctx       Context to test
 * \param type      Target type
 *
 * \return          0 if context can't do the operations,
 *                  1 otherwise.
 */
jhd_tls_bool jhd_tls_pk_can_do(const jhd_tls_pk_context *ctx,const jhd_tls_pk_info_t *pk_info);


#else
#define jhd_tls_pk_init(ctx)  (ctx)->pk_info = NULL; (ctx)->pk_ctx = NULL

#define jhd_tls_pk_can_do(ctx,info)  ((ctx)->pk_info == (info))
#endif

/**
 * \brief           Get the size in bits of the underlying key
 *
 * \param ctx       Context to use
 *
 * \return          Key size in bits, or 0 on error
 */
size_t jhd_tls_pk_get_bitlen(const jhd_tls_pk_context *ctx);

/**
 * \brief           Get the length in bytes of the underlying key
 * \param ctx       Context to use
 *
 * \return          Key length in bytes, or 0 on error
 */
static inline size_t jhd_tls_pk_get_len(const jhd_tls_pk_context *ctx) {
	return ((jhd_tls_pk_get_bitlen(ctx) + 7) / 8);
}



/**
 * \brief           Verify signature (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  #JHD_TLS_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in sig but its length is less than \p siglen,
 *                  or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  Use \c jhd_tls_pk_verify_ext( JHD_TLS_PK_RSASSA_PSS, ... )
 *                  to verify RSASSA_PSS signatures.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be JHD_TLS_MD_NONE, only if hash_len != 0
 */
int jhd_tls_pk_verify(jhd_tls_pk_context *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);

/**
 * \brief           Verify signature, with options.
 *                  (Includes verification of the padding depending on type.)
 *
 * \param type      Signature type (inc. possible padding type) to verify
 * \param options   Pointer to type-specific options, or NULL
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  #JHD_TLS_ERR_PK_TYPE_MISMATCH if the PK context can't be
 *                  used for this type of signatures,
 *                  #JHD_TLS_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in sig but its length is less than \p siglen,
 *                  or a specific error code.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be JHD_TLS_MD_NONE, only if hash_len != 0
 *
 * \note            If type is JHD_TLS_PK_RSASSA_PSS, then options must point
 *                  to a jhd_tls_pk_rsassa_pss_options structure,
 *                  otherwise it must be NULL.
 */
int jhd_tls_pk_verify_ext(const jhd_tls_pk_info_t *pk_info, const void *options, jhd_tls_pk_context *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash,
        size_t hash_len, const unsigned char *sig, size_t sig_len);

/**
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       PK context to use - must hold a private key
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Place to write the signature
 * \param sig_len   Number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            For RSA, md_alg may be JHD_TLS_MD_NONE if hash_len != 0.
 *                  For ECDSA, md_alg may never be JHD_TLS_MD_NONE.
 */
int jhd_tls_pk_sign(jhd_tls_pk_context *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t *sig_len);

/**
 * \brief           Decrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use - must hold a private key
 * \param input     Input to decrypt
 * \param ilen      Input size
 * \param output    Decrypted output
 * \param olen      Decrypted message length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int jhd_tls_pk_decrypt(jhd_tls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize);

/**
 * \brief           Encrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param input     Message to encrypt
 * \param ilen      Message size
 * \param output    Encrypted output
 * \param olen      Encrypted output length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int jhd_tls_pk_encrypt(jhd_tls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize);

/**
 * \brief           Check if a public-private pair of keys matches.
 *
 * \param pub       Context holding a public key.
 * \param prv       Context holding a private (and public) key.
 *
 * \return          0 on success or JHD_TLS_ERR_PK_BAD_INPUT_DATA
 */
int jhd_tls_pk_check_pair(const jhd_tls_pk_context *pub, const jhd_tls_pk_context *prv);


/**
 * \brief           Access the type name
 *
 * \param ctx       Context to use
 *
 * \return          Type name on success, or "invalid PK"
 */
const char * jhd_tls_pk_get_name(const jhd_tls_pk_context *ctx);



/** \ingroup pk_module */
/**
 * \brief           Parse a private key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 * \param pwd       password for decryption (optional)
 * \param pwdlen    size of the password
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with jhd_tls_pk_init() or reset with jhd_tls_pk_free(). If you need a
 *                  specific key type, check the result with jhd_tls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int jhd_tls_pk_parse_key(jhd_tls_pk_context *ctx, const unsigned char *key, size_t keylen);

/** \ingroup pk_module */
/**
 * \brief           Parse a public key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with jhd_tls_pk_init() or reset with jhd_tls_pk_free(). If you need a
 *                  specific key type, check the result with jhd_tls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int jhd_tls_pk_parse_public_key(jhd_tls_pk_context *ctx, const unsigned char *key, size_t keylen);

#if defined(JHD_TLS_FS_IO)
/** \ingroup pk_module */
/**
 * \brief           Load and parse a private key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the private key from
 * \param password  password to decrypt the file (can be NULL)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with jhd_tls_pk_init() or reset with jhd_tls_pk_free(). If you need a
 *                  specific key type, check the result with jhd_tls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int jhd_tls_pk_parse_keyfile(jhd_tls_pk_context *ctx, const char *path, const char *password);

/** \ingroup pk_module */
/**
 * \brief           Load and parse a public key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the public key from
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with jhd_tls_pk_init() or reset with jhd_tls_pk_free(). If
 *                  you need a specific key type, check the result with
 *                  jhd_tls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int jhd_tls_pk_parse_public_keyfile(jhd_tls_pk_context *ctx, const char *path);
#endif /* JHD_TLS_FS_IO */



/**
 * \brief           Write a private key to a PKCS#1 or SEC1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int jhd_tls_pk_write_key_der(jhd_tls_pk_context *ctx, unsigned char *buf, size_t size);

/**
 * \brief           Write a public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int jhd_tls_pk_write_pubkey_der(jhd_tls_pk_context *ctx, unsigned char *buf, size_t size);


/**
 * \brief           Write a public key to a PEM string
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int jhd_tls_pk_write_pubkey_pem(jhd_tls_pk_context *ctx, unsigned char *buf, size_t size);

/**
 * \brief           Write a private key to a PKCS#1 or SEC1 PEM string
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int jhd_tls_pk_write_key_pem(jhd_tls_pk_context *ctx, unsigned char *buf, size_t size);



/*
 * WARNING: Low-level functions. You probably do not want to use these unless
 *          you are certain you do ;)
 */


/**
 * \brief           Parse a SubjectPublicKeyInfo DER structure
 *
 * \param p         the position in the ASN.1 data
 * \param end       end of the buffer
 * \param pk        the key to fill
 *
 * \return          0 if successful, or a specific PK error code
 */
int jhd_tls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end, jhd_tls_pk_context *pk,void *event);

int jhd_tls_pk_parse_subpubkey_by_master(unsigned char **p, const unsigned char *end, jhd_tls_pk_context *pk);




#endif /* JHD_TLS_PK_H */
