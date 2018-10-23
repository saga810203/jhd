#ifndef JHD_TLS_PK_WRAP_H
#define JHD_TLS_PK_WRAP_H


#include <tls/jhd_tls_config.h>

#include <tls/jhd_tls_pk.h>

#define JHD_TLS_SSL_SIG_ANON                 0
#define JHD_TLS_SSL_SIG_RSA                  1
#define JHD_TLS_SSL_SIG_ECDSA                3

struct jhd_tls_pk_info_t {
	/** Public key type */
	unsigned char pk_flag;
	uint16_t  ctx_size;
	/** Type name */
	const char *name;
    void (*pk_ctx_init_func)(void *);
	/** Get key size in bits */
	size_t (*pk_get_bitlen)(const void *);
	/** Verify signature */
	int (*pk_verify_func)(void *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);

	/** Make signature */
	int (*pk_sign_func)(void *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t *sig_len);

	/** Decrypt message */
	int (*pk_decrypt_func)(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize);

	/** Encrypt message */
	int (*pk_encrypt_func)(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize);

	/** Check public-private key pair */
	int (*pk_check_pair_func)(const void *pub, const void *prv);
};


extern const jhd_tls_pk_info_t jhd_tls_rsa_info;


//extern const jhd_tls_pk_info_t jhd_tls_eckey_info;
//extern const jhd_tls_pk_info_t jhd_tls_eckeydh_info;

extern const jhd_tls_pk_info_t jhd_tls_ecdsa_info;



#endif /* JHD_TLS_PK_WRAP_H */
