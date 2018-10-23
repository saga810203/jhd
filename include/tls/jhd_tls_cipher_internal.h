#ifndef JHD_TLS_CIPHER_WRAP_H
#define JHD_TLS_CIPHER_WRAP_H


#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher.h>

#include <tls/jhd_tls_cipher.h>

/**
 * Base cipher information. The non-mode specific functions and values.
 */
struct jhd_tls_cipher_base_t {
	jhd_tls_cipher_id_t cipher;
	uint16_t ctx_size;
	jhd_tls_cipher_init_pt cipher_ctx_init;
//	jhd_tls_cipher_ecb_pt ecb_func;
//	jhd_tls_cipher_cbc_pt cbc_func;

	jhd_tls_cipher_ecb_encrypt_pt ecb_encrypt_func;
	jhd_tls_cipher_ecb_decrypt_pt ecb_decrypt_func;
	jhd_tls_cipher_cbc_encrypt_pt cbc_encrypt_func;
	jhd_tls_cipher_cbc_encrypt_pt cbc_decrypt_func;


	jhd_tls_cipher_setkey_enc_pt setkey_enc_func;
	jhd_tls_cipher_setkey_dec_pt setkey_dec_func;
};

typedef struct {
	jhd_tls_cipher_type_t type;
	const jhd_tls_cipher_info_t *info;
} jhd_tls_cipher_definition_t;

extern const jhd_tls_cipher_definition_t jhd_tls_cipher_definitions[];

extern int jhd_tls_cipher_supported[];

#endif /* JHD_TLS_CIPHER_WRAP_H */
