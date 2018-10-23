#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher.h>
#include <tls/jhd_tls_cipher_internal.h>
#include <stdlib.h>
#include <string.h>
#include <tls/jhd_tls_gcm.h>
#include <tls/jhd_tls_ccm.h>
#include <tls/jhd_tls_platform.h>


#if !defined(JHD_TLS_INLINE)
const int *jhd_tls_cipher_list(void) {
	return (jhd_tls_cipher_supported);
}
#endif

const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_type(const jhd_tls_cipher_type_t cipher_type) {
	const jhd_tls_cipher_definition_t *def;
	for (def = jhd_tls_cipher_definitions; def->info != NULL; def++){
		if (def->type == cipher_type){
			return (def->info);
		}
	}
	return ( NULL);
}

const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_string(const char *cipher_name) {
	const jhd_tls_cipher_definition_t *def;
	if ( NULL == cipher_name)
		return ( NULL);
	for (def = jhd_tls_cipher_definitions; def->info != NULL; def++){
		if (!strcmp(def->info->name, cipher_name)){
			return (def->info);
		}
	}
	return ( NULL);
}

const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_values(const jhd_tls_cipher_id_t cipher_id, int key_bitlen, const jhd_tls_cipher_mode_t mode) {
	const jhd_tls_cipher_definition_t *def;
	for (def = jhd_tls_cipher_definitions; def->info != NULL; def++){
		if (def->info->base->cipher == cipher_id && def->info->key_bitlen == (unsigned) key_bitlen && def->info->mode == mode){
			return (def->info);
		}
	}
	return ( NULL);
}




