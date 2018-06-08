/*
 * jhd_ssl.c
 *
 *  Created on: Jun 8, 2018
 *      Author: root
 */

#include <jhd_config.h>

#include <jhd_ssl.h>
#include <jhd_core.h>
#include <jhd_event.h>

int jhd_ssl_connection_index;
int jhd_ssl_server_conf_index;
int jhd_ssl_session_cache_index;
int jhd_ssl_session_ticket_keys_index;
int jhd_ssl_certificate_index;
int jhd_ssl_next_certificate_index;
int jhd_ssl_certificate_name_index;
int jhd_ssl_stapling_index;

static jhd_listener_t jhd_ssl_listener;

jhd_bool jhd_ssl_init() {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L

	if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
		ngx_ssl_error(NGX_LOG_ALERT, log, 0, "OPENSSL_init_ssl() failed");
		return jhd_false;
	}

	/*
	 * OPENSSL_init_ssl() may leave errors in the error queue
	 * while returning success
	 */

	ERR_clear_error();

#else

	OPENSSL_config(NULL);

	SSL_library_init();
	SSL_load_error_strings();

	OpenSSL_add_all_algorithms();

#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef SSL_OP_NO_COMPRESSION
	{
		/*
		 * Disable gzip compression in OpenSSL prior to 1.0.0 version,
		 * this saves about 522K per connection.
		 */
		int n;
		STACK_OF(SSL_COMP) *ssl_comp_methods;

		ssl_comp_methods = SSL_COMP_get_compression_methods();
		n = sk_SSL_COMP_num(ssl_comp_methods);

		while (n--) {
			(void) sk_SSL_COMP_pop(ssl_comp_methods);
		}
	}
#endif
#endif

	jhd_ssl_connection_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	if (jhd_ssl_connection_index == -1) {
		//TODO:LOG
		printf("SSL_get_ex_new_index() failed");
		return jhd_false;
	}

	jhd_ssl_server_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
	NULL);
	if (jhd_ssl_server_conf_index == -1) {
		printf("SSL_CTX_get_ex_new_index() failed");
		return jhd_false;
	}

	jhd_ssl_session_cache_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
	NULL);
	if (jhd_ssl_session_cache_index == -1) {
		printf("SSL_CTX_get_ex_new_index() failed");
		return jhd_false;
	}

	jhd_ssl_session_ticket_keys_index = SSL_CTX_get_ex_new_index(0, NULL, NULL,
	NULL, NULL);
	if (jhd_ssl_session_ticket_keys_index == -1) {
		printf("SSL_CTX_get_ex_new_index() failed");
		return jhd_false;
	}

	jhd_ssl_certificate_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
	NULL);
	if (jhd_ssl_certificate_index == -1) {
		printf("SSL_CTX_get_ex_new_index() failed");
		return jhd_false;
	}

	jhd_ssl_next_certificate_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
	NULL);
	if (jhd_ssl_next_certificate_index == -1) {
		printf("X509_get_ex_new_index() failed");
		return jhd_false;
	}

	jhd_ssl_certificate_name_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
	NULL);

	if (jhd_ssl_certificate_name_index == -1) {
		printf("X509_get_ex_new_index() failed");
		return jhd_false;
	}

	jhd_ssl_stapling_index = X509_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	if (jhd_ssl_stapling_index == -1) {
		printf("X509_get_ex_new_index() failed");
		return jhd_false;
	}
	return jhd_true;
}

void jhd_ssl_free() {
#if OPENSSL_VERSION_NUMBER < 0x10100003L

	EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif

#endif
}
