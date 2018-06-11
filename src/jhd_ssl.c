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

static jhd_queue_t jhd_ssl_srv_queue;

static int jhd_ssl_listener_handler(jhd_listener_t *ev) {
	jhd_queue_t *q;
	jhd_ssl_srv_t *ssl;
	SSL_CTX *ctx;
	while (!jhd_queue_empty(&jhd_ssl_srv_queue)) {
		q = jhd_queue_head(&jhd_ssl_srv_queue);
		jhd_queue_only_remove(q);

		ssl = jhd_queue_data(q, jhd_ssl_srv_t, queue);
		X509 *cert, *next;
		ctx = ssl->ctx;
		if (ctx) {

			cert = SSL_CTX_get_ex_data(ctx, jhd_ssl_certificate_index);

			while (cert) {
				next = X509_get_ex_data(cert, jhd_ssl_next_certificate_index);
				X509_free(cert);
				cert = next;
			}

			SSL_CTX_free(ctx);
		}

		if (ssl->name) {
			free(ssl->name);
			ssl->name = NULL;
		}
		if (ssl->certificates) {
			free(ssl->certificates);
			ssl->certificates = NULL;
		}
		if (ssl->certificate_keys) {
			free(ssl->certificate_keys);
			ssl->certificate_keys = NULL;
		}
		if (ssl->ciphers) {
			free(ssl->ciphers);
			ssl->ciphers = NULL;
		}

		free(ssl);

	}

}

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
	jhd_queue_init(&jhd_ssl_srv_queue);

	jhd_ssl_listener.handler = jhd_ssl_listener_handler;
	jhd_add_master_shutdown_listener(&jhd_ssl_listener);

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
