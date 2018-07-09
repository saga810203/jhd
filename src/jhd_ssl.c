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
		if (ssl->certificate) {
			free(ssl->certificate);
			ssl->certificate = NULL;
		}
		if (ssl->certificate_key) {
			free(ssl->certificate_key);
			ssl->certificate_key = NULL;
		}
		if (ssl->ciphers) {
			free(ssl->ciphers);
			ssl->ciphers = NULL;
		}
		free(ssl);
	}
	return 0;
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

jhd_ssl_srv_t* jhd_ssl_srv_get(u_char* name) {
	jhd_queue_t *q;
	jhd_ssl_srv_t *ssl;
	for (q = jhd_queue_head(&jhd_ssl_srv_queue); q != &jhd_ssl_srv_queue; q = jhd_queue_next(q)) {
		ssl = jhd_queue_data(q, jhd_ssl_srv_t, queue);
		if (strcmp(ssl->name, name) == 0) {
			return ssl;
		}
	}
	return NULL;
}
static void jhd_ssl_info_callback(const SSL *ssl_conn, int where, int ret) {
	BIO *rbio, *wbio;
	jhd_connection_t *c;
	jhd_ssl_srv_session_t session;
	if ((where & SSL_CB_HANDSHAKE_START) && SSL_is_server(ssl_conn)) {
		c = jhd_ssl_get_connection(ssl_conn);
		session = c->ssl;
		if (session->handshaked) {
			session->renegotiation = 1;
		}
	}

	if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
		c = jhd_ssl_get_connection(ssl_conn);
		session = c->ssl;
		if (!session->handshake_buffer_set) {
			/*
			 * By default OpenSSL uses 4k buffer during a handshake,
			 * which is too low for long certificate chains and might
			 * result in extra round-trips.
			 *
			 * To adjust a buffer size we detect that buffering was added
			 * to write side of the connection by comparing rbio and wbio.
			 * If they are different, we assume that it's due to buffering
			 * added to wbio, and set buffer size.
			 */

			rbio = SSL_get_rbio(ssl_conn);
			wbio = SSL_get_wbio(ssl_conn);

			if (rbio != wbio) {
				(void) BIO_set_write_buffer_size(wbio, 1024 * 16);
				session->handshake_buffer_set = 1;
			}
		}
	}
}

static u_char* jhd_ssl_create_srv_ctx(jhd_ssl_srv_t *ssl) {
	ssl->ctx = SSL_CTX_new(SSLv23_method());

	if (ssl->ctx == NULL) {
		return "SSL_CTX_new() failed";
	}

	if (SSL_CTX_set_ex_data(ssl->ctx, jhd_ssl_server_conf_index, ssl) == 0) {
		SSL_CTX_free(ssl->ctx);
		ssl->ctx = NULL;
		return "SSL_CTX_set_ex_data() failed";
	}

	if (SSL_CTX_set_ex_data(ssl->ctx, jhd_ssl_certificate_index, NULL) == 0) {
		SSL_CTX_free(ssl->ctx);
		ssl->ctx = NULL;
		return "SSL_CTX_set_ex_data() failed";
	}

	/* client side options */

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
	SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
	SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
#endif

	/* server side options */

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
	SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
	SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
#endif

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
	/* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
	SSL_CTX_set_options(ssl->ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
	SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
#endif

#ifdef SSL_OP_TLS_D5_BUG
	SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
	SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

	SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);

#ifdef SSL_CTRL_CLEAR_OPTIONS
	/* only in 0.9.8m+ */
	SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
#endif

	if (!(ssl->protocols & JHD_SSL_SSLv2)) {
		SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv2);
	}
	if (!(ssl->protocols & JHD_SSL_SSLv3)) {
		SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv3);
	}
	if (!(ssl->protocols & JHD_SSL_TLSv1)) {
		SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1);
	}
#ifdef SSL_OP_NO_TLSv1_1
	SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
	if (!(ssl->protocols & JHD_SSL_TLSv1_1)) {
		SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
	}
#endif
#ifdef SSL_OP_NO_TLSv1_2
	SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
	if (!(ssl->protocols & JHD_SSL_TLSv1_2)) {
		SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
	}
#endif
#ifdef SSL_OP_NO_TLSv1_3
	SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
	if (!(protocols & NGX_SSL_TLSv1_3)) {
		SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
	}
#endif

#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
	SSL_CTX_set_mode(ssl->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_MODE_NO_AUTO_CHAIN
	SSL_CTX_set_mode(ssl->ctx, SSL_MODE_NO_AUTO_CHAIN);
#endif

	SSL_CTX_set_read_ahead(ssl->ctx, 1);

	SSL_CTX_set_info_callback(ssl->ctx, jhd_ssl_info_callback);
	return NULL;
}

static int jhd_ssl_servername(SSL *ssl, int *ad, void *arg) {
	const char *servername;
	jhd_connection_t *c;
	jhd_ssl_srv_session_t ses;

	size_t len;

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

	if (servername == NULL) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	c = jhd_ssl_get_connection(ssl);
	ses = c->ssl;

	if (ses->renegotiation) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,"SSL server name: \"%s\"", servername);

	len = strlen(servername);

	if (len == 0) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	if (NULL == jhd_http_find_server_by_hostname(c, servername, len)) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	return SSL_TLSEXT_ERR_OK;
}
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int jhd_ssl_alpn_select(SSL ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
	if (SSL_select_next_proto((unsigned char **) out, outlen, "\x02h2\x08http/1.1", sizeof("\x02h2\x08http/1.1") - 1, in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	return SSL_TLSEXT_ERR_OK;
}

#endif

#ifdef TLSEXT_TYPE_next_proto_neg

static int jhd_ssl_npn_advertised(SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg) {

	*out = "\x02h2\x08http/1.1";
	*outlen = sizeof("\x02h2\x08http/1.1") - 1;

	return SSL_TLSEXT_ERR_OK;

}

#endif

static RSA * jhd_ssl_rsa512_key_callback(SSL *ssl_conn, int is_export, int key_length) {
	static RSA *key = NULL;

	if (key_length != 512) {
		return NULL;
	}

#if (OPENSSL_VERSION_NUMBER < 0x10100003L && !defined OPENSSL_NO_DEPRECATED)

	if (key == NULL) {
		key = RSA_generate_key(512, RSA_F4, NULL, NULL);
	}

#endif

	return key;
}

static jhd_bool jhd_ssl_session_id_context(jhd_ssl_srv_t *ssl) {
	int n, i;
	X509 *cert;
	X509_NAME *name;
	EVP_MD_CTX *md;
	unsigned int len;
	STACK_OF(X509_NAME) *list;
	u_char buf[EVP_MAX_MD_SIZE];

	/*
	 * Session ID context is set based on the string provided,
	 * the server certificates, and the client CA list.
	 */

	md = EVP_MD_CTX_create();
	if (md == NULL) {
		return jhd_false;
	}

	if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
//        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,                     "EVP_DigestInit_ex() failed");
		//TODO:LOG
		goto failed;
	}

	if (EVP_DigestUpdate(md, "JHTTPD", sizeof("JHTTPD") - 1) == 0) {
//		ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "EVP_DigestUpdate() failed");
		goto failed;
	}

	for (cert = SSL_CTX_get_ex_data(ssl->ctx, jhd_ssl_certificate_index); cert; cert = X509_get_ex_data(cert, jhd_ssl_next_certificate_index)) {
		if (X509_digest(cert, EVP_sha1(), buf, &len) == 0) {
//			ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "X509_digest() failed");
			goto failed;
		}

		if (EVP_DigestUpdate(md, buf, len) == 0) {
//			ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "EVP_DigestUpdate() failed");
			goto failed;
		}
	}

	list = SSL_CTX_get_client_CA_list(ssl->ctx);

	if (list != NULL) {
		n = sk_X509_NAME_num(list);

		for (i = 0; i < n; i++) {
			name = sk_X509_NAME_value(list, i);

			if (X509_NAME_digest(name, EVP_sha1(), buf, &len) == 0) {
//				ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "X509_NAME_digest() failed");
				goto failed;
			}

			if (EVP_DigestUpdate(md, buf, len) == 0) {
//				ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "EVP_DigestUpdate() failed");
				goto failed;
			}
		}
	}

	if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
//		ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "EVP_DigestUpdate() failed");
		goto failed;
	}

	EVP_MD_CTX_destroy(md);

	if (SSL_CTX_set_session_id_context(ssl->ctx, buf, len) == 0) {
//		ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "SSL_CTX_set_session_id_context() failed");
		return jhd_false;
	}

	return jhd_true;

	failed:

	EVP_MD_CTX_destroy(md);

	return jhd_false;
}

u_char* jhd_ssl_srv_add(jhd_ssl_srv_t *srv_ssl) {
	jhd_queue_t *q;
	jhd_ssl_srv_t *ssl_tmp;
	u_char *p;
	if (srv_ssl->name == NULL) {
		return "no found ssl name";
	}

	for (q = jhd_queue_head(&jhd_ssl_srv_queue); q != &jhd_ssl_srv_queue; q = jhd_queue_next(q)) {
		ssl_tmp = jhd_queue_data(q, jhd_ssl_srv_t, queue);
		if (strcmp(ssl_tmp->name, srv_ssl->name) == 0) {
			return "duplicate ssl";
		}
	}
	if (srv_ssl->certificate == NULL) {
		return "no found ssl certificate";
	}
	if (srv_ssl->certificate_key == NULL) {
		return "no found ssl certificate_key";
	}
	//TODO:config buffer_size;
	srv_ssl->buffer_size = 16 * 1024;
	if (srv_ssl->ciphers == NULL) {
		srv_ssl->ciphers = "HIGH:!aNULL:!MD5";
	}
	if (srv_ssl->timeout < 60) {
		srv_ssl->timeout = 300;
	}
	if (srv_ssl->protocols == 0) {
		srv_ssl->protocols = 1 | JHD_SSL_TLSv1 | JHD_SSL_TLSv1_1 | JHD_SSL_TLSv1_2;
	}
	p = jhd_ssl_create_srv_ctx(srv_ssl);
	if (p)
		return p;

	jhd_queue_insert_tail(&jhd_ssl_srv_queue, &srv_ssl->queue);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

	if (SSL_CTX_set_tlsext_servername_callback(srv_ssl->ctx,jhd_ssl_servername) == 0) {
//		ngx_log_error(NGX_LOG_WARN, cf->log, 0, "nginx was built with SNI support, however, now it is linked "
//				"dynamically to an OpenSSL library which has no tlsext support, "
//				"therefore SNI is not available");
		//TODO:LOG
	}

#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	SSL_CTX_set_alpn_select_cb(srv_ssl->ctx, jhd_ssl_alpn_select, NULL);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
	SSL_CTX_set_next_protos_advertised_cb(srv_ssl->ctx, jhd_ssl_npn_advertised, NULL);
#endif

	if (SSL_CTX_set_cipher_list(srv_ssl->ctx, (char *) srv_ssl->ciphers) == 0) {
		return "SSL_CTX_set_cipher_list() failed";
	}

	SSL_CTX_set_options(srv_ssl->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

#if (OPENSSL_VERSION_NUMBER < 0x10100001L && !defined LIBRESSL_VERSION_NUMBER)
	/* a temporary 512-bit RSA key is required for export versions of MSIE */
	SSL_CTX_set_tmp_rsa_callback(srv_ssl->ctx, jhd_ssl_rsa512_key_callback);

#endif

#if (defined SSL_CTX_set1_curves_list || defined SSL_CTRL_SET_CURVES_LIST)

	/*
	 * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
	 * curve previously supported.  By default an internal list is used,
	 * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
	 * and X25519 in OpenSSL 1.1.0+.
	 *
	 * By default a curve preferred by the client will be used for
	 * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
	 * be used to prefer server curves instead, similar to what it
	 * does for ciphers.
	 */

	SSL_CTX_set_options(srv_ssl->ctx, SSL_OP_SINGLE_ECDH_USE);

#if SSL_CTRL_SET_ECDH_AUTO
	/* not needed in OpenSSL 1.1.0+ */
	SSL_CTX_set_ecdh_auto(srv_ssl->ctx, 1);
#endif
#endif

	SSL_CTX_set_timeout(srv_ssl->ctx, (long) srv_ssl->timeout);

	if (!jhd_ssl_session_id_context(srv_ssl->ctx)) {
		return "create ssl session context error";
	}
	SSL_CTX_set_session_cache_mode(srv_ssl->ctx, SSL_SESS_CACHE_OFF);
	return NULL;

}

void jhd_ssl_free() {
#if OPENSSL_VERSION_NUMBER < 0x10100003L

	EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif

#endif
}

static void jhd_ssl_close(jhd_connection_t *c) {
	jhd_ssl_session_t *sc;
	sc = c->ssl;
	c->close = sc->c_close;
	SSL_free(sc->session);
	jhd_free(sc);
	c->close(c);
}

jhd_bool jhd_ssl_create_connection(jhd_connection_t *c, int flags) {

	jhd_ssl_session_t *sc;

	log_notice("%s", "enter function");

	sc = jhd_malloc(sizeof(jhd_ssl_session_t));
	if (sc == NULL) {
		log_warn("OutOfMemory with:%s", "alloc jhd_ssl_srv_session_t");
		log_notice("leave function return with:%s", "OutOfMemory");
		return jhd_false;
	}

	sc->buffer = ((flags & JHD_SSL_BUFFER) != 0);

	sc->session_ctx = c->listening->ssl->ctx;

	sc->session = SSL_new(sc->session_ctx);

	if (sc->session == NULL) {
		jhd_free(sc);
		log_warn("%s", "exec SSL_new failed");
		log_notice("leave function return with:%s", "exec SSL_new");
		return jhd_false;
	}

	if (SSL_set_fd(sc->session, c->fd) == 0) {
		SSL_free(sc->session);
		jhd_free(sc);
		log_warn("%s", "exec SSL_set_fd(sc->session, c->fd) failed");
		log_notice("leave function return with:%s", "exec SSL_set_fd");
		return jhd_false;
	}

	if (flags & JHD_SSL_CLIENT) {
		SSL_set_connect_state(sc->session);
		sc->client = 1;

	} else {
		SSL_set_accept_state(sc->session);
		sc->client = 0;
	}

	if (SSL_set_ex_data(sc->session, jhd_ssl_connection_index, c) == 0) {
		SSL_free(sc->session);
		jhd_free(sc);
		log_warn("%s", "SSL_set_ex_data(sc->session, jhd_ssl_connection_index, c) failed");
		log_notice("leave function return with:%s", "exec SSL_set_ex_data");
		return jhd_false;
	}
	sc->handshaked = 0;
	sc->renegotiation = 0;
	sc->buffer = 0;
	sc->no_wait_shutdown = 0;
	sc->no_send_shutdown = 0;
	sc->handshake_buffer_set = 0;
	sc->last = 0;
	sc->c_close = c->close;
	c->close = jhd_ssl_close;


	c->ssl = sc;

	return jhd_true;
}


ssize_t
jhd_ssl_recv(jhd_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;



    if (c->ssl->last == NGX_ERROR) {
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    ngx_ssl_clear_error(c->log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        n = SSL_read(c->ssl->connection, buf, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = ngx_ssl_handle_recv(c, n);

        if (c->ssl->last == NGX_OK) {

            size -= n;

            if (size == 0) {
                c->read->ready = 1;
                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            if (c->ssl->last != NGX_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NGX_ERROR:
            c->read->error = 1;

            /* fall through */

        case NGX_AGAIN:
            return c->ssl->last;
        }
    }
}



int jhd_ssl_handshake(jhd_connection_t *c){
	 int        n, sslerr;
	    int  err;


	    jhd_ssl_srv_session_t *ssl;


	    log_notice("%s","enter function");
	    ssl = c->ssl;


	    while (ERR_peek_error()) {
	    ;
	       }

	       ERR_clear_error();

	    n = SSL_do_handshake(ssl->session);



	    if (n == 1) {

	        ssl->handshaked = 1;

	        c->recv = ngx_ssl_recv;
	        c->send = ngx_ssl_write;


	#if OPENSSL_VERSION_NUMBER < 0x10100000L
	#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS

	        /* initial handshake done, disable renegotiation (CVE-2009-3555) */
	        if (c->ssl->connection->s3 && SSL_is_server(c->ssl->connection)) {
	            c->ssl->connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
	        }

	#endif
	#endif

	        return NGX_OK;
	    }

	    sslerr = SSL_get_error(c->ssl->connection, n);

	    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

	    if (sslerr == SSL_ERROR_WANT_READ) {
	        c->read->ready = 0;
	        c->read->handler = ngx_ssl_handshake_handler;
	        c->write->handler = ngx_ssl_handshake_handler;

	        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
	            return NGX_ERROR;
	        }

	        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
	            return NGX_ERROR;
	        }

	        return NGX_AGAIN;
	    }

	    if (sslerr == SSL_ERROR_WANT_WRITE) {
	        c->write->ready = 0;
	        c->read->handler = ngx_ssl_handshake_handler;
	        c->write->handler = ngx_ssl_handshake_handler;

	        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
	            return NGX_ERROR;
	        }

	        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
	            return NGX_ERROR;
	        }

	        return NGX_AGAIN;
	    }

	    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

	    c->ssl->no_wait_shutdown = 1;
	    c->ssl->no_send_shutdown = 1;
	    c->read->eof = 1;

	    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
	        ngx_connection_error(c, err,
	                             "peer closed connection in SSL handshake");

	        return NGX_ERROR;
	    }

	    c->read->error = 1;

	    ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

	    return NGX_ERROR;
}
