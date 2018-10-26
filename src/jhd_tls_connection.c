#include <jhd_config.h>
#include <jhd_log.h>
#include <errno.h>
#include <sys/types.h>
#include <jhd_connection.h>
#include <tls/jhd_tls_ssl_internal.h>

int jhd_connection_tls_handshark(jhd_connection_t *c) {
	jhd_tls_ssl_context *ssl;
	int ret;
	ssl = (jhd_tls_ssl_context*) c->ssl;
	if (ssl->conf->server_side) {
		while (ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER) {
			ret = jhd_tls_ssl_handshake_server_step(c);
			if (ret /*!=JHD_OK*/) {
				return ret;
			}
		}
	} else {
		while (ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER) {
			ret = jhd_tls_ssl_handshake_client_step(c);
			if (ret /*!=JHD_OK*/) {
				return ret;
			}
		}
	}
	return JHD_OK;
}
ssize_t jhd_connection_tls_recv(jhd_connection_t *c, u_char *buf, size_t size) {
	jhd_tls_ssl_context *ssl;
	int ret;
	ssl = (jhd_tls_ssl_context*) c->ssl;
	if (ssl->conf->server_side) {
		while (ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER) {
			ret = jhd_tls_ssl_handshake_server_step(c);
			if (ret /*!=JHD_OK*/) {
				return ret;
			}
		}
	} else {
		while (ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER) {
			ret = jhd_tls_ssl_handshake_client_step(c);
			if (ret /*!=JHD_OK*/) {
				return ret;
			}
		}
	}
	log_assert(c->recv != jhd_connection_tls_recv);
	return jhd_tls_ssl_read(c, buf, size);
}

ssize_t jhd_connection_tls_send(jhd_connection_t *c, u_char *buf, size_t size) {
	jhd_tls_ssl_context *ssl;
	int ret;
	ssl = (jhd_tls_ssl_context*) c->ssl;
	if (ssl->conf->server_side) {
		while (ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER) {
			ret = jhd_tls_ssl_handshake_server_step(c);
			if (ret /*!=JHD_OK*/) {
				return ret;
			}
		}
	} else {
		while (ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER) {
			ret = jhd_tls_ssl_handshake_client_step(c);
			if (ret /*!=JHD_OK*/) {
				return ret;
			}
		}
	}
    log_assert(c->send !=  jhd_connection_tls_send);
	return c->send(c, buf, size);
}

void jhd_connection_tls_empty_write(jhd_event_t * ev) {
	jhd_connection_t *c = ev->data;
	jhd_tls_ssl_context *ssl;
	size_t n;
	int err;
	log_notice("=> jhd_connection_tls_noop_write");
	if (c->ssl) {
		ssl = c->ssl;
		if (ssl->out_msglen) {
			for (;;) {
				n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
				if (n >= 0) {
					ssl->out_msglen -= n;
					ssl->out_offt += n;
					log_debug("send(fd:%d,buf:0x%lX,size:%u,0)==%ld", c->fd,ssl->out_offt, ssl->out_msglen,n);
					log_notice("<= jhd_connection_tls_noop_write(...) with JHD_OK");
					//FIXME wait send(...)==(-1) then return   ???????????
					break;
				} else {
					err = errno;
					if (err == EAGAIN) {
						log_debug("send(fd:%d,buf:0x%lX,size:%u,0)==(-1),errno==EAGAIN", c->fd, (u_int64_t ) ssl->out_offt, ssl->out_msglen);
						log_notice("<= jhd_connection_tls_noop_write(...) with JHD_AGAIN");
						break;
					} else if (err != EINTR) {
						log_debug("exec send(fd:%d,buf:0x%lX,size:%u,0)==(-1),errno==%d", c->fd, (u_int64_t ) ssl->out_offt, ssl->out_msglen, err);
						log_notice("<= jhd_connection_tls_noop_write(...) with JHD_ERROR");
						c->recv = jhd_connection_error_send;
						break;
					}
				}
				log_debug("send(fd:%d,buf:0x%lX,size:%u,0)==(-1),errno==EINTR", c->fd, (u_int64_t )ssl->out_offt, ssl->out_msglen);
			}
		}
	}
}



void jhd_connection_tls_close(jhd_connection_t *c){
	log_assert_worker();
	log_assert(c->ssl != NULL);
	jhd_tls_ssl_context_free(c->ssl);
	jhd_connection_close(c);
}
