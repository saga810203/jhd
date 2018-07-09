#include <jhd_http.h>
#include <jhd_pool.h>

static jhd_queue_t jhd_http_server_queue = { &jhd_http_server_queue, &jhd_http_server_queue };

jhd_bool jhd_http_server_add(jhd_http_server_t * srv) {
	if(srv->listening_count == 0){
		//TODO
	}


}

jhd_bool jhd_http_server_listening_add(jhd_http_server_t *srv, u_char *addr_text, size_t len) {
	void **old_lis;
	jhd_listening_t *lis;
	lis = jhd_listening_get(addr_text, len);
	if (lis) {
		old_lis = srv->listenings;

		srv->listenings = calloc(sizeof(jhd_listening_t*) * (srv->listening_count + 1));
		if (srv->listenings == NULL) {
			srv->listenings = old_lis;
			return jhd_false;

		}
		if (old_lis) {
			memcpy(srv->listenings, old_lis, sizeof(jhd_listening_t*) * srv->listening_count);
			free(old_lis);
		}
		srv->listenings[srv->listening_count] = lis;
		++srv->listening_count;
		return jhd_true;
	}
	//TODO:LOG
	return jhd_false;

}

jhd_bool jhd_http_server_servername_add(jhd_http_server_t *srv, u_char *name, size_t len) {
	void **old_names;
	u_char* sn;
	sn = malloc(len + sizeof(u_int16_t));
	if (sn == NULL) {
		return jhd_false;
	}
	*((u_int16_t*) sn) = len;
	memcpy(sn + 2, name, len);

	old_names = srv->servernames;

	srv->servernames = calloc(sizeof(void*) * (srv->servername_count + 1));
	if (srv->servernames == NULL) {
		srv->servernames = old_names;
		free(sn);
		return jhd_false;

	}
	if (old_names) {
		memcpy(srv->servernames, old_names, sizeof(void*) * srv->servername_count);
		free(old_names);
	}
	srv->servernames[srv->servername_count] = sn;
	++srv->servername_count;
	return jhd_true;
}
void jhd_http_server_free(jhd_http_server_t *s) {
	u_int32_t i;
	if (s->servername_count > 0) {
		for (i = 0; i < s->servername_count; ++i) {
			free(s->servernames[i]);
		}
		free(s->servernames);
		s->servername_count = 0;
		s->servernames = NULL;
	}
}

jhd_http_server_t* jhd_http_find_server_by_host_name(jhd_connection_t *c, u_char* servername, size_t servername_len) {
	jhd_listening_t *lis;
	u_int32_t i, j;
	u_char *p;
	u_int16_t sl;
	jhd_http_server_t *s;

	lis = c->listening;
	for (i = 0; i < lis->http_server_count; ++i) {
		s = lis->http_servers[i];
		for (j = 0; j < s->servername_count; ++j) {
			p = s->servernames[j];
			sl = *((u_int16_t*) p);
			if (sl == servername_len) {
				p += sizeof(u_int16_t);
				if (strncmp(p, servername, sl) == 0) {
					return s;
				}
			}
		}
	}
	return NULL;
}


void jhd_http_empty_handler(jhd_event_t *ev){
	log_notice("%s","exec function");
}
void jhd_http_h1_wait_request_handler(jhd_event_t *rev){



}

void jhd_http_h1_close_connection(jhd_connection_t *c){
	jhd_h1c_t   *hc;

	jhd_connection_close_pt cl;



	log_notice("%s","enter function");

	hc = c->data;
	cl=hc->c_close_pt;








	jhd_free(hc);
	cl(c);
	log_notice("%s","leave function");

}

static void jhd_http_ssl_handshake(jhd_event_t *rev) {
	u_char *p, buf[128];
	size_t size;
	ssize_t n;
	int err;
	ssize_t rc;
	jhd_connection_t *c;


	log_notice("%s","enter function");

	c = rev->data;
	if (rev->timedout) {
		log_info("%s", "client timed out");
		rev->timedout = 0;
		if(c->write.queue.next){
			jhd_queue_only_remove(&(c->write.queue));
		}
		c->close(c);
		log_notice("leave function return with:%s", "connection read timeout");
		return;
	}



	size = 1;
    for(;;){
		n = recv(c->fd, (char *) buf, size, MSG_PEEK);
		if (n == -1) {
			err = errno;
			if (err == EAGAIN) {
				log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",MSG_PEEK)==%"PRId64",errno=%s", c->fd, (u_int64_t )buf, size, n, "EAGAIN");

				if(!rev->timer.key){
					jhd_add_timer(rev,c->listening->accept_timeout);
					log_notice("leave function return with:%s", "EAGAIN");
					return;
				}
				return;
			}else if(err == EINTR){
				log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",MSG_PEEK)==%"PRId64",errno=%s", c->fd, (u_int64_t )buf, size, n, "EINTR");
			}else{
				log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",MSG_PEEK)==%"PRId64",errno=%d", c->fd, (u_int64_t )buf, size, n, err);


			}
			log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",MSG_PEEK)==%"PRId64",errno=%d", c->fd, (u_int64_t )buf, size, n, err);
			c->close(c);
			log_notice("leave function return with:%s", "connection read error");
			return;
		}else{
			break;
		}
    }

	if (n == 1) {
		if (buf[0] & 0x80 /* SSLv2 */|| buf[0] == 0x16 /* SSLv3/TLSv1 */) {
			log_debug("ssl first byte is %d",buf[0]);


			if(!jhd_ssl_create_connection(c,JHD_SSL_BUFFER)){
						c->close(c);
						log_notice("leave function return with:%s", "create ssl session");
						return;
			}

			rc = ngx_ssl_handshake(c);

			if (rc == NGX_AGAIN) {

				if (!rev->timer_set) {
					ngx_add_timer(rev, c->listening->post_accept_timeout);
				}

				ngx_reusable_connection(c, 0);

				c->ssl->handler = ngx_http_ssl_handshake_handler;
				return;
			}

			ngx_http_ssl_handshake_handler(c);

			return;
		}

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "plain http");

		c->log->action = "waiting for request";

		rev->handler = ngx_http_wait_request_handler;
		ngx_http_wait_request_handler(rev);

		return;
	}

	ngx_log_error(NGX_LOG_INFO, c->log, 0, "client closed connection");
	ngx_http_close_connection(c);
}



void jhd_http_init_connection(jhd_connection_t *c){
	jhd_h1c_t *hc;


	log_notice("%s", "enter function");

	if(c->listening->ssl){
		log_info("connection[%s] with ssl",c->listening->addr_text);

	}else{
		log_info("connection[%s] without ssl",c->listening->addr_text);
	}
	hc = jhd_malloc(sizeof(jhd_h1c_t));
	if(hc ==NULL){
		log_warn("OutOfMemory with:%s","alloc jhd_h1c_t");
		c->close(c);
		log_notice("leave function return with:%s", "OutOfMemory");
		return;
	}


	hc->c_close_pt = c->close;
	c->data = hc;
	hc->c = c;




	c->close = jhd_http_h1_close_connection;
	c->read->handler = jhd_http_h1_wait_request_handler;
	c->write->handler = jhd_http_empty_handler;


	jhd_http_h1_wait_request_handler(&c->read);

	log_notice("leave function return with:%s", "success");
}
