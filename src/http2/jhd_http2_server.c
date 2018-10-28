#include <http2/jhd_http2_server.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>

void jhd_http2_only_by_clean_server_connection_start(jhd_connection_t *c){

}
void jhd_http2_only_by_tls_server_connection_start(jhd_connection_t *c){

}


static char *  jhd_http_alpn_list[]={"h2","http/1.1",NULL};

static void jhd_http2_server_connection_close(jhd_connection_t *c){
	//TODO:
}

static int jhd_http2_server_connection_alloc(void **pcon,jhd_event_t *ev,jhd_http2_connection_conf *conf){
      jhd_http2_connection *hc;
      jhd_connection_t *c;

      log_assert_worker();
      log_notice("==>%s",__FUNCTION__);
      c= ev->data;
      hc =*pcon;
      if(hc == NULL){
    	  *pcon = hc = jhd_alloc(sizeof(jhd_http2_connection));
    	  if(hc == NULL){
    		  jhd_wait_mem(ev,sizeof(jhd_http2_connection));
    		  jhd_event_add_timer(ev,conf->wait_mem_timeout);
    		  return JHD_AGAIN;
    	  }
    	  memset(hc,0,sizeof(jhd_http2_connection));
    	//TODO:init
    	  hc->conf = conf;
    	  hc->close_pt = c->close;
    	  c->close = jhd_http2_server_connection_close;
      }




      return JHD_OK;
}


void jhd_http11_init_with_alpn(jhd_event_t *ev){
//	jhd_connection_t *c;
//	jhd_http2_connection_conf *conf;
//	int ret;
//	log_assert_worker();
//	c = ev->data;
//
//	jhd_event_with_timeout(ev){
//		c->close(c);
//		return;
//	}
//
//	conf = &((jhd_listening_config_ctx_with_alpn*)(c->listening->lis_ctx))->h2_conf;
//
//	if(JHD_OK !=jhd_http2_server_connection_alloc(&c->data,ev,conf)){
//		return;
//	}
//
//




}


void jhd_http2_read_preface(jhd_event_t *ev){
		u_char preface[24];
		int ret;
		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		event_c = ev->data;
		jhd_event_with_timeout(ev){
			log_err("timedout");
			event_c->close(event_c);
			log_notice("<==%s with timedout",__FUNCTION__);
			return;
		}
		event_h2c = event_c->data;
		log_assert(event_h2c->recv.state< 24);
		ret = event_c->recv(event_c,preface,24 - event_h2c->recv.state);
		if(ret >0){
			log_buf_info("read buf=>",preface,ret);
			if(memcmp(preface,jhd_http2_preface+ event_h2c->recv.state,ret)!=0){
				log_err("invalid http2 preface");
				event_c->close(event_c);
				log_notice("<==% with invalid httppreface",__FUNCTION__);
				return;
			}
			event_h2c->recv.state += ret;
			if(event_h2c->recv.state == 24){
				log_info("read http2 preface success");
				event_h2c->recv.state = 0;
				ev->handler = jhd_http2_read_frame_header;
				jhd_http2_read_frame_header(ev);
			}else{
				JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
			}
		}else if(ret == JHD_AGAIN){
			JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
		}else{
			event_c->close(event_c);
		}
		log_notice("<==%s",__FUNCTION__);
}

void jhd_http2_init_with_alpn(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection_conf *conf;
	int ret;
	log_assert_worker();
	c = ev->data;

	jhd_event_with_timeout(ev){
		c->close(c);
		return;
	}

	conf = &((jhd_listening_config_ctx_with_alpn*)(c->listening->lis_ctx))->h2_conf;

	if(JHD_OK !=jhd_http2_server_connection_alloc(&c->data,ev,conf)){
		return;
	}

	ev->handler = jhd_http2_read_preface;
	jhd_http2_read_preface(ev);
}


void jhd_http2_alpn_handshake(jhd_event_t *ev){
	jhd_connection_t *c;
	int ret;
	log_assert_worker();
	c = ev->data;

	jhd_event_with_timeout(ev){
		c->close(c);
		return;
	}

	ret = jhd_connection_tls_handshark(c);
	if(ret == JHD_OK){

		if(((jhd_tls_ssl_context*)(c->ssl))->alpn_chosen ==jhd_http_alpn_list[0]){
			ev->handler = jhd_http2_init_with_alpn;
			jhd_http2_init_with_alpn(ev);
		}else{
			ev->handler = jhd_http11_init_with_alpn;
			jhd_http11_init_with_alpn(ev);
		}
	}else if(ret != JHD_AGAIN){
		if(c->write.queue.next){
			jhd_queue_remove(&c->write);
		}
		c->close(c);
	}
}

void jhd_http2_alpn_recv_start(jhd_event_t *ev){
	jhd_connection_t *c;
	int ret;
	log_assert_worker();
	c = ev->data;

	jhd_event_with_timeout(ev){
		c->close(c);
		return;
	}
	if(c->ssl == NULL){
		if(JHD_OK != jhd_tls_ssl_context_alloc((jhd_tls_ssl_context**)(&c->ssl),(jhd_tls_ssl_config*)(c->listening->ssl),ev)){
			jhd_event_add_timer(ev,c->listening->wait_mem_timeout);
			return;
		}
		c->close = jhd_connection_tls_close;
	}
	ret = jhd_connection_tls_handshark(c);
	if(ret == JHD_AGAIN){
		ev->handler = jhd_http2_alpn_handshake;
		jhd_event_add_timer(ev,c->listening->read_timeout);
	}else if(ret == JHD_OK){
		if(((jhd_tls_ssl_context*)(c->ssl))->alpn_chosen ==jhd_http_alpn_list[0]){
			ev->handler = jhd_http2_init_with_alpn;
			jhd_http2_init_with_alpn(ev);
		}else{
			ev->handler = jhd_http11_init;
			jhd_http11_init(ev);
		}
	}else{
		c->close(c);
	}
}
void jhd_http2_with_alpn_server_connection_start(jhd_connection_t *c){
	log_assert_worker();
	log_assert(((jhd_tls_ssl_config*) c->listening->ssl)->alpn_list == jhd_http_alpn_list);
	log_assert(((jhd_tls_ssl_config*) c->listening->ssl)->server_side == JHD_TLS_SSL_IS_SERVER);

	c->write.handler = jhd_connection_tls_empty_write;
	c->read.handler = jhd_http2_alpn_recv_start;
	c->read.queue.next = NULL;
	c->write.queue.next = NULL;
    c->ssl = NULL;
	jhd_queue_insert_tail(&jhd_posted_events,&c->read);
}

























