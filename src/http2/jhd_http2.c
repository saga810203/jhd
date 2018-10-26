#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>


const u_char *jhd_http2_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";









void jhd_http2_only_by_clean_start(jhd_connection_t *c){

}
void jhd_http2_only_by_tls_start(jhd_connection_t *c){

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
void jhd_http2_read_frame_header(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection_conf *conf;
	jhd_http2_connection *hc;
	u_char *p;
	int ret;
	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	c = ev->data;

	jhd_event_with_timeout(ev){
		log_err("timedout");
		c->close(c);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}

	hc = c->data;
	conf = hc->conf;
	if(hc->recv.buffer== NULL){
		hc->recv.buffer = jhd_alloc(conf->recv_buffer_size);
		if(hc->recv.buffer == NULL){
			jhd_wait_mem(ev,conf->recv_buffer_size);
			jhd_event_add_timer(conf->wait_mem_timeout);
			return ;
		}
		hc->recv.pos = hc->recv.buffer;
		hc->recv.end = hc->recv.pos + conf->recv_buffer_size;
	}
	if(hc->recv.state<9){
		memcpy(hc->recv.buffer,hc->recv.pos);
		hc->recv.pos = hc->recv.buffer;
		p = hc->recv.pos + hc->recv.state;

		ret = c->recv(c,p,hc->recv.end -p);

		if(ret >0){

		}else if(ret ){

		}

	}






	log_notice("<==%s",__FUNCTION__);
}

void jhd_http2_read_preface(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection_conf *conf;
		jhd_http2_connection *hc;
		u_char preface[24];
		int ret;
		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		c = ev->data;
		jhd_event_with_timeout(ev){
			log_err("timedout");
			c->close(c);
			log_notice("<==%s with timedout",__FUNCTION__);
			return;
		}
		hc = c->data;
		conf = hc->conf;
		log_assert(hc->recv.state< 24);
		ret = c->recv(c,preface,24 - hc->recv.state);
		if(ret >0){
			log_buf_info("read buf=>",preface,ret);
			if(memcmp(preface,&jhd_http2_preface[hc->recv.state],ret)!=0){
				log_err("invalid http2 preface");
				c->close(c);
				log_notice("<==% with invalid httppreface",__FUNCTION__);
				return;
			}
			hc->recv.state += ret;
			if(hc->recv.state == 24){
				log_info("read http2 preface success");
				hc->recv.state = 0;
				ev->handler = jhd_http2_read_frame_header;
				jhd_http2_read_frame_header(ev);
			}else{
				jhd_event_add_timer(ev,conf->read_timeout);
			}
		}else if(ret == JHD_AGAIN){
			jhd_event_add_timer(ev,conf->read_timeout);
		}else{
			c->close(c);
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
void jhd_http2_with_alpn_start(jhd_connection_t *c){
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























jhd_http_request_info  jhd_http2_info={};
