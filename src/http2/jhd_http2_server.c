#include <http2/jhd_http2_server.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_queue.h>


typedef struct{
		jhd_http_method mothed;
		u_char *uri;
		uint16_t uri_len;
		u_char *host;
		uint8_t host_len;
}jhd_http2_connection_server_param;




void jhd_http2_only_by_clean_server_connection_start(jhd_connection_t *c){

}
void jhd_http2_only_by_tls_server_connection_start(jhd_connection_t *c){

}


static char *jhd_http_alpn_list[]={"h2","http/1.1",NULL};

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
	log_assert_worker();
	c = ev->data;

	jhd_event_with_timeout(ev){
		c->close(c);
		return;
	}

	conf = &((jhd_http_listenning_ctx*)(c->listening->lis_ctx))->h2_conf;

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
			jhd_queue_remove(&c->write.queue);
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
	log_assert(((jhd_tls_ssl_config*) c->listening->ssl)->server_side == JHD_TLS_SSL_IS_SERVER);

	c->write.handler = jhd_connection_tls_empty_write;
	c->read.handler = jhd_http2_alpn_recv_start;
	c->read.queue.next = NULL;
	c->write.queue.next = NULL;
    c->ssl = NULL;
	jhd_post_event(&c->read,&jhd_posted_events);
}


static void server_rst_stream(jhd_event_t *ev){
	jhd_http_header *header;
	jhd_queue_t h,*q;
	jhd_http2_frame *frame;
	uint32_t sid;
	u_char *p;

	event_h2c = ((jhd_connection_t*)ev->data)->data;

	if(ev->timedout){
		log_err("timeout");
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_read_timeout(ev);
		goto func_free;
	}
	frame = jhd_alloc(sizeof(jhd_http2_frame)+13);
	if(frame==NULL){
		jhd_wait_mem(ev,sizeof(jhd_http2_frame)+13);
		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		return;
	}
	jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+13);
	frame->type = JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME;

	p = frame->pos;
	//IN X86   00 00 03 08 = uint32_t
	*((uint32_t*)p) =0x03040000;
	p[4] = 0;
	p+=5;
	sid = event_h2c->recv.last_stream_id ;
	jhd_http2_set_stream_id(p,sid);
	p+=4;
	*((uint32_t*)p) = JHD_HTTP2_REFUSED_STREAM_MAX_STREAM;
	jhd_http2_send_queue_frame(frame);
	event_h2c->recv.state = 0;
	ev->handler = event_h2c->recv.connection_frame_header_read;
	jhd_unshift_event(ev,&jhd_posted_events);
	jhd_queue_move(&h,&event_h2c->recv.headers);
func_free:
	for(q = h.next; q!= &h; q= q->next){
		jhd_queue_only_remove(q);
		header = jhd_queue_data(q,jhd_http_header,queue);
		jhd_http_free_header(header);
	}
}


static void server_service(jhd_event_t *ev){
	event_h2c = ((jhd_connection_t*)ev->data)->data;

	//create request   method in event_h2c->recv.headers;



	event_h2c->recv.state = 0;
	ev->handler = event_h2c->recv.connection_frame_header_read;
	jhd_unshift_event(ev,&jhd_posted_events);
}

static void server_end_headers_handler(jhd_event_t *ev){
	event_h2c = ((jhd_connection_t*)ev->data)->data;
	jhd_http2_stream *stream ;
	jhd_http_header *header;
	jhd_queue_t h,*q;
	jhd_http2_servcer_service *server_service;


	if(ev->timedout){
		log_err("timeout");
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_read_timeout(ev);
		for(q = h.next; q!= &h; q= q->next){
				jhd_queue_only_remove(q);
				header = jhd_queue_data(q,jhd_http_header,queue);
				jhd_http_free_header(header);

		}
		return;
	}
	if(event_h2c->processing == event_h2c->conf->max_streams){
		log_assert(event_h2c->recv.state_param == NULL);
		ev->handler = server_rst_stream;
		server_rst_stream(ev);
	}else{
		stream = jhd_alloc(sizeof(jhd_http2_stream));
		if(stream== NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_stream));
			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
			return;
		}
		//memset(stream,0,sizeof(jhd_http2_stream));
		stream->id = event_h2c->recv.last_stream_id;
		stream->recv_window_size = event_h2c->recv.init_window_size;
		stream->send_window_size = event_h2c->send.initial_window_size;
		stream->state = (event_h2c->recv.frame_flag & JHD_HTTP2_END_STREAM_FLAG)? JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE : JHD_HTTP2_STREAM_STATE_OPEN;
		jhd_queue_init(&stream->flow_control);
		q = &event_h2c->streams[(stream->id >> 1) & 0x1F/*31*/];
		jhd_queue_insert_tail(q,&stream->queue);
		++event_h2c->processing;
		event_h2c->recv.stream = stream;
		event_h2c->recv.state_param =server_service= event_h2c->conf->extend_param;
		ev->handler = server_service->servcie;
		ev->handler(ev);
	}
}





static void server_headers_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(event_h2c = event_c->data);

#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len == 0){
		event_h2c->conf->connection_protocol_error(ev);
		return;
	}
//	srv_param = event_h2c->data;
	log_assert(jhd_queue_empty(&event_h2c->recv.headers));

	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);

	if((stream_id & 0X80000001) != 1){
		event_h2c->conf->connection_protocol_error(ev);
	}else if(stream_id <= event_h2c->recv.last_stream_id){
		event_h2c->conf->connection_protocol_error(ev);
	}else{
		event_h2c->recv.last_stream_id = stream_id;
		ev->handler = jhd_http2_headers_frame_payload_handler;
		jhd_unshift_event(ev,&jhd_posted_events);
	}
}


void server_goaway_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len <8){
		event_h2c->recv.state = 1;
		return;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id  != 0){
		event_h2c->recv.state = 1;
		return;
	}
}


static jhd_event_handler_pt server_frame_handlers[]={
		jhd_http2_data_frame_header_check,//DATA
		server_headers_frame_header_check,//HEADERS
		jhd_http2_priority_frame_header_check,//PRIORITY
		jhd_http2_rst_stream_frame_header_check,//RST_STREAM
		jhd_http2_setting_frame_header_check,//SETTING
		jhd_http2_unsupported_frame_type,//PUSH_PROMISE
		jhd_http2_ping_frame_header_check,//PING
		server_goaway_frame_header_check,//GO_AWAY
		jhd_http2_window_update_frame_header_check,//WINDOW_UPDATE
		jhd_http2_unsupported_frame_type,//CONTINUATION
};




void jhd_http2_server_connection_conf_init(jhd_http2_connection_conf *conf){
	jhd_http2_servcer_service *service;

	memset(conf,0,sizeof(jhd_http2_connection_conf));
	conf->frame_payload_handler_pts =server_frame_handlers;



	conf->extend_param = service = malloc(sizeof(jhd_http2_servcer_service));
	service->servcie = server_service;


	///TEST

}


















