#include <http2/jhd_http2_server.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>


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







static void server_headers_frame_parse_item(jhd_event_t *ev);
static void server_headers_frame_parse_item(jhd_event_t *ev);



static void jhd_http2_recv_continuation_payload(jhd_event_t *ev){
	jhd_http_header *header;
	jhd_queue_t h,*q;
	ssize_t rc;
	size_t len;
	u_char *p;

	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	header = event_h2c->recv.state_param;
	p = event_h2c->recv.alloc_buffer[0];


	if((ev)->timedout){
		log_err("timeout");
		len =  event_h2c->recv.payload_len;
		event_h2c->recv.state_param = NULL;
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_read_timeout(ev);
		goto func_free;
	}

	p += event_h2c->recv.state;

	len = event_h2c->recv.payload_len - event_h2c->recv.state;

	log_assert(len >0);

	rc = event_c->recv(event_c,p,len);
	if(rc > 0){
		if(rc == len){
			event_h2c->recv.state = 0;
			ev->handler = server_headers_frame_parse_item;
			jhd_unshift_event(ev,&jhd_posted_events);
		}else{
			event_h2c->recv.state += rc;
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
		}
	}else if(rc == JHD_AGAIN){
		jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
	}else{
		p = event_h2c->recv.alloc_buffer[0];
		len =  event_h2c->recv.payload_len;
		event_h2c->recv.state_param = NULL;
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_read_error(ev);
		goto func_free;
	}
	return;
	func_free:
			jhd_free_with_size(p,len);
			if(header->name_alloced){
				jhd_free_with_size(header->name,header->name_alloced);
			}
			if(header->value_alloced){
				jhd_free_with_size(header->value,header->value_alloced);
			}
			jhd_free_with_size(header,sizeof(jhd_http_header));
		while(!(jhd_queue_empty(&h))){
			q = h.next;
			jhd_queue_remove(q);
			header = jhd_queue_data(q,jhd_http_header,queue);
			if(header->name_alloced){
				jhd_free_with_size(header->name,header->name_len);
			}
			if(header->value_alloced){
				jhd_free_with_size(header->value,header->value_len);
			}
			jhd_free_with_size(header,sizeof(jhd_http_header));
		}

}


static server_continuation_head_read(jhd_event_t *ev){
	jhd_http_header *header;
	jhd_queue_t h,*q;
	u_char *p;
	uint32_t len,c_payload_len;
	uint32_t sid;
	ssize_t rc;


	log_assert_worker();

	event_c = ev->data;
	event_h2c = event_c->data;
	header = event_h2c->recv.state_param;
	len = event_h2c->recv.payload_len;
	log_assert(header!= NULL);
	log_assert(header->queue.next != NULL);
	if((ev)->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_read_timeout(ev);
		goto func_free;
	}

	if (event_h2c->recv.state < 9) {
		rc = event_c->recv(event_c, event_h2c->recv.buffer + event_h2c->recv.state, 9 - event_h2c->recv.state);
		if (rc > 0) {
			event_h2c->recv.state +=rc;
			if(event_h2c->recv.state  <9){
				jhd_event_add_timer(ev, event_h2c->conf->read_timeout);
				return;
			}
		} else if (rc == JHD_AGAIN) {
			jhd_event_add_timer(ev, event_h2c->conf->read_timeout);
			return;
		} else {
			event_h2c->recv.state_param = NULL;
			jhd_queue_move(&h,&event_h2c->recv.headers);
			event_h2c->conf->connection_read_error(ev);
			goto func_free;
		}
	}
	if(event_h2c->recv.buffer[3] != JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME){
		event_h2c->recv.state_param = NULL;
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_protocol_error(ev);
		goto func_free;
	}
	sid = (event_h2c->recv.buffer[5] << 24) | (event_h2c->recv.buffer[6] << 16) |  (event_h2c->recv.buffer[7] << 8) |  (event_h2c->recv.buffer[8]);
	if(sid != event_h2c->recv.last_stream_id){
		event_h2c->recv.state_param = NULL;
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_protocol_error(ev);
		goto func_free;
	}

	if(event_h2c->recv.buffer[4] & JHD_HTTP2_END_HEADERS_FLAG){
		event_h2c->recv.frame_flag |= JHD_HTTP2_END_HEADERS_FLAG;
	}
    c_payload_len = (event_h2c->recv.buffer[0] << 16) |  (event_h2c->recv.buffer[1] << 8) |  (event_h2c->recv.buffer[2]);
    if(c_payload_len > 16384){
    	event_h2c->recv.state_param = NULL;
    	jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_protocol_error(ev);
		goto func_free;
    }else if(c_payload_len ==0){
    	event_h2c->recv.state_param = NULL;
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_protocol_error(ev);
		goto func_free;
    }
    rc = event_h2c->recv.end - event_h2c->recv.pos;
    log_assert(rc>=0);
    log_assert(rc < 8192);

    c_payload_len +=rc;

    if(c_payload_len == len){
    	p = header->queue.next;
    	header->queue.next = NULL;
    }else{
		p = jhd_alloc(c_payload_len);
		if(p==NULL){
			jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);
			jhd_wait_mem(ev,c_payload_len);
			return;
		}
		event_h2c->recv.alloc_buffer[0]= p;
    }
    if(rc>0){
    	memcpy(p,event_h2c->recv.pos,rc);
    }
    event_h2c->recv.end = event_h2c->recv.pos = p;
    event_h2c->recv.end += c_payload_len;


    event_h2c->recv.payload_len = c_payload_len;
    event_h2c->recv.alloc_buffer[0] = p;
    event_h2c->recv.state = rc;
	ev->handler = jhd_http2_recv_continuation_payload;
	jhd_unshift_event(ev,&jhd_posted_events);
    if(header->queue.next){
    	header->queue.next = NULL;
    	jhd_free_with_size(header->queue->next,len);
    }
   return;
func_free:
		jhd_free_with_size(header->queue->next,len);
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_alloced);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_alloced);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	while(!(jhd_queue_empty(&h))){
		q = h.next;
		jhd_queue_remove(q);
		header = jhd_queue_data(q,jhd_http_header,queue);
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_len);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_len);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	}
}




static void server_headers_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	jhd_http2_connection_server_param *srv_param;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len == 0){
		event_h2c->recv.state = 1;
		return;
	}
	srv_param = event_h2c->data;
	log_assert(srv_param->mothed == JHD_HTTP_METHOD_NONE); // op in (connection init)   (after    notify http service)
	log_assert(event_h2c->recv.headers.next  = &event_h2c->recv.headers);
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id & 0X80000001 != 1){
		event_h2c->recv.state = 1;

	}else if(stream_id <= event_h2c->recv.last_stream_id){
		event_h2c->recv.state = 1;
	}else {
		++event_h2c->processing;
		if(event_h2c->processing > event_h2c->conf->max_streams){
			event_h2c->recv.state = 1;
		}else{
			event_h2c->recv.last_stream_id = stream_id;
		}
	}
}



static void server_headers_frame_parse_item(jhd_event_t *ev){
	jhd_http_header *header;
	jhd_queue_t h,*q;
	u_char *p,*end,*old_hpack_data;
	jhd_event_handler_pt err_handler;

    u_char      ch,indexed,index,size_update,prefix,octet,shift;
    size_t   value;
    uint16_t hpack_capacity,old_capacity;
    int rc;

	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	header = event_h2c->recv.state_param;

	if((ev)->timedout){
		log_err("timeout");
		err_handler = event_h2c->conf->connection_read_timeout;
		goto func_error;
	}
	p = event_h2c->recv.pos;
	end = event_h2c->recv.end;

	for(;;){
		if(header == NULL){
			event_h2c->recv.state_param = header = jhd_alloc(sizeof(jhd_http_header));
			if(header == NULL){
				 jhd_wait_mem(ev,sizeof(jhd_http_header));
				 jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
				 return;
			}
			memset(header,0,sizeof(jhd_http_header));
		}
		if(((end - p) < 4 ) && (0 == (event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG))){
			event_h2c->recv.pos = p;
			event_h2c->recv.end = end;
			header->queue.next =event_h2c->recv.alloc_buffer[0];
			event_h2c->recv.state = 0;
			ev->handler = server_continuation_head_read;
			jhd_unshift_event(ev,&jhd_posted_events);
			return;
		}
        ch = *p++;
        index = size_update = indexed = 0;
		if (ch >= (1 << 7)) {   //0x80
			/* indexed header field */
			indexed = 1;
			prefix = jhd_http2_prefix(7);

		} else if (ch >= (1 << 6)) {
			/* literal header field with incremental indexing */
			index = 1;
			prefix = jhd_http2_prefix(6);

		} else if (ch >= (1 << 5)) {
			/* dynamic table size update */
			size_update = 1;
			prefix = jhd_http2_prefix(5);

		} else if (ch >= (1 << 4)) {
			/* literal header field never indexed */
			prefix = jhd_http2_prefix(4);

		} else {
			/* literal header field without indexing */
			prefix = jhd_http2_prefix(4);
		}

	    value = ch & prefix;
	    if (value == prefix) {
			shift = 0;
			for(;;){
				if( p >= end  || shift >= 21){
					//index < (1 << 14+prefix) size_update <(1 << 14+prefix)
					err_handler = event_h2c->conf->connection_protocol_error;
					goto func_error;
				}
				octet = *p++;
				value += (octet & 0x7f) << shift;
				if(octet<128){
					break;
				}
				shift+=7;
			}
		}
	    if(indexed){
	    	header->name = NULL;
	    	header->value = NULL;
	    	header->name_alloced = 0;
	    	header->value_alloced = 0;


	    	jhd_http2_hpack_get_index_header_item(&event_h2c->recv.hpack,value,&header->name,&header->name_len,
	    		&header->value,&header->value_len);
	    	if(header->name == NULL || header->value == NULL){
				err_handler = event_h2c->conf->connection_protocol_error;
				goto func_error;
	    	}
	    }else if(size_update){
	    	old_hpack_data = NULL;
	    	rc = jhd_http2_hpack_resize(&event_h2c->recv.hpack,value,&hpack_capacity,&old_hpack_data,&old_capacity);
	    	if(rc == JHD_AGAIN){
	    		jhd_wait_mem(ev,hpack_capacity);
	    		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
	    		return;
	    	}else if(rc== JHD_ERROR){
	    		//invalid hapck size; > 65535 -4096
				err_handler = event_h2c->conf->connection_protocol_error;
				goto func_error;
	    	}
	    	if(old_hpack_data != NULL){
	    		//TODO:

	    		return;
	    	}

		}else{
			h2c->recv_paser_value = 0;
			if(value){
				if(ngx_http2_hpack_get_index_header(h2c,value,1)){
					goto failed;
				}
				h2c->recv_paser_value = 1;
			}else{
				header = ngx_pcalloc(h2c->recv.pool,sizeof(ngx_http2_header_t));
				if(header){
					h2c->recv.c_header = header;
					ngx_queue_insert_tail(&h2c->recv.headers_queue,&header->queue);
				}else{
					goto failed;
				}
			}
			h2c->recv.min_len = 0 ;
			h2c->recv.handler = ngx_http_upstream_http2_read_field_len;
		}








		if(header->name == NULL){


























		}




	}




	return;
func_error:
	event_h2c->recv.state_param = NULL;
	jhd_queue_move(&h,&event_h2c->recv.headers);
	p = event_h2c->recv.alloc_buffer[0];
	value = event_h2c->recv.payload_len;
	err_handler(ev);
	if(header != NULL){
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_len);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_len);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	}
	while(!(jhd_queue_empty(&h))){
		q = h.next;
		jhd_queue_remove(q);
		header = jhd_queue_data(q,jhd_http_header,queue);
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_len);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_len);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	}
	jhd_free_with_size(p,value);
}

static void server_headers_frame_parse_begin(jhd_event_t *ev){
	log_assert_worker();
	log_assert(event_c == ev->data);
	log_assert(event_h2c == event_c->data);

	event_h2c->recv.end = event_h2c->recv.pos = event_h2c->recv.alloc_buffer[0];
	event_h2c->recv.end +=event_h2c->recv.payload_len;

	if(event_h2c->recv.frame_flag & 0x08 /*PADDED (0x8)*/ ){
		event_h2c->recv.end -= *(event_h2c->recv.pos);
		++event_h2c->recv.pos;
	}
	if(event_h2c->recv.frame_flag & 0x20 /*PRIORITY(0x20)*/ ){
			//TODO impl PRIORITY
			event_h2c->recv.pos+= 5;
	}

	if(event_h2c->recv.pos <= event_h2c->recv.end){
		event_h2c->conf->connection_protocol_error(ev);
		return;
	}

    ev->handler = server_headers_frame_parse_item;
    server_headers_frame_parse_item(ev);
}

static void server_headers_frame_payload_handler(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	event_h2c->recv.alloc_buffer[0] = jhd_alloc(event_h2c->recv.payload_len);
	if(event_h2c->recv.alloc_buffer[0] == NULL){
		jhd_event_add_time(ev,event_h2c->conf->wait_mem_timeout);
	}else{
	jhd_http2_do_recv_payload(ev,event_h2c,server_headers_frame_parse_begin);
	}
}



























