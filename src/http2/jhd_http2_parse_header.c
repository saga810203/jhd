#include <jhd_config.h>
#include <jhd_log.h>
#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>


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
	if((ev)->timedout){
		log_err("timeout");
		p = event_h2c->recv.alloc_buffer[0];
		jhd_queue_move(&h,&event_h2c->recv.headers);
		len = event_h2c->recv.payload_len;
		event_h2c->conf->connection_read_timeout(ev);
		goto func_error;
	}
	p = event_h2c->recv.alloc_buffer[0] + event_h2c->recv.state;

	len = event_h2c->recv.payload_len - event_h2c->recv.state;

	log_assert(len >0);

	rc = event_c->recv(event_c,p,len);
	if(rc > 0){
		if(((size_t)rc) == len){
			event_h2c->recv.state = 0;
			ev->handler = jhd_http2_headers_frame_parse_item;
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

		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
		event_h2c->conf->connection_read_error(ev);
		goto func_error;
	}
	return;
func_error:
	if(header){
		jhd_free_with_size(header->queue.next,len);
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_alloced);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_alloced);
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
	jhd_free_with_size(p,len);
}


static void jhd_http2_recv_continuation_header(jhd_event_t *ev){
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
//	if(header != NULL){
//		prev_payload = header->queue.next;
//	}
	if((ev)->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_read_timeout(ev);
		goto func_free;
	}
loop_begin:
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

			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
			event_h2c->conf->connection_read_error(ev);
			goto func_free;
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
		event_h2c->recv.frame_flag |=(JHD_HTTP2_END_HEADERS_FLAG & event_h2c->recv.buffer[4]);
		c_payload_len = (event_h2c->recv.buffer[0] << 16) |  (event_h2c->recv.buffer[1] << 8) |  (event_h2c->recv.buffer[2]);
		if(c_payload_len > 16384){
			event_h2c->recv.state_param = NULL;
			jhd_queue_move(&h,&event_h2c->recv.headers);
			event_h2c->conf->connection_protocol_error(ev);
			goto func_free;
		}else if(c_payload_len ==0){
			//TODO do tigger protocol error?
			if(event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG){
                if(len ==0 && jhd_queue_has_item(&event_h2c->recv.headers)){
            		event_h2c->recv.state = 0;
            		event_h2c->recv.state_param = NULL;
                	ev->handler = event_h2c->recv.connection_end_headers_handler;
                	jhd_unshift_event(ev,&jhd_posted_events);
                	if(header!= NULL){
                		jhd_free_with_size(header,sizeof(jhd_http_header));
                	}
                	return;
                }else{
            		event_h2c->recv.state = 0;
                	event_h2c->recv.state_param = NULL;
                	jhd_queue_move(&h,&event_h2c->recv.headers);
                	event_h2c->conf->connection_protocol_error(ev);
                	goto func_free;
                }
			}
			goto loop_begin;
		}
	}else{
		c_payload_len = (event_h2c->recv.buffer[0] << 16) |  (event_h2c->recv.buffer[1] << 8) |  (event_h2c->recv.buffer[2]);
	}
    log_assert(c_payload_len > 0);

    if(len > 0){
    	log_assert(event_h2c->recv.end > event_h2c->recv.pos);
    	log_assert(header!= NULL);
    	log_assert(header->queue.next!= NULL);
    	rc = event_h2c->recv.end - event_h2c->recv.pos;
    	c_payload_len +=rc;
    	if(len >= c_payload_len){
    		memcpy(header->queue.next,event_h2c->recv.pos,rc);
    		event_h2c->recv.alloc_buffer[0] = (u_char*)header->queue.next;
    		event_h2c->recv.pos = (u_char*)header->queue.next;
    		event_h2c->recv.end = event_h2c->recv.pos + c_payload_len;
    		event_h2c->recv.state = len - c_payload_len +rc ;
    		event_h2c->recv.payload_len = len;
    		ev->handler = jhd_http2_recv_continuation_payload;
    		jhd_unshift_event(ev,&jhd_posted_events);
    	}else{
    		p = jhd_alloc(c_payload_len);
    		if(p == NULL){
    			jhd_wait_mem(ev,c_payload_len);
    			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
    		}else{
				event_h2c->recv.alloc_buffer[0] = p;
				memcpy(p,event_h2c->recv.pos,rc);
				event_h2c->recv.state = rc;
				event_h2c->recv.payload_len= c_payload_len;
				event_h2c->recv.pos = p;
				event_h2c->recv.end = p+c_payload_len;
				ev->handler = jhd_http2_recv_continuation_payload;
				jhd_unshift_event(ev,&jhd_posted_events);
				jhd_free_with_size(header->queue.next,len);
			}
    	}
    }else{
    	p = jhd_alloc(c_payload_len);
    	if(p == NULL){
    		jhd_wait_mem(ev,c_payload_len);
    		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
    	}else{
			event_h2c->recv.alloc_buffer[0] = p;
			event_h2c->recv.state = 0;
			event_h2c->recv.payload_len= c_payload_len;
			event_h2c->recv.pos = p;
			event_h2c->recv.end = p+c_payload_len;
			ev->handler = jhd_http2_recv_continuation_payload;
			jhd_unshift_event(ev,&jhd_posted_events);
    	}
    }
    return;
func_free:
	if(header != NULL){
		if(header->queue.next!= NULL){
			jhd_free_with_size(header->queue.next,len);
		}
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_alloced);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_alloced);
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
}






jhd_inline static int http2_get_indexed_header(uint32_t idx,jhd_http_header *header,uint16_t *wait_mem_len){
	u_char *idx_name,*idx_val;
	uint16_t idx_name_len,idx_val_len;
	idx_name = NULL;
	idx_val = NULL;
	idx_name_len = 0;
	idx_val_len = 0;
	if(idx ==0){
		return JHD_ERROR;
	}
	log_assert(header!= NULL);

	if(header->name == NULL){
		log_assert(header->name_alloced == 0);
		log_assert(header->value_alloced == 0);
		jhd_http2_hpack_get_index_header_item(&event_h2c->recv.hpack,idx,&header->name,&header->name_len,&header->value,&header->value_len);
		if(header->name == NULL || header->value == NULL){
			return JHD_ERROR;
		}
	}
#ifdef JHD_LOG_ASSERT_ENABLE
	else{
		jhd_http2_hpack_get_index_header_item(&event_h2c->recv.hpack,idx,&idx_name,&idx_name_len,&idx_val,&idx_val_len);
		log_assert(idx_name != NULL);
		log_assert(idx_val != NULL);
		log_assert(header->name != NULL);
		log_assert(header->value != NULL);
		log_assert(header->name_len == idx_name_len);
		log_assert(header->value_len == idx_val_len);
		if(header->name_alloced == 0){
			log_assert(header->name = idx_name);
		}else{
			log_assert(header->name_alloced ==(idx_name_len + 1));
			log_assert(memcmp(idx_name,header->name,idx_name_len)==0);
		}
		if(header->value_alloced == 0){
			log_assert(header->value = idx_val);
		}else{
			log_assert(header->value_alloced ==(idx_val_len + 1));
			if(idx_val_len>0){
				log_assert(memcmp(idx_val,header->value,idx_val_len)==0);
			}
		}
	}
#endif
	if(jhd_http2_hpack_is_dyncmic(idx)){
	   if(header->name_alloced == 0){
		   header->name_alloced = header->name_len +1;
		   idx_name = jhd_alloc(header->name_alloced);
		   if(idx_name == NULL){
			   *wait_mem_len = header->name_alloced;
			   header->name_alloced = 0;
			   return JHD_AGAIN;
		   }
		   memcpy(idx_name,header->name,header->name_len+1);
		   header->name = idx_name;
	   }
	   if(header->value_len>0){
		   if(0 == header->value_alloced){
			   header->value_alloced= header->value_len + 1;
			   idx_val = jhd_alloc(header->value_alloced);
			   if(idx_val == NULL){
				   *wait_mem_len = header->value_alloced;
				   header->value_alloced = 0;
				   return JHD_AGAIN;
			   }
			   memcpy(idx_val,header->value,header->value_len);
			   header->value = idx_val;
		   }
	   }else{
		  log_assert(header->value_alloced = 0);
		  header->value = jhd_empty_string;
	   }
	}
	return JHD_OK;
}

static int jhd_http2_hpack_parse_header_name(u_char *start,u_char *end,jhd_http_header *header){
	u_char *p,huff;
	int rc;
	uint32_t len;

	p = start;
	huff = *p >> 7;

	rc = jhd_http2_parse_int(&len,jhd_http2_prefix(7),p,end,21);
	if(rc == JHD_ERROR){
		return JHD_ERROR;
	}else if(rc == JHD_AGAIN){
		return JHD_AGAIN;
	}
	p+=rc;

	if(header->name_alloced == 0){
		if(len){
			if((end - p) < len){
				return JHD_AGAIN;
			}
			if(huff){
				rc = jhd_http2_huff_decode(p, len,jhd_calc_buffer,256);
				if(rc == JHD_ERROR){
					return JHD_ERROR;
				}
				if(rc >128){
					jhd_err = JHD_HTTP2_ENHANCE_YOUR_CALM;
					return JHD_ERROR;
				}
				log_assert(header->name_len == 0 || header->name_len == rc);
				header->name_len = rc;
				header->name = jhd_calc_buffer;
				jhd_calc_buffer[rc] = 0;
			}else{
				if(len >128){
					jhd_err = JHD_HTTP2_ENHANCE_YOUR_CALM;
					return JHD_ERROR;
				}
				memcpy(jhd_calc_buffer,p,len);
				jhd_calc_buffer[len] = 0;
				header->name_len = len;
			}
		}else{
			return JHD_ERROR;
		}
	}
#ifdef JHD_LOG_ASSERT_ENABLE
	else{
		log_assert(len >0);
		log_assert(header->name_len<=128);
		log_assert(header->name_alloced = (header->name_len+1));
		log_assert((end-p)>= len);
		if(huff){
			log_assert(header->name != jhd_calc_buffer);
			rc = jhd_http2_huff_decode(p, len,jhd_calc_buffer,256);
			log_assert(rc == header->name_len);
			log_assert(memcmp(header->name,jhd_calc_buffer,rc)==0);
		}else{
			log_assert(header->name != p);
			log_assert(len == header->name_len);
			log_assert(memcmp(header->name,p,len)==0);
		}
	}
#endif
    return p +len - start;
}

static int jhd_http2_hpack_parse_header_val(u_char *start,u_char *end,jhd_http_header *header){
	u_char *p,huff,*buf;
	int rc;
	uint32_t len;

	buf = jhd_calc_buffer + 256;

	p = start;
	huff = *p >> 7;
	rc = jhd_http2_parse_int(&len,jhd_http2_prefix(7),p,end,21);
	if(rc == JHD_ERROR){
		return JHD_ERROR;
	}else if(rc == JHD_AGAIN){
		return JHD_AGAIN;
	}
	p+=rc;
	if(len){
		if((end - p) < len){
			return JHD_AGAIN;
		}
		if(huff){
			rc = jhd_http2_huff_decode(p, len,buf,16384 -256);
			if(rc == JHD_ERROR){
				return JHD_ERROR;
			}
			if(rc >8192){
				jhd_err = JHD_HTTP2_ENHANCE_YOUR_CALM;
				return JHD_ERROR;
			}
			log_assert(header->value_len == rc || header->value_len == 0 );
			header->value_len = rc;
			header->value = buf;
		}else{
			log_assert(header->value_len ==len || header->value_len == 0);
			if(len >8192){
				jhd_err = JHD_HTTP2_ENHANCE_YOUR_CALM;
				return JHD_ERROR;
			}
			header->value = p;
			header->value_len = len;
		}
	}else{
		header->value_len = 0;
	}
    return p +len - start;
}

jhd_inline static int http2_get_name_indexed_header(u_char add,jhd_http2_hpack *hpack, uint32_t idx,jhd_http_header *header,u_char *start,u_char *end,uint16_t *wait_mem_len){
	u_char *p,*str;
	uint16_t len;
	int rc;

	log_assert(idx >0);
	*wait_mem_len = 0;
	p = start;
	if(header->name == NULL){
		jhd_http2_hpack_get_index_header_name(hpack,idx,&header->name,&header->name_len);
		if(header->name == NULL){
			return JHD_ERROR;
		}
	    log_assert(header->name_alloced == 0);
	}
#ifdef JHD_LOG_ASSERT_ENABLE
	else{
		jhd_http2_hpack_get_index_header_name(hpack,idx,&str,&len);
		log_assert(str != NULL);
		log_assert(len == header->name_len);
		if(header->name_alloced){
			log_assert(header->name_alloced == (len+1));
			log_assert(header->name != str);
			log_assert(memcmp(header->name,str,len)==0);
		}else{
			log_assert(header->name == str);
		}
	}
#endif
	if( p == end ){
		return JHD_AGAIN;
	}
	rc = jhd_http2_hpack_parse_header_val(p,end,header);
	if(rc < 0){
		return rc;
	}
	p+=rc;
	if( header->value_len > 0){
		if(jhd_http2_hpack_is_dyncmic(idx)){
			if (header->name_alloced == 0) {
				header->name_alloced = header->name_len + 1;
				str = jhd_alloc(header->name_alloced);
				if (str == NULL) {
					*wait_mem_len = header->name_alloced;
					header->name_alloced = 0;
					return JHD_AGAIN;
				}
				memcpy(str, header->name,header->name_alloced);
				header->name = str;
			}
		}
		header->value_alloced =  header->value_len + 1;
		str =  jhd_alloc(header->value_len + 1);
		if(str == NULL){
			*wait_mem_len = header->value_alloced;
			header->value_alloced =  0;
			return JHD_AGAIN;
		}
		memcpy(str,header->value,header->value_alloced);
		if(add){
			if(JHD_OK != jhd_http2_hpack_add(hpack,header->name,header->name_len,header->value,header->value_len)){
				return JHD_ERROR;
			}
		}
	}else{
		if(add){
			if(JHD_OK != jhd_http2_hpack_add(hpack,header->name,header->name_len,jhd_empty_string,0)){
				return JHD_ERROR;
			}
		}
		jhd_http_header_init(header);
	}
	log_assert(p > start);
	return p - start;
}

jhd_inline static int http2_get_raw_header(u_char add,jhd_http2_hpack *hpack,jhd_http_header *header,u_char *start,u_char *end,uint16_t *wait_mem_len){
	u_char *p,*str;
	int rc;

	*wait_mem_len = 0;
	p = start;
	log_assert(p < end);

	rc = jhd_http2_hpack_parse_header_name(p,end,header);
	if(rc < 0){
		return rc;
	}
	p+=rc;
	log_assert(p <= end);
	if( p == end ){
		return JHD_AGAIN;
	}
	rc = jhd_http2_hpack_parse_header_val(p,end,header);
	if(rc < 0){
		return rc;
	}
	p+=rc;
	if(header->value_len > 0){
		if(header->name_alloced ==0){
			header->name_alloced = header->name_len +1;
			str = jhd_alloc(header->name_alloced);
			if(str == NULL){
				*wait_mem_len = header->name_alloced ;
				header->name_alloced =  0;
				return JHD_AGAIN;
			}
			memcpy(str,header->name,header->name_len);
			str[header->name_len] = 0;
			header->name = str;
		}
#ifdef JHD_LOG_ASSERT_ENABLE
		else{
			log_assert(header->name != jhd_calc_buffer);
		}
#endif
		header->value_alloced = header->value_len+1;
		str = jhd_alloc(header->value_alloced);
		if(str == NULL){
			*wait_mem_len = header->value_alloced;
			header->value_alloced = 0;
			return JHD_AGAIN;
		}
		memcpy(str,header->value,header->value_len);
		str[header->value_len] = 0;
		header->value = str;
		if(add){
			if(JHD_OK != jhd_http2_hpack_add(hpack,header->name,header->name_len,header->value,header->value_len)){
				return JHD_ERROR;
			}
		}
	}else{
		if(add){
			if(JHD_OK != jhd_http2_hpack_add(hpack,header->name,header->name_len,jhd_empty_string,0)){
				return JHD_ERROR;
			}
		}
		jhd_http_header_init(header);
	}
	log_assert(p > start);
	return p - start;
}

#define http2_header_first_parse(C,P,I,S,D,F) \
	C = *P;\
	I = S = D = 0;\
	if (C >= (1 << 7)) {\
		D = 1;\
		F = jhd_http2_prefix(7);\
	} else if (C >= (1 << 6)) { \
		I = 1;\
		F = jhd_http2_prefix(6);\
	} else if (C >= (1 << 5)) {\
		S = 1;\
		F = jhd_http2_prefix(5);\
	} else{ \
		F = jhd_http2_prefix(4);\
	}

void jhd_http2_headers_frame_parse_item(jhd_event_t *ev){
	jhd_http_header *header;
	jhd_queue_t h,*q;
	u_char *p,*end,*hpack_data;
	jhd_event_handler_pt err_handler;
    u_char      ch,indexed,index,size_update,prefix;
    uint32_t   value;
    uint16_t hpack_capacity,mem_len;
    int rc;

	log_assert_worker();

	event_c = ev->data;
	event_h2c = event_c->data;
	header = event_h2c->recv.state_param;
	end = event_h2c->recv.end;
	p = event_h2c->recv.pos;
	hpack_data = NULL;
	if((ev)->timedout){
		log_err("timeout");
		err_handler = event_h2c->conf->connection_read_timeout;
		goto func_error;
	}

	log_assert( end > p );
	for(;;){
		log_assert(end > p);
		if(header == NULL){
			event_h2c->recv.state_param = header = jhd_alloc(sizeof(jhd_http_header));
			if(header == NULL){
				 jhd_wait_mem(ev,sizeof(jhd_http_header));
				 jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
				 return;
			}
			jhd_http_header_init(header);
		}
		http2_header_first_parse(ch,p,index,size_update,indexed,prefix)

		rc = jhd_http2_parse_int(&value,prefix,p,end,21);
		if(rc == JHD_ERROR){
			err_handler = event_h2c->conf->connection_protocol_error;
			goto func_error;
		}else if(rc == JHD_AGAIN){
			goto next_frame;
		}
		p+=rc;
		if(size_update){
			log_assert(header != NULL);
			log_assert(header->name == NULL);
			log_assert(header->value == NULL);
			log_assert(header->name_len == 0);
			log_assert(header->name_alloced == 0);
			log_assert(header->value_len == 0);
			log_assert(header->value_alloced == 0);

			rc = jhd_http2_hpack_resize(&event_h2c->recv.hpack,value,&hpack_data,&hpack_capacity);
			if(rc == JHD_AGAIN){
				jhd_wait_mem(ev,hpack_capacity);
				jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
				return;
			}else if(rc== JHD_ERROR){
				//invalid hapck size; > 65535 -4096
				err_handler = event_h2c->conf->connection_protocol_error;
				goto func_error;
			}
			log_assert(p <= end);
			if(hpack_data != NULL){
				if(p != end){
					event_h2c->recv.pos = p;
					jhd_unshift_event(ev,&jhd_posted_events);
					jhd_free_with_size(hpack_data,hpack_capacity);
					return;
				}
			}
		} else {
			if (indexed) {
				rc = http2_get_indexed_header(value, header, &mem_len);
				if (rc == JHD_ERROR) {
					err_handler = event_h2c->conf->connection_protocol_error;
					goto func_error;
				} else if (rc == JHD_AGAIN) {
					jhd_wait_mem(ev, mem_len);
					jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);
					return;
				}

				header = NULL;
				event_h2c->recv.state_param = NULL;
			} else {
				if(p == end){
					goto next_frame;
				}
				if(value){
				    rc = http2_get_name_indexed_header(index,&event_h2c->recv.hpack,value,header,p,end,&mem_len);
				}else{
					rc = http2_get_raw_header(index,&event_h2c->recv.hpack,header,p,end,&mem_len);
				}
				if(rc == JHD_ERROR){
					err_handler = event_h2c->conf->connection_protocol_error;
					goto func_error;
				}else if(rc == JHD_AGAIN){
					if(mem_len){
						jhd_wait_mem(ev, mem_len);
						jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);
						return;
					}
					goto next_frame;
				}
				p+=rc;
				if(header->name_alloced){
					jhd_queue_insert_tail(&event_h2c->recv.headers,&header->queue);
					header = NULL;
					event_h2c->recv.state_param = NULL;
				}
			}
		}

		log_assert(p <= end);
		event_h2c->recv.pos = p;
		if (p == end) {
			goto next_frame;
		}
	}
	return ;
next_frame:
	log_assert(event_h2c->recv.end >=  event_h2c->recv.pos);
	log_assert(header == event_h2c->recv.state_param);
	if(event_h2c->recv.pos ==event_h2c->recv.end){
		p = event_h2c->recv.alloc_buffer[0];
		event_h2c->recv.payload_len = 0;
		value = event_h2c->recv.payload_len;
		if(event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG){
			if(event_h2c->recv.headers.next == (&event_h2c->recv.headers)){
				log_err("invalid headers_frame(maybe include continuation_frame)  (hasnot valid header");
				err_handler = event_h2c->conf->connection_protocol_error;
				goto func_error;
			}
			event_h2c->recv.state_param = NULL;
			ev->handler= event_h2c->recv.connection_end_headers_handler;
			if(header != NULL){
				log_assert(header->name == NULL);
				log_assert(header->name_len == 0);
				log_assert(header->value == NULL);
				log_assert(header->value_len ==0);
				log_assert(header->name_alloced == 0);
				log_assert(header->value_alloced == 0);
				jhd_free_with_size(header,sizeof(jhd_http_header));
			}
		}else{
			if(header != NULL){
				log_assert(header->name == NULL);
				log_assert(header->name_len == 0);
				log_assert(header->value == NULL);
				log_assert(header->value_len ==0);
				log_assert(header->name_alloced == 0);
				log_assert(header->value_alloced == 0);
				header->queue.next = NULL;
			}
			ev->handler= jhd_http2_recv_continuation_header;
		}
		jhd_unshift_event(ev,&jhd_posted_events);
		jhd_free_with_size(p,value);
	}else{
		if(event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG){
			log_err("invalid headers_frame(maybe include continuation_frame)");
			err_handler = event_h2c->conf->connection_protocol_error;
			goto func_error;
		}
		log_assert(header != NULL);
		p = event_h2c->recv.alloc_buffer[0];
		header->queue.next = (jhd_queue_t*)p;
		ev->handler = jhd_http2_recv_continuation_header;
		jhd_unshift_event(ev,&jhd_posted_events);
	}
	if(hpack_data){
		jhd_free_with_size(hpack_data,hpack_capacity);
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
	while(jhd_queue_has_item(&h)){
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
	if(hpack_data){
		jhd_free_with_size(hpack_data,hpack_capacity);
	}
}

static void headers_frame_parse_begin(jhd_event_t *ev){
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
    ev->handler = jhd_http2_headers_frame_parse_item;
    jhd_http2_headers_frame_parse_item(ev);
}

void jhd_http2_headers_frame_payload_handler(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	event_h2c->recv.alloc_buffer[0] = jhd_alloc(event_h2c->recv.payload_len);
	if(event_h2c->recv.alloc_buffer[0] == NULL){
		jhd_wait_mem(ev,event_h2c->recv.payload_len);
		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
	}else{
	    jhd_http2_do_recv_payload(ev,event_h2c,headers_frame_parse_begin);
	}
}
