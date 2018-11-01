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
	jhd_event_handler_pt err_handler;

	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	header = event_h2c->recv.state_param;



	if((ev)->timedout){
		log_err("timeout");
		err_handler = event_h2c->conf->connection_read_timeout;
		goto func_error;
	}
	p = event_h2c->recv.buffer + event_h2c->recv.state;

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
func_error:
    len =  event_h2c->recv.payload_len;
	event_h2c->recv.state_param = NULL;
	jhd_queue_move(&h,&event_h2c->recv.headers);

	err_handler(ev);

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
	u_char *p,*end,*old_hpack_data,*idx_name,*idx_val;
	jhd_event_handler_pt err_handler;
    u_char      ch,indexed,index,size_update,prefix,huff;
    uint32_t   value;
    uint16_t hpack_capacity,old_capacity,idx_name_len,idx_val_len,mem_len;
    int rc;

	log_assert_worker();

	event_c = ev->data;
	event_h2c = event_c->data;

	header = event_h2c->recv.state_param;
	end = event_h2c->recv.end;
	p = event_h2c->recv.pos;
	if((ev)->timedout){
		log_err("timeout");
		err_handler = event_h2c->conf->connection_read_timeout;
		goto func_error;
	}
	log_assert( end > p );
	for(;;){
		log_assert(end > p);
		event_h2c->recv.pos = p;
		if(header == NULL){
			event_h2c->recv.state_param = header = jhd_alloc(sizeof(jhd_http_header));
			if(header == NULL){
				 jhd_wait_mem(ev,sizeof(jhd_http_header));
				 jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
				 return;
			}
			memset(header,0,sizeof(jhd_http_header));
		}
		http2_header_first_parse(ch,p,index,size_update,indexed,prefix)

		rc = jhd_http2_parse_int(&value,prefix,p,end,21);
		if(rc == JHD_ERROR){
			err_handler = event_h2c->conf->connection_protocol_error;
			goto func_error;
		}else if(rc == JHD_AGAIN){
			goto func_read_next_frame;
		}
		p+=rc;
	    if(indexed){
	    	idx_name = NULL;
	    	idx_val = NULL;
	    	idx_name_len = 0;
	    	idx_val_len = 0;
	    	if(value ==0){
				err_handler = event_h2c->conf->connection_protocol_error;
				goto func_error;
	    	}
	    	jhd_http2_hpack_get_index_header_item(&event_h2c->recv.hpack,value,&idx_name,&idx_name_len,&idx_val,&idx_val_len);
	    	if(idx_name == NULL || idx_val == NULL){
				err_handler = event_h2c->conf->connection_protocol_error;
				goto func_error;
	    	}
	    	if(jhd_http2_hpack_is_dyncmic(value)){
	    	   if(header->name_alloced == 0){

	    		   log_assert(header->name == NULL);

	    		   header->name = jhd_alloc(idx_name_len +1);

	    		   if(header->name == NULL){
	    			   jhd_waite_mem(ev,idx_name_len +1);
	    			   jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
	    			   return;
	    		   }
	    		   memcpy(header->name,idx_name,idx_name_len+1);

	    		   header->name_alloced = idx_name_len +1;

	    		   header->name_len = idx_name_len;

	    	   }log_assert_code(else{

	    		  log_assert(header->name_alloced == (idx_name_len +1));

	    		  log_assert(memcmp(header->name,idx_name,idx_name_len +1)==0);

	    		  log_assert(header->name_len = idx_name_len);
	    	   })
	    	   if(0 == header->value_alloced){

	    		   log_assert(header->value == NULL);

	    		   header->value = jhd_alloc(idx_val_len +1);

	    		   if(header->value == NULL){

	    			   jhd_waite_mem(ev,idx_val_len +1);
	    			   jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
	    			   return;
	    		   }
	    		   memcpy(header->value,idx_val,idx_val_len+1);
	    		   header->value_alloced = idx_val_len +1;
	    		   header->value_len = idx_val_len;
	    	   }log_assert_code(else{
	    		  log_assert(header->value_alloced == (idx_val_len +1));

	    		  log_assert(memcmp(header->value,idx_val,idx_val_len +1)==0);

	    		  log_assert(header->value_len = idx_val_len);
	    	   })
	    	}else{
	    		if(header->name == NULL){
	    			log_assert(header->name_len == 0);

	    			log_assert(header->value == NULL);

	    			log_assert(header->value_len == 0);

	    			log_assert(header->name_alloced == 0);

	    			log_assert(header->value_alloced == 0);

	    			header->name = idx_name;
	    			header->value = idx_val;
	    			header->name_len = idx_name_len;
	    			header->value = idx_val_len;
	    		}log_assert_code(else{
	    			log_assert(header->name == idx_name);

	    			log_assert(header->name_len == idx_name_len);

	    		    log_assert(header->value == idx_val);

	    		    log_assert(header->value_len == idx_val_len);

	    		    log_assert(header->name_alloced == 0);

	    		    log_assert(header->value_alloced == 0);


	    		})
	    	}
	    }else if(size_update){
	    	log_assert(header != NULL);
	    	log_assert(header->name == NULL);
	    	log_assert(header->value == NULL);
	    	log_assert(header->name_len == 0);
	    	log_assert(header->name_alloced == 0);
	    	log_assert(header->value_len == 0);
	    	log_assert(header->value_alloced == 0);

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
	    		if((p == end)  &&   ((event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG)  = JHD_HTTP2_END_HEADERS_FLAG)){
	    			goto func_end_header_with_size_update;
	    		}else{
	    			event_h2c->recv.pos = p;
	    			jhd_unshift_event(ev,&jhd_posted_events);
	    			jhd_free_with_size(old_hpack_data,old_capacity);
	    			return;
	    		}
	    	}else{
	    		if((p == end) &&  ((event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG)  = JHD_HTTP2_END_HEADERS_FLAG)){
	    			goto func_end_header_with_size_update;
	    		}
	    	}
		}else{
			if(value/*!=0*/){
				idx_name = NULL;
				idx_name_len = 0;
				jhd_http2_hpack_get_index_header_name(&event_h2c->recv.hpack,value,&idx_name,&idx_name_len);
				if(idx_name == NULL){
					err_handler = event_h2c->conf->connection_protocol_error;
					goto func_error;
				}
				if(jhd_http2_hpack_is_dyncmic(value)){
					if (header->name_alloced == 0) {
						log_assert(header->name == NULL);
						header->name = jhd_alloc(idx_name_len + 1);
						if (header->name == NULL) {
							jhd_waite_mem(ev, idx_name_len + 1);
							jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);
							return;
						}
						memcpy(header->name, idx_name, idx_name_len + 1);
						header->name_alloced = idx_name_len + 1;
						header->name_len = idx_name_len;
					}log_assert_code(else{
						log_assert(header->name_alloced == (idx_name_len +1));
						log_assert(memcmp(header->name,idx_name,idx_name_len +1)==0);
					})
				}else{
					log_assert(header->name == NULL  || (header->name == idx_name));
					header->name = idx_name;
					header->name_alloced = 0;
					header->name_len = idx_name_len;
				}
			}else{
				if( p == end ){
					goto func_read_next_frame;
				}
				mem_len = 0;
				rc = jhd_http2_hpack_parse_value(p,end,&header->name,&header->name_len,&header->name_alloced,&mem_len);
				if(rc == JHD_ERROR){
					err_handler = event_h2c->conf->connection_protocol_error;
					goto func_error;
				}else if(rc == JHD_AGAIN){
					if(mem_len/*!=0*/){
						jhd_waite_mem(ev, mem_len);
						jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);
						return;
					}else{
						goto func_read_next_frame;
					}
				}
				p+=rc;
			}
			if( p == end ){
				goto func_read_next_frame;
			}
			mem_len = 0;
			rc = jhd_http2_hpack_parse_value(p,end,&header->value,&header->value_len,&header->value_alloced,&mem_len);
			if(rc == JHD_ERROR){
				err_handler = event_h2c->conf->connection_protocol_error;
				goto func_error;
			}else if(rc == JHD_AGAIN){
				if(mem_len/*!=0*/){
					jhd_waite_mem(ev, mem_len);
					jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);
					return;
				}else{
					goto func_read_next_frame;
				}
			}
			p+=rc;
			if(index){
				if(JHD_OK !=jhd_http2_hpack_add(&event_h2c->recv.hpack,header->name,header->name_len,header->value,header->value_len)){
					err_handler = event_h2c->conf->connection_protocol_error;
					goto func_error;
				}
			}
		}

	    jhd_queue_insert_tail(&event_h2c->recv.headers,&header->queue);
		event_h2c->recv.state_param = NULL;
		header = NULL;

		log_assert(p<=end);

		if( p == end ){
			if(0 == (event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG)){
				goto func_read_next_frame;
			}else{
				p = event_h2c->recv.alloc_buffer[0];
				value = event_h2c->recv.payload_len;
				ev->handler =event_h2c->conf->connection_end_headers_handler;
				jhd_unshift_event(ev,&jhd_posted_events);
				jhd_free_with_size(p,value);

			}
		}
	}
	return ;
func_read_next_frame:
	if(0 != (event_h2c->recv.frame_flag & JHD_HTTP2_END_HEADERS_FLAG)){
		err_handler = event_h2c->conf->connection_protocol_error;
		goto func_error;
	}
	if(header != NULL){
		log_assert(event_h2c->recv.state_param  ==  header);
		header->queue.next =event_h2c->recv.alloc_buffer[0];
	}else{
		event_h2c->recv.state_param = NULL;
		p = event_h2c->recv.alloc_buffer[0];
		value = event_h2c->recv.payload_len;
	}
	event_h2c->recv.state = 0;
	ev->handler = jhd_http2_recv_continuation_header;
	jhd_unshift_event(ev,&jhd_posted_events);

	if(header == NULL){
		jhf_free_with_size(p,value);
	}

	return;
func_end_header_with_size_update:
    log_assert(header != NULL);
	log_assert(header->name == NULL);
	log_assert(header->value == NULL);
	log_assert(header->name_len == 0);
	log_assert(header->name_alloced == 0);
	log_assert(header->value_len == 0);
	log_assert(header->value_alloced == 0);
	ev->handler =event_h2c->conf->connection_end_headers_handler;

	p =event_h2c->recv.alloc_buffer[0];

	value = event_h2c->recv.payload_len;

	event_h2c->recv.state_param = NULL;

	jhd_unshift_event(ev,&jhd_posted_events);

	jhd_free_with_size(p,value);

	if(old_hpack_data != NULL){
		jhd_free_with_size(old_hpack_data,old_capacity);
	}

	jhd_free_with_size(header,sizeof(jhd_http_header));
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