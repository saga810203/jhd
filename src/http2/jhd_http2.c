#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_time.h>



const u_char *jhd_http2_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";


#define JHD_HTTP2_SET_STRAM_ID_IN_CHECK(val) val = (event_h2c->recv.buffer[5] << 24) |(event_h2c->recv.buffer[6] << 16) |(event_h2c->recv.buffer[7] << 8) |(event_h2c->recv.buffer[8])


static void jhd_http2_frame_free_by_direct(void *data){
	jhd_http2_frame *frame = data;
	log_assert(data != NULL);
	log_assert(frame->free_func == jhd_http2_frame_free_by_direct  );
	if(frame->data != NULL){
		jhd_free_with_size(frame->data,frame->data_len);
	}
	jhd_free_with_size(frame,sizeof(jhd_http2_frame));
}

static void jhd_http2_data_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	jhd_http2_stream *stream;
	jhd_queue_t *q,*head;

	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id & 0X80000001 != 1){
		event_h2c->recv.state = 1;
		return;
	}
	if(((event_h2c->recv.frame_flag) & 0x8 != 0) && (event_h2c->recv.payload_len ==0)){
		event_h2c->recv.state = 1;
		return;
	}
	jhd_http2_set_curr_stream(stream_id);
	event_h2c->recv.window_size -= event_h2c->recv.payload_len;
	if(event_h2c->recv.window_size<0){
		event_h2c->recv.state = 1;
		return;
	}
	if(event_h2c->recv.stream !=NULL){
		event_h2c->recv.stream->recv_window_size -=event_h2c->recv.payload_len;
		if(event_h2c->recv.stream->recv_window_size <0){
			event_h2c->recv.state = 1;
			return;
		}
	}
}








static void jhd_http2_headers_frame_handler(jhd_event_t *ev){
	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev)

	if(event_h2c->recv.stream == NULL){
		if(event_h2c->recv.window_size < event_h2c->conf->recv_window_size_threshold){
			event_h2c->recv.state_param = jhd_http2_send_connection_window_update;
		}else{
			event_h2c->recv.state_param = jhd_http2_read_frame_header;
		}
		event_h2c->recv.state = event_h2c->recv.payload_len;
		ev->handler = jhd_http2_recv_skip;
		jhd_http2_recv_skip(ev);
		return;
	}
	if(event_h2c->recv.payload_len > 0){
		ev->handler = jhd_http2_data_frame_alloc_buffer;
		jhd_http2_data_frame_alloc_buffer(ev);
	}else{
		if(event_h2c->recv.frame_flag & 0x01 == 1){
			event_h2c->recv.stream->handler->remote_close_with_empty_data(event_h2c->recv.stream);

		}

	}
}


static void jhd_http2_priority_frame_header_check(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len != 5){
		event_h2c->recv.state = 1;
		return;
	}
}
static void jhd_http2_rst_stream_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len != 4){
		event_h2c->recv.state = 1;
		return;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id & 0X80000001 != 1){
		event_h2c->recv.state = 1;
		return;
	}
	jhd_http2_set_curr_stream(stream_id);
}

static void jhd_http2_setting_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif


	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id != 0){
		event_h2c->recv.state = 1;
		return;
	}
	if(event_h2c->recv.payload_len % 6 != 0){
		event_h2c->recv.state = 1;
		return;
	}
	if((event_h2c->recv.frame_flag & 0x01 !=0) && (event_h2c->recv.payload_len != 0)){
		event_h2c->recv.state = 1;
	}
}

static void jhd_http2_ping_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif

	if(event_h2c->recv.payload_len != 8){
		event_h2c->recv.state = 1;
		return;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id != 0){
		event_h2c->recv.state = 1;
		return;
	}
}

static void jhd_http2_goaway_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
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

static void jhd_http2_window_update_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;

#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len != 4){
		event_h2c->recv.state = 1;
		return;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id  == 0){
		event_h2c->recv.stream = (void*)(0xFFFFFFFFFFFFFFFFULL);
	}else{
		jhd_http2_set_curr_stream(stream_id);
	}
}



static void jhd_http2_unsupported_frame_type(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
	event_h2c->recv.state = 1;
}
static jhd_event_handler_pt jhd_http2_frame_header_check_pts[]={
	jhd_http2_data_frame_header_check,
	jhd_http2_headers_frame_header_check,
	jhd_http2_priority_frame_header_check,
	jhd_http2_rst_stream_frame_header_check,
	jhd_http2_setting_frame_header_check,
	jhd_http2_unsupported_frame_type,//push
	jhd_http2_ping_frame_header_check,
	jhd_http2_goaway_frame_header_check,
	jhd_http2_window_update_frame_header_check,
	jhd_http2_unsupported_frame_type,//CONTINUATION
};
static void jhd_http2_data_frame_read(jhd_event_t *ev){
	jhd_http2_frame *frame;
	ssize_t rc;
	size_t len;
	event_c = ev->data;
	event_h2c = event_c->data;

	JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev)

	frame = event_h2c->recv.state_param;
	log_assert((frame->data_len-9) == event_h2c->recv.payload_len);
	log_assert((frame->pos -9 - frame->len) == frame->data);

	len = event_h2c->recv.payload_len -frame->len;
	log_assert(len >0);

	rc = event_c->recv(event_c,frame->pos,len);
	if(rc >0){
        if(len == rc){
        	frame->pos-=frame->len;
        	frame->len = event_h2c->recv.payload_len;

        	if(frame->padded ==1){
                rc = frame->data_len - 1 - frame->data[0];
                if(rc<0){
                	event_h2c->recv.state_param  = NULL;
                	event_h2c->conf->connection_read_error(ev);
                	jhd_free_with_size(frame->data,frame->data_len);
                	jhd_frame_with_size(frame,sizeof(jhd_http2_frame));
                }else if(rc == 0){


                }else{

                }
        	}else{


        	}
        }else{
        	 frame->len +=rc;
        	 JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
        }
	}else if(rc == JHD_AGAIN){
		JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
	}else{
		event_h2c->conf->connection_read_error(ev);

	}
}

static void jhd_http2_send_connection_window_update(jhd_event_t *ev){
	jhd_http2_frame *frame;
	uint32_t len;
	event_c = ev->data;
	event_h2c = event_c->data;

	frame = event_h2c->recv.state_param;
	if((ev)->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		event_h2c->conf->connection_read_timeout(ev);
		if(frame){
			 log_assert(frame->tag =jhd_http2_send_connection_window_update);
             jhd_http2_frame_free_by_direct(frame);
		}
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	if(frame == NULL){
			frame = jhd_alloc(sizeof(jhd_http2_frame));
			if(frame==NULL){
				jhd_wait_mem(ev,sizeof(jhd_http2_frame));
				JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
				return;
			}
			memset(frame,0,sizeof(jhd_http2_frame));
			log_assert_code(frame->tag = jhd_http2_send_connection_window_update);
			frame->free_func = jhd_http2_frame_free_by_direct;
	}
	frame->data = jhd_alloc(13);
	if(frame->data == NULL){
		event_h2c->recv.state_param = frame;
		jhd_wait_mem(ev,13);
		JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
		return;
	}

	event_h2c->recv.state_param  = NULL;

	frame->data_len = 13;
	frame->len = 13;
	frame->type = JHD_HTTP2_FRAME_TYPE_WINDOW_UPDATE_FRAME;
	frame->pos = frame->data;

	//IN X86   00 00 04 08 = uint32_t
	*((uint32_t*)frame->data) =0x08040000;
	frame->data[4] = 0;
	*((uint32_t*)(5+frame->data)) =0;
	len = 2147483647 - event_h2c->recv.window_size;
	frame->data[9] =  (u_char)(len >> 24);
	frame->data[10] = u_char(len >> 16);
	frame->data[11] = u_char(len >> 8);
	frame->data[12] = u_char(len);
	jhd_http2_send_queue_frame(frame);
	ev->handler = event_h2c->conf->connection_frame_header_read;
	jhd_unshift_event(ev,&jhd_posted_events);
}

static void jhd_http2_data_frame_alloc_buffer(jhd_event_t *ev){
	jhd_http2_frame *frame;
	size_t len;
	event_c = ev->data;
	event_h2c = event_c->data;
	JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev)
	frame = event_h2c->recv.state_param;
	if(frame == NULL){
		frame = jhd_alloc(sizeof(jhd_http2_frame));
		if(frame==NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
			return;
		}
		event_h2c->recv.state_param = frame;
		memset(frame,0,sizeof(jhd_http2_frame));
		if((event_h2c->recv.frame_flag & 0x08)!=0){
			frame->padded = 1;
		}
		if((event_h2c->recv.frame_flag & 0x01)!=0){
			frame->end_stream = 1;
		}

	}
	len = event_h2c->recv.payload_len + 9;
	frame->data = jhd_alloc(len);
	if(frame->data == NULL){
		jhd_wait_mem(ev,len);
		return;
	}
	log_assert(event_h2c->recv.payload_len<=65535);
	frame->data_len =len;
	frame->pos = frame->data +9;
	ev->handler = jhd_http2_data_frame_read;
	jhd_http2_data_frame_read(ev);
}
static void jhd_http2_data_frame_handler(jhd_event_t *ev){
	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev)

	if(event_h2c->recv.stream == NULL){
		if(event_h2c->recv.window_size < event_h2c->conf->recv_window_size_threshold){
			event_h2c->recv.state_param = jhd_http2_send_connection_window_update;
		}else{
			event_h2c->recv.state_param = jhd_http2_read_frame_header;
		}
		event_h2c->recv.state = event_h2c->recv.payload_len;
		ev->handler = jhd_http2_recv_skip;
		jhd_http2_recv_skip(ev);
		return;
	}
	if(event_h2c->recv.payload_len > 0){
		ev->handler = jhd_http2_data_frame_alloc_buffer;
		jhd_http2_data_frame_alloc_buffer(ev);
	}else{
		if(event_h2c->recv.frame_flag & 0x01 == 1){
			event_h2c->recv.stream->handler->remote_close_with_empty_data(event_h2c->recv.stream);

		}

	}
}




static void jhd_http2_setting_resize_hpack(jhd_event_t ev){
	uint16_t capacity;
	uint32_t size;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;

	c = ev->data;
	h2c = c->data;
	if((ev)->timedout){
		log_err("timeout");
		h2c->conf->connection_read_timeout(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	size = (uint32_t) h2c->recv.state_param;
	if(JHD_OK ==jhd_http2_hpack_resize(&h2c->recv.hpack,(uint16_t)size,&capacity)){
		ev->handler = jhd_http2_setting_frame_handler;
		jhd_http2_setting_frame_handler(ev);
	}
	log_assert_code(else{log_assert(1>2);})
}

static void jhd_http2_setting_frame_handler(jhd_event_t *ev){
	ssize_t rc;
	size_t len;
	uint32_t idx,val;
	uint16_t capacity;
	uint64_t  param;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;

	jhd_queue_t  *head,*q;
	jhd_http2_stream *stream;
	size_t i;
	c = ev->data;
	h2c = c->data;
	if((ev)->timedout){
		log_err("timeout");
		h2c->conf->connection_read_timeout(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	if((h2c->recv.payload_len == 0)  ||(h2c->recv.payload_len == h2c->recv.state)){
		h2c->recv.state=0;
		ev->handler = jhd_http2_send_setting_frame_ack;
		jhd_http2_send_setting_frame_ack(ev);
		return;
	}
	log_assert(h2c->recv.state < h2c->recv.payload_len);


	for(;;){
		len = 6 -(h2c->recv.state % 6);
		rc = c->recv(c,h2c->recv.buffer  + 6 - len,len);
		if(rc > 0){
			h2c->recv.state += rc;
			if(rc == len){
				idx = (h2c->recv.buffer[0] << 8) | h2c->recv.buffer[1];
				val =  (h2c->recv.buffer[2] << 24) | (h2c->recv.buffer[3] << 16) | (h2c->recv.buffer[4] << 8) | h2c->recv.buffer[5];
				if(idx == 0x01){
					//SETTINGS_HEADER_TABLE_SIZE
					if(val > (0xFFFF - 4096)){
						h2c->conf->connection_unsupported_error(ev);
						return;
					}
					if(val != h2c->recv.hpack.size){
						if(JHD_OK !=jhd_http2_hpack_resize(&h2c->recv.hpack,(uint16_t)val,&capacity)){
							h2c->recv.state_param = (void*)val;
							ev->handler = jhd_http2_setting_resize_hpack;
							jhd_wait_mem(ev,capacity);
							jhd_event_add_timer(ev,h2c->conf->wait_mem_timeout);
							return;
						}
					}
				}else if(idx == 0x02){
					//SETTINGS_ENABLE_PUSH
					//IGNORE
				}else if(idx == 0x03){
					//SETTINGS_MAX_CONCURRENT_STREAMS
					if(val < h2c->max_streams){
						if(val == 0){
							h2c->conf->connection_unsupported_error(ev);
							return;
						}
						h2c->max_streams = val;
					}else if(val > h2c->max_streams){
						 h2c->max_streams = val <= h2c->conf->max_streams?val:h2c->conf->max_streams;
					}
				}else if(idx == 0x04){
					//SETTINGS_INITIAL_WINDOW_SIZE
					if(val > 65535){
						h2c->conf->connection_protocol_error(ev);
						return;
					}
					for(head = h2c->streams,i=0; i < 32; ++i,++head){
						for(q=jhd_queue_next(head);q != head;q = q->next){
							stream = jhd_queue_data(q,jhd_http2_stream,queue);
							if(stream->state > JHD_HTTP2_STREAM_STATE_CLOSE_LOCAL){
								rc = stream->send_window_size + val - h2c->send.initial_window_size;
								if(rc > 2147483647){
									h2c->recv.state = JHD_HTTP2_FLOW_CTRL_ERROR;
									h2c->conf->connection_protocol_error(ev);
									return;
								}
								stream->send_window_size = rc;
							}
						}
					}
					h2c->send.initial_window_size = val;
				}else if(idx == 0x05){
					//SETTINGS_MAX_FRAME_SIZE (0x5)
					//IGNORE  impl val == 16384
				}else if(idx == 0x06){
					//SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
					//IGNORE
				}
				if(h2c->recv.state == h2c->recv.payload_len){
					h2c->recv.state = 0;
					h2c->recv.state_param = NULL;
					ev->handler = jhd_http2_send_setting_frame_ack;
					jhd_http2_send_setting_frame_ack(ev);
					return;
				}
			}else{
				jhd_event_add_timer(ev,h2c->conf->read_timeout);
				return;
			}
		}else if(rc == JHD_AGAIN){
			JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev);
			return;
		}else{
			log_err("io error");
			event_h2c->conf->connection_read_error(ev);
			return;
		}
	}
}



static jhd_event_handler_pt jhd_http2_frame_handler_pts[]={
	jhd_http2_data_frame_handler,
	jhd_http2_headers_frame_handler,
	jhd_http2_priority_frame_handler,
	jhd_http2_rst_stream_frame_handler,
	jhd_http2_setting_frame_handler,
	NULL,//push
	jhd_http2_ping_frame_handler,
	jhd_http2_goaway_frame_handler,
	jhd_http2_window_update_frame_handler,
	NULL,//CONTINUATION
};

void jhd_http2_connection_default_idle_handler(jhd_event_t *ev){
	log_assert(event_c = ev->data);
	log_assert(event_h2c == event_c->data);
	JHD_HTTP2_CONNECTION_ADD_IDLE_TIMEOUT(ev);
}
void jhd_http2_connection_default_protocol_error_handler(jhd_event_t *ev){
	event_c = ev->data;
	event_h2c = event_c->data;

	event_h2c->recv.state = 0;
	event_h2c->recv.state_param = NULL;
	event_h2c->recv_error = 1;
	event_c->close(event_c);
	//TODO impl send goaway frame
}




void jhd_http2_recv_skip(jhd_event_t *ev){
	ssize_t rc;
	size_t len;
	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;
	log_assert(event_h2c->recv.state_param != NULL);

	if((ev)->timedout ==1){
		log_err("timeout");
		event_h2c->conf->connection_read_timeout(ev);
		return;
	}
	for(;;){
		len = event_h2c->recv.state;
		if(len > 16384){
			len = 16384;
		}
		rc = event_c->read(event_c,jhd_calc_buffer,len);
		if(rc > 0){
			event_h2c->recv.state-=rc;
			if(rc < len){
				jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
				break;
			}else if(event_h2c->recv.state == 0){
				ev->handler = event_h2c->recv.state_param;
				ev->handler(ev);
				break;
			}
		}else if (rc == JHD_AGAIN){
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
			break;
		}else{
			event_h2c->conf->connection_read_error(ev);
			break;
		}
	}
}


void jhd_http2_recv_payload(jhd_event_t *ev){
	ssize_t rc;
	size_t len;
	u_char *p;

	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	p = event_h2c->recv.alloc_buffer[0];


	if((ev)->timedout){
		log_err("timeout");
		len =  event_h2c->recv.payload_len;
		event_h2c->conf->connection_read_timeout(ev);
		jhd_free_with_size(p,len);
		return;
	}

	p += event_h2c->recv.state;

	len = event_h2c->recv.payload_len - event_h2c->recv.state;

	log_assert(len >0);

	rc = event_c->recv(event_c,p,len);
	if(rc > 0){
		if(rc == len){
			event_h2c->recv.state = 0;
			ev->handler = event_h2c->recv.state_param;
			event_h2c->recv.state_param = NULL;
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
		event_h2c->conf->connection_read_error(ev);
		jhd_free_with_size(p,len);
	}
}

void jhd_http2_recv_buffer(jhd_event_t *ev){
	ssize_t rc;
	size_t len;
	u_char *p;

	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	p = event_h2c->recv.buffer;
	if((ev)->timedout ==1){
		log_err("timeout");
		event_h2c->conf->connection_read_timeout(ev);
		return;
	}
	p += event_h2c->recv.state;

	len = event_h2c->recv.payload_len - event_h2c->recv.state;

	log_assert(len >0 && len < sizeof(event_h2c->recv.buffer));

	rc = event_c->recv(event_c,p,len);
	if(rc > 0){
		if(rc == len){
			event_h2c->recv.state = 0;
			ev->handler = event_h2c->recv.state_param;
			ev->handler(ev);
		}else{
			event_h2c->recv.state += rc;
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
		}
	}else if(rc == JHD_AGAIN){
		jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
	}else{
		event_h2c->conf->connection_read_error(ev);
	}
}

void jhd_http2_read_frame_header(jhd_event_t *ev){
	ssize_t ret,len;
	u_char *p;
	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;
	JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev)


	log_assert(event_h2c->recv.state <= 8);

	event_h2c->recv.frame_type = 0xFF;

	ret = event_c->read(event_c,event_h2c->recv.buffer+ event_h2c->recv.state,9-event_h2c->recv.state);
	if(ret >0){
		event_h2c->recv.state +=ret;
		if(event_h2c->recv.state <9){
			JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
			log_notice("<==%s EAGAIN",__FUNCTION__);
		}else{


			event_h2c->recv.payload_len = (event_h2c->recv.buffer[0] << 16) | (event_h2c->recv.buffer[1] << 8) | (event_h2c->recv.buffer[2]);
			if(event_h2c->recv.payload_len> 16384){
				log_err("invalid frame payload length[%u]",event_h2c->recv.payload_len);
				event_h2c->conf->connection_protocol_error(ev);
				return;
			}
			event_h2c->recv.frame_type = event_h2c->recv.buffer[3];
			if(event_h2c->recv.frame_type > JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME){
				log_err("invalid frame type[0X%02X]",event_h2c->recv.buffer[3]);
				event_h2c->conf->connection_protocol_error(ev);
				return;
			}
			event_h2c->recv.frame_flag = event_h2c->recv.buffer[4];

			event_h2c->recv.state = 0;
			event_h2c->conf->frame_header_check_pts[event_h2c->recv.frame_type](ev);

            log_assert(event_c == ev->data);
            log_aseert(event_h2c == event_c->data);

			if(JHD_OK != event_h2c->recv.state){
				log_err("invalid frame header");
				log_buf_debug("invalid frame header==>",event_h2c->recv.buffer,9);
				event_h2c->conf->connection_protocol_error(ev);
				return;
			}
			event_h2c->recv.state_param = NULL;
			event_h2c->conf->frame_payload_handler_pts[event_h2c->recv.frame_type](ev);
			ev->handler(ev);
			return;
		}
	}else if(ret == JHD_AGAIN){
		if(event_h2c->recv.state==0){
			if(event_h2c->processing ==0){
				event_h2c->conf->connection_idle(ev);
			}else{
				if(ev->timer.key){
					jhd_event_del_timer(ev);
				}
			}
		}else{
			JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
		}
		log_notice("<==%s EAGAIN",__FUNCTION__);
	}else{
		event_h2c->conf->connection_read_error(ev);
		log_notice("<==%s error",__FUNCTION__);
	}
}



void jhd_http2_send_setting_frame(jhd_event_t *ev){
	jhd_http2_frame *frame;
	uint32_t len;
	event_c = ev->data;
	event_h2c = event_c->data;

	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	u_char *p;

	frame = event_h2c->recv.state_param;

	if((ev)->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		event_h2c->conf->connection_read_timeout(ev);
		if(frame){
			 log_assert(frame->tag =jhd_http2_send_setting_frame);
             jhd_http2_frame_free_by_direct(frame);
		}
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	if(frame == NULL){
		frame = jhd_alloc(sizeof(jhd_http2_frame));
		if(frame == NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
			JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
			return;
		}
		memset(frame,0,sizeof(jhd_http2_frame));
		frame->free_func = jhd_http2_frame_free_by_direct;
		log_assert_code(frame->tag = jhd_http2_send_setting_frame;)
	}

	p = frame->data = jhd_alloc(9 + 24 );
	if(frame->data == NULL){
		event_h2c->recv.state_param = frame;
		jhd_wait_mem(ev,9 + 24);
		JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
		return;
	}
	event_h2c->recv->state_param = NULL;


	frame->data_len = 24 + 9;
	frame->len = 24 + 9 ;
    frame->pos = frame->data;
    frame->type = JHD_HTTP2_FRAME_TYPE_SETTINGS_FRAME;

    //000018  len  type 04
    *((uint32_t*)p) = 0x04180000;
    p[4] = 0;
    p+=5;
    *((uint32_t*)p) = 0;
	p+=4;

	//SETTINGS_HEADER_TABLE_SIZE
	*p= 0;
	++p;
	*p = 0x01;
	++p;
	*p = (u_char)(event_h2c->conf->max_header_table_size >> 24);
	++p;
	*p = (u_char) (event_h2c->conf->max_header_table_size >> 16);
	++p;
	*p = (u_char) (event_h2c->conf->max_header_table_size >> 8);
	++p;
	*p = (u_char) (event_h2c->conf->max_header_table_size);

	//SETTINGS_ENABLE_PUSH (0x2)
	++p;
	*p= 0;
	++p;
	*p = 0x02;
	++p;
    *((uint32_t*)p) = 0;
	p+=4;
	//SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
	*p= 0;
	++p;
	*p = 0x03;
	++p;
	*p = (u_char)(event_h2c->conf->max_streams >> 24);
	++p;
	*p = (u_char) (event_h2c->conf->max_streams >> 16);
	++p;
	*p = (u_char) (event_h2c->conf->max_streams >> 8);
	++p;
	*p = (u_char) (event_h2c->conf->max_streams);

	//SETTINGS_INITIAL_WINDOW_SIZE (0x4)
	++p;
	*p= 0;
	++p;
	*p = 0x03;
	++p;
	*p = (u_char)(event_h2c->conf->initial_window_size >> 24);
	++p;
	*p = (u_char) (event_h2c->conf->initial_window_size >> 16);
	++p;
	*p = (u_char) (event_h2c->conf->initial_window_size >> 8);
	++p;
	*p = (u_char) (event_h2c->conf->initial_window_size);
	jhd_http2_send_queue_frame(frame);
	ev->handler = event_h2c->conf->connection_frame_header_read;
	jhd_unshift(ev,&jhd_posted_events);
}
void jhd_http2_send_setting_frame_ack(jhd_event_t *ev){
	jhd_http2_frame *frame;
	uint32_t len;
	event_c = ev->data;
	event_h2c = event_c->data;

	frame = event_h2c->recv.state_param;

	if((ev)->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		event_h2c->conf->connection_read_timeout(ev);
		if(frame){
			 log_assert(frame->tag =jhd_http2_send_setting_frame_ack);
             jhd_http2_frame_free_by_direct(frame);
		}
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	if(frame == NULL){
		frame = jhd_alloc(sizeof(jhd_http2_frame));
		if(frame == NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
			JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
			return;
		}
		memset(frame,0,sizeof(jhd_http2_frame));
		event_h2c->recv.state_param = frame;
		frame->free_func = jhd_http2_frame_free_by_direct;
		log_assert_code(frame->tag = jhd_http2_send_setting_frame_ack;)
	}

	p = frame->data = jhd_alloc(9);
	if(frame->data == NULL){
		event_h2c->recv.state_param = frame;
		jhd_wait_mem(ev,9);
		JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
		return;
	}
	event_h2c->recv->state_param = NULL;


	frame->data_len =  9;
	frame->len =  9 ;
    frame->pos = frame->data;
    frame->type = JHD_HTTP2_FRAME_TYPE_SETTINGS_FRAME;

    //000000  len  type 04
    *((uint32_t*)p) = 0x04000000;
    p[4] = 0x01;//ack
    p+=5;
    *((uint32_t*)p) = 0;

    jhd_http2_send_queue_frame(frame);

    ev->handler = event_h2c->conf->connection_frame_header_read;

    jhd_unshift(ev,&jhd_posted_events);



}
void jhd_http2_send_ping_frame(jhd_event_t *ev){
	jhd_http2_frame *frame;
	uint32_t len;
	event_c = ev->data;
	event_h2c = event_c->data;

	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	u_char *p;

	frame = event_h2c->recv.state_param;

	if((ev)->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		event_h2c->conf->connection_read_timeout(ev);
		if(frame){
			 log_assert(frame->tag =jhd_http2_send_ping_frame);
             jhd_http2_frame_free_by_direct(frame);
		}
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	if(frame == NULL){
		frame = jhd_alloc(sizeof(jhd_http2_frame));
		if(frame == NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
			JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
			return;
		}
		memset(frame,0,sizeof(jhd_http2_frame));
		frame->free_func = jhd_http2_frame_free_by_direct;
		log_assert_code(frame->tag = jhd_http2_send_ping_frame;)
	}

	p = frame->data = jhd_alloc(9 + 8);
	if(frame->data == NULL){
		event_h2c->recv.state_param = frame;
		jhd_wait_mem(ev,9 + 8);
		JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
		return;
	}
	event_h2c->recv->state_param = NULL;


	frame->data_len = 8 + 9;
	frame->len = 8 + 9 ;
    frame->pos = frame->data;
    frame->type = JHD_HTTP2_FRAME_TYPE_PING_FRAME;

    //000018  len  type 04
    *((uint32_t*)p) = 0x06080000;
    p[4] = 0;
    p+=5;
    *((uint32_t*)p) = 0;
	p+=4;
	*((uint64_t*)p) = jhd_current_msec;
	jhd_http2_send_queue_frame(frame);
	ev->handler = event_h2c->conf->connection_frame_header_read;
	jhd_unshift(ev,&jhd_posted_events);
}

void jhd_http2_send_ping_frame_ack(jhd_event_t *ev){
	jhd_http2_frame *frame;
	uint32_t len;
	event_c = ev->data;
	event_h2c = event_c->data;

	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	u_char *p;

	frame = event_h2c->recv.state_param;

	if((ev)->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		event_h2c->conf->connection_read_timeout(ev);
		if(frame){
			 log_assert(frame->tag =jhd_http2_send_ping_frame_ack);
             jhd_http2_frame_free_by_direct(frame);
		}
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	if(frame == NULL){
		frame = jhd_alloc(sizeof(jhd_http2_frame));
		if(frame == NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
			JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
			return;
		}
		memset(frame,0,sizeof(jhd_http2_frame));
		frame->free_func = jhd_http2_frame_free_by_direct;
		log_assert_code(frame->tag = jhd_http2_send_ping_frame_ack;)
	}

	p = frame->data = jhd_alloc(9 + 8);
	if(frame->data == NULL){
		event_h2c->recv.state_param = frame;
		jhd_wait_mem(ev,9 + 8);
		JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
		return;
	}
	event_h2c->recv->state_param = NULL;


	frame->data_len = 8 + 9;
	frame->len = 8 + 9 ;
    frame->pos = frame->data;
    frame->type = JHD_HTTP2_FRAME_TYPE_PING_FRAME;

    //000018  len  type 04
    *((uint32_t*)p) = 0x06080000;
    p[4] = 0x01; //ack
    p+=5;
    *((uint32_t*)p) = 0;
	p+=4;
	*((uint64_t*)p) = *((uint64_t*)event_h2c->recv.buffer);
	jhd_http2_send_ping_ack(frame);
	ev->handler = event_h2c->conf->connection_frame_header_read;
	jhd_unshift(ev,&jhd_posted_events);
}




//TODO optimized code with ssl write  by  buffer   if  frame size is to small;
static jhd_inline void jhd_http2_send_event_handler(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
		ssize_t rc;
		jhd_http2_frame * frame,*prev_frame;
		jhd_tls_ssl_context *ssl;
		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		c = ev->data;
		h2c = c->data;
		frame = h2c->send.head;
		if((ev)->timedout){
				log_err("timeout");
				h2c->conf->connection_send_timeout(ev);
				log_notice("<==%s with timedout",__FUNCTION__);
				return;
		}
		while (frame != NULL) {
			rc = c->send(c, frame->pos, frame->len);
			if(rc > 0){
				log_assert(rc <= frame->len);
				if(rc == frame->len){
					prev_frame = frame;
					frame = frame->next;
					prev_frame->free_func(prev_frame);
				}else{
					h2c->send.head = frame;
					frame->pos +=rc;
					frame->len -=rc;
					jhd_event_add_timer(ev,h2c->conf->write_timeout);
					log_notice("<==%s with write EAGAIN",__FUNCTION__);
					return;
				}
			}else if(rc == JHD_AGAIN) {
				h2c->send.head = frame;
				jhd_event_add_timer(ev,h2c->conf->write_timeout);
				log_notice("<==%s with write EAGAIN",__FUNCTION__);
				return;
			}else{
				h2c->send.head = frame;
				h2c->conf->connection_send_error(ev);
				log_notice("<==%s with write ERROR",__FUNCTION__);
				return;
			}
		}
        h2c->send.head = h2c->send.tail = NULL;
        ssl = c->ssl;
        if(ssl != NULL && ssl->out_msglen > 0){
			rc = jhd_tls_ssl_flush(c,ssl);
			if(rc == JHD_AGAIN){
				jhd_event_add_timer(ev,h2c->conf->write_timeout);
				log_notice("<==%s with write EAGAIN",__FUNCTION__);
				return;
			}else if(rc == JHD_ERROR){
				h2c->conf->connection_send_error(ev);
				log_notice("<==%s with write ERROR",__FUNCTION__);
				return;
			}
        }
        if(h2c->goaway_sent){
        	//TODO check
        	c->close(c);
        	return;
        }
}


void jhd_http2_send_event_handler_clean(jhd_event_t *ev){
	jhd_http2_send_event_handler(ev);
}
void jhd_http2_send_event_handler_ssl(jhd_event_t *ev){
	jhd_http2_send_event_handler(ev);
}





jhd_http_request_info  jhd_http2_info={};
