#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>



const u_char *jhd_http2_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";


#define JHD_HTTP2_SET_STRAM_ID_IN_CHECK(val) val = (event_h2c->recv.buffer[5] << 24) |(event_h2c->recv.buffer[6] << 16) |(event_h2c->recv.buffer[7] << 8) |(event_h2c->recv.buffer[8])


jhd_inline static void jhd_http2_set_curr_stream(uint32_t sid){
	jhd_http2_stream *stream;
	jhd_queue_t *q,*head;
	stream = event_h2c->recv.stream;
	if(stream == NULL || stream->id != sid){
		event_h2c->recv.stream = NULL;
		head = &(event_h2c->streams[(sid >1) & 0x1F]);
		for(q = head->next; q != head ; q = q->next){
			stream = jhd_queue_data(q,jhd_http2_stream,queue);
			if(stream->id == sid){\
				event_h2c->recv.stream = stream;\
				break;
			}
		}
	}
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
static void jhd_http2_headers_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
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
	if(stream_id <= event_h2c->recv.last_stream_id){
		event_h2c->recv.state = 1;
		return;
	}
	event_h2c->recv.last_stream_id = stream_id;
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
	if(frame == NULL){
			frame = jhd_alloc(sizeof(jhd_http2_frame));
			if(frame==NULL){
				jhd_wait_mem(ev,sizeof(jhd_http2_frame));
				return;
			}
			event_h2c->recv.state_param = frame;
			memset(frame,0,sizeof(jhd_http2_frame));
			frame->type = JHD_HTTP2_FRAME_TYPE_WINDOW_UPDATE_FRAME;
			frame->data_len =13;
			frame->free_data = 1;
			frame->pos = frame->data;
			frame->len = 13;
	}
	frame->data = jhd_alloc(13);
	if(frame->data == NULL){
		event_h2c->recv.state_param = frame;
		jhd_wait_mem(ev,13);
		return;
	}
	event_h2c->recv.state_param  = NULL;
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
	ev->handler = jhd_http2_read_frame_header;
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
		frame->free_data = 1;
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



static jhd_event_handler_pt jhd_http2_frame_handler_pts[]={
	jhd_http2_data_frame_handler,
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

void jhd_http2_connection_default_idle_handler(jhd_event_t *ev){
	log_assert(event_c = ev->data);
	log_assert(event_h2c == event_c->data);
	JHD_HTTP2_CONNECTION_ADD_IDLE_TIMEOUT(ev);
}
void jhd_http2_connection_default_protocol_error_handler(jhd_event_t *ev){
	log_assert(event_c = ev->data);
	log_assert(event_h2c == event_c->data);
	event_h2c->recv_error = 1;
	event_c->close(event_c);
	//TODO impl send goaway frame
}




void jhd_http2_recv_skip(jhd_event_t *ev){
	u_char buffer[1024];
	ssize_t rc;
	size_t len;
	jhd_http2_frame * frame,prev_frame;
	jhd_tls_ssl_context *ssl;
	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;
	log_assert(event_h2c->recv.state_param != NULL);
	JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev)

	for(;;){
		len = event_h2c->recv.state;
		if(len > 1024){
			len = 1024;
		}
		rc = event_c->read(event_c,buffer,len);
		if(rc > 0){
			event_h2c->recv.state-=rc;
			if(rc < len){
				JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
				return;
			}else if(event_h2c->recv.state == 0){
				ev->handler = event_h2c->recv.state_param;
				event_h2c->recv.state_param = NULL;
				jhd_post_event(ev,&jhd_posted_events);
				return;
			}
		}else if (rc == JHD_AGAIN){
			JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
			return;
		}else{
			event_h2c->conf->connection_read_error(ev);
			return;
		}
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
			event_h2c->recv->state = 0;
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
			jhd_http2_frame_header_check_pts[event_h2c->recv.frame_type](ev);

			if(JHD_OK != event_h2c->recv.state){
				log_err("invalid frame header");
				log_buf_debug("invalid frame header==>",event_h2c->recv.buffer,9);
				event_h2c->conf->connection_protocol_error(ev);
				return;
			}
			event_h2c->recv.state_param = NULL;
			ev->handler = jhd_http2_frame_handler_pts[event_h2c->recv.frame_type];
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


//TODO optimized code with ssl write  by  buffer   if  frame size is to small;
static jhd_inline void jhd_http2_send_event_handler(jhd_event_t *ev){
		ssize_t rc;
		jhd_http2_frame * frame,prev_frame;
		jhd_tls_ssl_context *ssl;
		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		event_c = ev->data;
		event_h2c = event_c->data;
		frame = event_h2c->send.head;
		jhd_event_with_timeout(ev){
				event_h2c->send_error = 1;
				log_err("timeout");
				event_c->close(event_c);
				log_notice("<==%s with timedout",__FUNCTION__);
				return;
		}
		while (frame != NULL) {
			rc = event_c->send(event_c, frame->pos, frame->len);
			if(rc > 0){
				log_assert(rc <= frame->len);
				if(rc == frame->len){
					if(frame->free_data){
						jhd_free_with_size(frame->data,frame->data_len);
					}
					prev_frame = frame;
					frame = frame->next;
					jhd_free_with_size(prev_frame,sizeof(jhd_http2_frame));
				}else{
					event_h2c->send.head = frame;
					frame->pos +=rc;
					frame->len -=rc;
					JHD_HTTP2_CONNECTION_ADD_WRITE_TIMEOUT(ev);
					log_notice("<==%s with write EAGAIN",__FUNCTION__);
					return;
				}
			}else if(rc == JHD_AGAIN) {
				event_h2c->send.head = frame;
				JHD_HTTP2_CONNECTION_ADD_WRITE_TIMEOUT(ev);
				log_notice("<==%s with write EAGAIN",__FUNCTION__);
				return;
			}else{
				event_h2c->send.head = frame;
				event_h2c->send_error = 1;
				event_c->close(event_c);
				log_notice("<==%s with write ERROR",__FUNCTION__);
				return;
			}
		}
        event_h2c->send.head = event_h2c->send.tail = NULL;
        ssl = event_c->ssl;
        if(ssl != NULL && ssl->out_msglen > 0){
			rc = jhd_tls_ssl_flush(event_c,ssl);
			if(rc == JHD_AGAIN){
				JHD_HTTP2_CONNECTION_ADD_WRITE_TIMEOUT(ev);
				log_notice("<==%s with write EAGAIN",__FUNCTION__);
				return;
			}else if(rc == JHD_ERROR){
				event_h2c->send_error = 1;
				event_c->close(event_c);
				log_notice("<==%s with write ERROR",__FUNCTION__);
				return;
			}
        }
        if(event_h2c->goaway_sent){
        	event_c->close(event_c);
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
