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

static int jhd_http2_data_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	jhd_http2_stream *stream;
	jhd_queue_t *q,*head;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(((event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME) || (event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME)) &&
					(event_h2c->recv.frame_flag & 0x01 == 0)){
		return JHD_ERROR;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id & 0X80000001 != 1){
		return JHD_ERROR;
	}
	jhd_http2_set_curr_stream(stream_id);

	return JHD_OK;
}
static int jhd_http2_headers_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(((event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME) || (event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME)) &&
					(event_h2c->recv.frame_flag & 0x01 == 0)){
		return JHD_ERROR;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id & 0X80000001 != 1){
		return JHD_ERROR;
	}
	if(stream_id <= event_h2c->recv.last_stream_id){
		return JHD_ERROR;
	}
	event_h2c->recv.last_stream_id = stream_id;
	return JHD_OK;
}
static int jhd_http2_priority_frame_header_check(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(((event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME) || (event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME)) &&
					(event_h2c->recv.frame_flag & 0x01 == 0)){
		return JHD_ERROR;
	}
	if(event_h2c->recv.payload_len != 5){
		return JHD_ERROR;
	}

	return JHD_OK;
}
static int jhd_http2_rst_stream_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(((event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME) || (event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME)) &&
					(event_h2c->recv.frame_flag & 0x01 == 0)){
		return JHD_ERROR;
	}
	if(event_h2c->recv.payload_len != 4){
		return JHD_ERROR;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id & 0X80000001 != 1){
		return JHD_ERROR;
	}
	jhd_http2_set_curr_stream(stream_id);
	return JHD_OK;
}

static int jhd_http2_setting_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !define(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(((event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME) || (event_h2c->recv.frame_type == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME)) &&
					(event_h2c->recv.frame_flag & 0x01 == 0)){
		return JHD_ERROR;
	}
	if(event_h2c->recv.payload_len != 4){
		return JHD_ERROR;
	}
	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id & 0X80000001 != 1){
		return JHD_ERROR;
	}
	jhd_http2_set_curr_stream(stream_id);
	return JHD_OK;
}


static jhd_event_handler_pt jhd_http2_frame_header_check_pts[]={
	jhd_http2_data_frame_header_check,
	jhd_http2_headers_frame_header_check,
	jhd_http2_priority_frame_header_check,
	jhd_http2_rst_stream_frame_header_check,
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
	log_assert(event_h2c->recv.next_recv_handler != NULL);
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
				ev->handler = event_h2c->recv.next_recv_handler;
				jhd_post_event(ev,&jhd_posted_events);
				return;
			}
		}else if (rc == JHD_AGAIN){
			JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev);
			return;
		}else{
			event_h2c->recv_error = 1;
			event_c->close(event_c);
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
			if(event_h2c->recv.buffer[3] > JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME){
				log_err("invalid frame type[0X%02X]",event_h2c->recv.buffer[3]);
				event_h2c->conf->connection_protocol_error(ev);
				return;
			}

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
		event_h2c->recv_error = 1;
		event_c->close(event_c);
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
