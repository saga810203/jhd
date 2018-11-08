#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_time.h>



const char *jhd_http2_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

uint32_t jhd_http2_error_code;

#ifdef JHD_LOG_LEVEL_ERR

char *jhd_http2_error_file;
char *jhd_http2_error_func;
int   jhd_http2_error_line;
#endif



jhd_http2_connection *event_h2c;


#define JHD_HTTP2_SET_STRAM_ID_IN_CHECK(val) val = (event_h2c->recv.buffer[5] << 24) |(event_h2c->recv.buffer[6] << 16) |(event_h2c->recv.buffer[7] << 8) |(event_h2c->recv.buffer[8])










static void jhd_http2_setting_frame_handler(jhd_event_t *ev);




//CONTINUATION  PUSH FRAME HANDLER
void jhd_http2_unsupported_frame_type(jhd_event_t *ev){
	log_assert(event_c == ev->data);
	log_assert(event_h2c == event_c->data);
#ifndef JHD_LOG_ASSERT_ENABLE
	(void*)ev;
#endif
	event_h2c->conf->connection_protocol_error(ev);
}

static void jhd_http2_rest_stream_after_skip_data(jhd_event_t *ev){
	jhd_http2_stream *stream;
	jhd_http2_frame *frame;
	u_char *p;

	event_c = ev->data;
	event_h2c = event_c->data;

	if(ev->timedout){
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_mem_time_out(ev);
	}else{
		stream = event_h2c->recv.stream;
		frame = jhd_alloc(sizeof(jhd_http2_frame)+13);
		if(frame==NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame)+13);
			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		}else{
			jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+13);
			frame->type = JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME;
			//IN X86   00 00 04 03 = uint32_t
			p = frame->pos;

			*((uint32_t*)p) =0x03040000;
			p[4] = 0;
			p += 5;
			jhd_http2_set_stream_id(p,stream->id);
			p+=4;
			*((uint32_t*)p) = event_h2c->recv.state;
			jhd_http2_send_queue_frame(frame);
			stream->listener->reset(ev);
			event_h2c->recv.stream = &jhd_http2_invalid_stream;
			jhd_queue_only_remove(&stream->queue);
			jhd_queue_only_remove(&stream->flow_control);
			--event_h2c->processing;
			event_h2c->recv.state =event_h2c->recv.payload_len;
			event_h2c->recv.state_param = event_h2c->recv.connection_frame_header_read;
			ev->handler = jhd_http2_recv_skip;
			jhd_unshift_event(ev,&jhd_posted_events);
			jhd_free_with_size(stream,sizeof(jhd_http2_stream));
		}
	}
	log_notice("<==%s with timedout",__FUNCTION__);
}

static void jhd_http2_rest_stream_after_read_frame_header(jhd_event_t *ev){
	jhd_http2_stream *stream;
	jhd_http2_frame *frame;
	u_char *p;

	event_c = ev->data;
	event_h2c = event_c->data;

	if(ev->timedout){
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_mem_time_out(ev);
	}else{
		stream = event_h2c->recv.stream;
		frame = jhd_alloc(sizeof(jhd_http2_frame)+13);
		if(frame==NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame)+13);
			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		}else{
			jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+13);
			frame->type = JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME;
			//IN X86   00 00 04 03 = uint32_t
			p = frame->pos;

			*((uint32_t*)p) =0x03040000;
			p[4] = 0;
			p += 5;
			jhd_http2_set_stream_id(p,stream->id);
			p+=4;
			*((uint32_t*)p) = event_h2c->recv.state;
			jhd_http2_send_queue_frame(frame);
			stream->listener->reset(ev);
			event_h2c->recv.stream = &jhd_http2_invalid_stream;
			jhd_queue_only_remove(&stream->queue);
			jhd_queue_only_remove(&stream->flow_control);
			--event_h2c->processing;
			event_h2c->recv.state =0;
			ev->handler = event_h2c->recv.connection_frame_header_read;
			jhd_unshift_event(ev,&jhd_posted_events);
			jhd_free_with_size(stream,sizeof(jhd_http2_stream));
		}
	}
	log_notice("<==%s with timedout",__FUNCTION__);
}

static void jhd_http2_send_connection_window_update(jhd_event_t *ev){
	jhd_http2_frame *frame;
	uint32_t len;

	log_notice("==>%s",__FUNCTION__);
	event_c = ev->data;
	event_h2c = event_c->data;
	if(ev->timedout){
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_mem_time_out(ev);
		goto func_return;
	}
	frame = jhd_alloc(sizeof(jhd_http2_frame)+13);
	if(frame==NULL){
		jhd_wait_mem(ev,sizeof(jhd_http2_frame)+13);
		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		goto func_return;
	}
	jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+13);
	frame->type = JHD_HTTP2_FRAME_TYPE_WINDOW_UPDATE_FRAME;
	//IN X86   00 00 04 08 = uint32_t
	*((uint32_t*)frame->pos) =0x08040000;
	frame->pos[4] = 0;
	*((uint32_t*)(5+frame->pos)) =0;
	log_assert(event_h2c->recv.window_size < 2147483647);
	len = 2147483647 - event_h2c->recv.window_size;
	frame->pos[9] =  (u_char)(len >> 24);
	frame->pos[10] = (u_char)(len >> 16);
	frame->pos[11] = (u_char)(len >> 8);
	frame->pos[12] = (u_char)(len);
	jhd_http2_send_queue_frame(frame);
	ev->handler = event_h2c->recv.state_param;
	jhd_unshift_event(ev,&jhd_posted_events);

func_return:
	log_notice("<==%s",__FUNCTION__);
}
static void jhd_http2_data_frame_read(jhd_event_t *ev){
	jhd_http2_frame *frame;
	ssize_t rc;
	size_t len;

	log_notice("==>%s",__FUNCTION__);
	event_c = ev->data;
	event_h2c = event_c->data;
	frame = event_h2c->recv.state_param;
	if(ev->timedout){
		log_err("timeout");
		event_h2c->conf->connection_read_timeout(ev);
		jhd_free_with_size(frame->data,frame->data_len);
		jhd_free_with_size(frame,sizeof(jhd_http2_frame));
		goto func_return;
	}
	len = event_h2c->recv.payload_len -frame->len;
	log_assert(len >0);
	rc = event_c->recv(event_c,frame->pos,len);
	if(rc >0){
        if(len == (size_t)rc){
        	frame->pos-=frame->len;
        	frame->len = event_h2c->recv.payload_len;
        	if(frame->padded){
        		--frame->len ;
                if(frame->len < frame->pos[0]){
                	log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_DATA_PAYLOAD);
                	event_h2c->conf->connection_protocol_error(ev);
                	jhd_free_with_size(frame->data,frame->data_len);
                	jhd_free_with_size(frame,sizeof(jhd_http2_frame));
                }else {
                    frame->len -= frame->pos[0];
                    if(frame->len){
						++frame->pos;
						ev->handler = event_h2c->recv.stream->listener->remote_data;
						jhd_unshift_event(ev,&jhd_posted_events);
                    }else{
                    	if(frame->end_stream){
                    		ev->handler = event_h2c->recv.connection_frame_header_read;
                    		event_h2c->recv.stream->listener->remote_close(ev);
                    	}else{
                    		ev->handler = event_h2c->recv.stream->listener->remote_empty_data;
                    	}
                    	jhd_unshift_event(ev,&jhd_posted_events);
                    	jhd_free_with_size(frame->data,frame->data_len);
                    	jhd_free_with_size(frame,sizeof(jhd_http2_frame));
                    }
                }
			} else {
				ev->handler = event_h2c->recv.stream->listener->remote_data;
				jhd_unshift_event(ev, &jhd_posted_events);
			}
        }else{
        	 frame->len +=rc;
        	 frame->pos +=rc;
        }
	}else if(rc == JHD_AGAIN){
		 jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
	}else{
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
		event_h2c->conf->connection_read_error(ev);
		jhd_free_with_size(frame->data,frame->data_len);
		jhd_free_with_size(frame,sizeof(jhd_http2_frame));
	}
func_return:
	log_notice("<==%s",__FUNCTION__);
}


static void jhd_http2_data_frame_alloc_buffer(jhd_event_t *ev){
	jhd_http2_frame *frame;
	size_t len;

	log_notice("==>%s", __FUNCTION__);
	event_c = ev->data;
	event_h2c = event_c->data;
	frame = event_h2c->recv.state_param;
	if (ev->timedout) {
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_mem_time_out(ev);
		if(frame!= NULL){
			jhd_free_with_size(frame,sizeof(jhd_http2_frame));
		}
		goto func_return;
	}
	if(frame == NULL){
		event_h2c->recv.state_param =frame = jhd_alloc(sizeof(jhd_http2_frame));
		if(frame==NULL){
			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
			goto func_return;
		}
		frame->padded =(event_h2c->recv.frame_flag & JHD_HTTP2_PADDED_FLAG)?1:0;
		if(event_h2c->recv.frame_flag & JHD_HTTP2_END_STREAM_FLAG){
			frame->end_stream = 1;
			event_h2c->recv.stream->state |= JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE;
		}else{
			frame->end_stream = 0;
		}
		frame->free_func = jhd_http2_frame_free_by_direct;
	}
	len = event_h2c->recv.payload_len + 9;
	frame->data = jhd_alloc(len);
	if(frame->data == NULL){
		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		jhd_wait_mem(ev,len);
		goto func_return;
	}
	frame->data_len =len;
	frame->pos = frame->data +9;
	frame->len = 0;
	ev->handler = jhd_http2_data_frame_read;
	jhd_http2_data_frame_read(ev);

func_return:
	log_notice("<==%s", __FUNCTION__);
}

static void jhd_http2_send_connection_window_update_after_read_data(jhd_event_t *ev) {
	jhd_http2_frame *frame;
	uint32_t len;
	log_notice("==>%s", __FUNCTION__);
	event_c = ev->data;
	event_h2c = event_c->data;
	if (ev->timedout) {
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_mem_time_out(ev);
	} else {
		frame = jhd_alloc(sizeof(jhd_http2_frame) + 13);
		if (frame == NULL) {
			jhd_wait_mem(ev, sizeof(jhd_http2_frame) + 13);
			jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);

		} else {
			jhd_http2_single_frame_init(frame, sizeof(jhd_http2_frame) + 13);
			frame->type = JHD_HTTP2_FRAME_TYPE_WINDOW_UPDATE_FRAME;
			//IN X86   00 00 04 08 = uint32_t
			*((uint32_t*) frame->pos) = 0x08040000;
			frame->pos[4] = 0;
			*((uint32_t*) (5 + frame->pos)) = 0;
			log_assert(event_h2c->recv.window_size < 2147483647);
			len = 2147483647 - event_h2c->recv.window_size;
			frame->pos[9] = (u_char) (len >> 24);
			frame->pos[10] = (u_char) (len >> 16);
			frame->pos[11] = (u_char) (len >> 8);
			frame->pos[12] = (u_char) (len);
			jhd_http2_send_queue_frame(frame);
			event_h2c->recv.state_param = NULL;
			ev->handler = jhd_http2_data_frame_alloc_buffer;
			jhd_unshift_event(ev, &jhd_posted_events);
		}
	}
	log_notice("<==%s", __FUNCTION__);
}



void jhd_http2_data_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_notice("==>%s",__FUNCTION__);

	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif

	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if((stream_id & 0X80000001) != 1){
		log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_STREAM_ID);
		log_err("invalid stream id==>%u",stream_id);
		event_h2c->conf->connection_protocol_error(ev);
	}else{
		if(event_h2c->recv.payload_len>0){
			if(event_h2c->recv.payload_len > event_h2c->recv.window_size){
				log_http2_err(JHD_HTTP2_FLOW_CTRL_ERROR_CONNECTION);
				event_h2c->conf->connection_protocol_error(ev);
			}else{
				event_h2c->recv.window_size-=event_h2c->recv.payload_len;
				if(event_h2c->recv.stream->id != stream_id){
					event_h2c->recv.stream = jhd_http2_stream_get(event_h2c,stream_id);
					if(event_h2c->recv.stream == NULL){
						event_h2c->recv.stream = &jhd_http2_invalid_stream;
						event_h2c->recv.state  = event_h2c->recv.payload_len;
						if(event_h2c->recv.window_size < event_h2c->conf->recv_window_size_threshold){
							event_h2c->recv.state_param = jhd_http2_send_connection_window_update;
						}else{
							event_h2c->recv.state_param = event_h2c->recv.connection_frame_header_read;
						}
						ev->handler = jhd_http2_recv_skip;
						jhd_unshift_event(ev,&jhd_posted_events);
						goto func_return;
					}
				}

				if(((int)event_h2c->recv.payload_len) > event_h2c->recv.stream->recv_window_size){
					log_http2_err(JHD_HTTP2_FLOW_CTRL_ERROR_STREAM);
					ev->handler = jhd_http2_rest_stream_after_skip_data;
					jhd_http2_rest_stream_after_skip_data(ev);
				}else if(event_h2c->recv.stream->state & JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE){
					log_http2_err(JHD_HTTP2_STREAM_CLOSED);
					ev->handler = jhd_http2_rest_stream_after_skip_data;
					jhd_http2_rest_stream_after_skip_data(ev);
				}else{
					if(event_h2c->recv.window_size < event_h2c->conf->recv_window_size_threshold){
						ev->handler = jhd_http2_send_connection_window_update_after_read_data;
						jhd_http2_send_connection_window_update_after_read_data(ev);
					}else{
						ev->handler = jhd_http2_data_frame_alloc_buffer;
						event_h2c->recv.state_param = NULL;
						jhd_http2_data_frame_alloc_buffer(ev);
					}
				}
			}
		}else{
			if(event_h2c->recv.frame_flag & JHD_HTTP2_PADDED_FLAG){
				log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_DATA_PAYLOAD);
				event_h2c->conf->connection_protocol_error(ev);
			}if(event_h2c->recv.frame_flag & JHD_HTTP2_END_STREAM_FLAG){
				if(event_h2c->recv.stream->id != stream_id){
					event_h2c->recv.stream = jhd_http2_stream_get(event_h2c,stream_id);
					if(event_h2c->recv.stream == NULL){
						event_h2c->recv.stream= &jhd_http2_invalid_stream;
						ev->handler = event_h2c->recv.connection_frame_header_read;
						jhd_unshift_event(ev,&jhd_posted_events);
						goto func_return;
					}
				}
				if(event_h2c->recv.stream->state & JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE){
					ev->handler = jhd_http2_rest_stream_after_read_frame_header;
					jhd_http2_rest_stream_after_read_frame_header(ev);
				}else{
					event_h2c->recv.stream->state |= JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE;
					event_h2c->recv.stream->listener->remote_close(ev);
					ev->handler = event_h2c->recv.connection_frame_header_read;
					jhd_unshift_event(ev,&jhd_posted_events);
				}
			}else{
				ev->handler = event_h2c->recv.connection_frame_header_read;
				jhd_unshift_event(ev,&jhd_posted_events);
			}
		}
	}
	func_return:
	log_notice("<==%s",__FUNCTION__);
}








void jhd_http2_priority_frame_header_check(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len != 5){
		event_h2c->conf->connection_protocol_error(ev);
	}else{
		jhd_http2_do_recv_buffer(ev,event_h2c,event_h2c->recv.connection_frame_header_read);
	}

}
static void jhd_http2_rst_stream_frame_handler(jhd_event_t * ev){
	uint32_t errcode;
	jhd_http2_stream *stream;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	errcode = *((uint32_t*)event_h2c->recv.buffer);
	stream = event_h2c->recv.stream;
	event_h2c->recv.stream = &jhd_http2_invalid_stream;

	log_warn("stream[%u] reset by remote;errcode=%u",stream->id,errcode);

	stream->listener->reset(ev);
	jhd_queue_only_remove(&stream->queue);
	if(jhd_queue_queued(&stream->flow_control)){
		jhd_queue_only_remove(&stream->flow_control);
	}
	ev->handler = event_h2c->recv.connection_frame_header_read;
	jhd_unshift_event(ev,&jhd_posted_events);
	jhd_free_with_size(stream,sizeof(jhd_http2_stream));
}

void jhd_http2_rst_stream_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len != 4){
		event_h2c->conf->connection_protocol_error(ev);
	}else {
		JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
		if(event_h2c->recv.stream->id != stream_id){
			event_h2c->recv.stream = jhd_http2_stream_get(event_h2c,stream_id);
			if(event_h2c->recv.stream== NULL){
				event_h2c->recv.stream = &jhd_http2_invalid_stream;
				jhd_http2_do_recv_skip(ev,event_h2c,4,event_h2c->recv.connection_frame_header_read);
				return;
			}
		}
		jhd_http2_do_recv_buffer(ev,event_h2c,jhd_http2_rst_stream_frame_handler);
	}
}


static void jhd_http2_setting_resize_hpack(jhd_event_t *ev){
	uint16_t capacity;
	uint16_t size;
	uint64_t param;
	u_char *p;
	event_h2c = ((jhd_connection_t*)ev->data)->data;
	if(ev->timedout){
		log_err("timeout");
		event_h2c->conf->connection_read_timeout(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	param = ((uint64_t) event_h2c->recv.state_param);
	size = param;
	p = NULL;
	if(JHD_OK == jhd_http2_hpack_resize(&event_h2c->recv.hpack,size,&p,&capacity)){
		ev->handler = jhd_http2_setting_frame_handler;
		jhd_unshift_event(ev,&jhd_posted_events);
		if(p != NULL){
			jhd_free_with_size(p,capacity);
		}
	}
	log_assert_code(else{
		log_assert(1==2);
	})
}




static void jhd_http2_setting_frame_handler(jhd_event_t *ev){
	ssize_t rc;
	size_t len;
	uint32_t idx,val;
	uint16_t capacity;
	uint64_t  param;


	jhd_queue_t  *head,*q;
	jhd_http2_stream *stream;
	u_char *p;

	size_t i;
	event_c = ev->data;
	event_h2c = event_c->data;
	if(ev->timedout){
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
		event_h2c->conf->connection_read_timeout(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	if((event_h2c->recv.payload_len == 0)  ||(event_h2c->recv.payload_len == event_h2c->recv.state)){
		event_h2c->recv.state=0;
		ev->handler = jhd_http2_send_setting_frame_ack;
		jhd_http2_send_setting_frame_ack(ev);
		return;
	}
	log_assert(event_h2c->recv.state < event_h2c->recv.payload_len);
	for(;;){
		len = 6 -(event_h2c->recv.state % 6);
		rc = event_c->recv(event_c,event_h2c->recv.buffer  + 6 - len,len);
		if(rc > 0){
			event_h2c->recv.state += rc;
			if(((size_t)rc) == len){
				idx = (event_h2c->recv.buffer[0] << 8) | event_h2c->recv.buffer[1];

				val =  (event_h2c->recv.buffer[2] << 24) | (event_h2c->recv.buffer[3] << 16) | (event_h2c->recv.buffer[4] << 8) | event_h2c->recv.buffer[5];

				if(idx == 0x01){
					if(val >  0xFFFF){
						log_http2_err(JHD_HTTP2_ENHANCE_YOUR_CALM_HAPCK_TO_LAGER);
						event_h2c->conf->connection_unsupported_error(ev);
						return;
					}

					rc = jhd_http2_hpack_resize(&event_h2c->recv.hpack,(uint16_t)val,&p,&capacity);
					if(rc == JHD_OK){
						if(p != NULL){
							jhd_unshift_event(ev,&jhd_posted_events);
							jhd_free_with_size(p,capacity);
							return;
						}
					}else if(rc == JHD_AGAIN){
						param = val;
						event_h2c->recv.state_param = (void*)param;
						ev->handler = jhd_http2_setting_resize_hpack;
						jhd_wait_mem(ev,capacity);
						jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
						return;
					}else{
						log_http2_err(JHD_HTTP2_ENHANCE_YOUR_CALM_HAPCK_TO_LAGER);
						event_h2c->conf->connection_unsupported_error(ev);
						return;
					}
				}else if(idx == 0x02){
					//SETTINGS_ENABLE_PUSH
					//IGNORE
				}else if(idx == 0x03){
					//SETTINGS_MAX_CONCURRENT_STREAMS
					if(event_h2c->conf->server_side==0){
						if(val < event_h2c->max_streams){
							if(val == 0){
								log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_SERVER_NOT_ALLOCED_CREATE_STREAM);
								event_h2c->conf->connection_unsupported_error(ev);
								return;
							}
							event_h2c->max_streams = val;
						}else if(val > event_h2c->max_streams){
							 event_h2c->max_streams = val <= event_h2c->conf->max_streams?val:event_h2c->conf->max_streams;
						}
					}
				}else if(idx == 0x04){
					//SETTINGS_INITIAL_WINDOW_SIZE
					if(val > 65535){
						log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_INITAIL_WINDOW);
						event_h2c->conf->connection_protocol_error(ev);
						return;
					}
					for(head = event_h2c->streams,i=0; i < 32; ++i,++head){
						for(q=jhd_queue_next(head);q != head;q = q->next){
							stream = jhd_queue_data(q,jhd_http2_stream,queue);
							if((stream->state & JHD_HTTP2_STREAM_STATE_CLOSE_LOCAL)==0){
								rc = stream->send_window_size + val - event_h2c->send.initial_window_size;
								if(rc > 2147483647){
									event_h2c->recv.state = JHD_HTTP2_FLOW_CTRL_ERROR;
									event_h2c->conf->connection_protocol_error(ev);
									return;
								}
								if(stream->send_window_size <= 0){
									stream->send_window_size = rc;
									if(rc > 0){
										event_h2c->recv.stream = stream;
										stream->listener->send_window_change(ev);
									}
								}else{
									stream->send_window_size = rc;
								}
							}
						}
					}
					event_h2c->send.initial_window_size = val;
				}else if(idx == 0x05){
					//SETTINGS_MAX_FRAME_SIZE (0x5)
					//IGNORE  impl val == 16384
				}else if(idx == 0x06){
					//SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
					//IGNORE
				}
				if(event_h2c->recv.state == event_h2c->recv.payload_len){
					event_h2c->recv.state = 0;
					event_h2c->recv.state_param = NULL;
					ev->handler = jhd_http2_send_setting_frame_ack;
					jhd_http2_send_setting_frame_ack(ev);
					return;
				}
			}else{
				jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
				return;
			}
		}else if(rc == JHD_AGAIN){
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
			return;
		}else{

			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
			event_h2c->conf->connection_read_error(ev);
			return;
		}
	}
}





static void jhd_http2_update_recv_window(jhd_event_t *ev) {
	jhd_queue_t *head, *q;
	jhd_http2_stream *stream;
	jhd_http2_frame *frame;
	uint32_t window_update_val;
	u_char *p;
	int i;

	frame = NULL;
	event_h2c = ((jhd_connection_t*) ev->data)->data;
	if (ev->timedout) {
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_mem_time_out(ev);
	} else {
		event_h2c->recv.state = 0;
		for (head = event_h2c->streams, i = 0; i < 32; ++i, ++head) {
			for (q = jhd_queue_next(head); q != head; q = q->next) {
				stream = jhd_queue_data(q, jhd_http2_stream, queue);
				if (((stream->state & JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE) == 0) && (stream->recv_window_size <= 0)) {

					event_h2c->recv.stream = stream;
					stream->listener->recv_window_change(ev);
					log_assert(event_h2c->recv.state < 2147483647);
					window_update_val = event_h2c->recv.state - stream->recv_window_size;
					frame = jhd_alloc(sizeof(jhd_http2_frame) + 13);
					if (frame == NULL) {
						jhd_event_add_timer(ev, event_h2c->conf->wait_mem_timeout);
						jhd_wait_mem(ev, sizeof(jhd_http2_frame) + 13);
						return;
					}
					jhd_http2_single_frame_init(frame, sizeof(jhd_http2_frame) + 13);
					frame->type = JHD_HTTP2_FRAME_TYPE_WINDOW_UPDATE_FRAME;
					p = frame->pos;
					//IN X86   00 00 04 08 = uint32_t
					*((uint32_t*) p) = 0x08040000;
					p[4] = 0;
					p += 5;
					jhd_http2_set_stream_id(p, stream->id);
					frame->pos[9] = (u_char) (window_update_val >> 24);
					frame->pos[10] = (u_char) (window_update_val >> 16);
					frame->pos[11] = (u_char) (window_update_val >> 8);
					frame->pos[12] = (u_char) (window_update_val);
					jhd_http2_send_queue_frame(frame);
					stream->recv_window_size = event_h2c->recv.state;
				}
			}
		}
		ev->handler = event_h2c->conf->connection_after_setting_ack;
		jhd_unshift_event(ev, &jhd_posted_events);
	}
	log_notice("<==%s with timedout", __FUNCTION__);
}






void jhd_http2_setting_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	jhd_queue_t  *head,*q;
	jhd_http2_stream *stream;
	int i;

	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif


	JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
	if(stream_id != 0){
		event_h2c->conf->connection_protocol_error(ev);
	}else if(event_h2c->recv.payload_len % 6 != 0){
		event_h2c->conf->connection_protocol_error(ev);
	}else if(event_h2c->recv.payload_len){
		if(event_h2c->recv.frame_flag & JHD_HTTP2_ACK_FLAG){
			event_h2c->conf->connection_protocol_error(ev);
		}else{
			ev->handler = jhd_http2_setting_frame_handler;
			jhd_http2_setting_frame_handler(ev);
		}
	}else{
		//only once recv  setting ack,
		log_assert(event_h2c->recv.init_window_size == 65535);

		event_h2c->recv.state = 0;
		if(event_h2c->recv.frame_flag & JHD_HTTP2_ACK_FLAG){
			event_h2c->recv.init_window_size = 16384;
			for(head = event_h2c->streams,i=0; i < 32; ++i,++head){
				for(q=jhd_queue_next(head);q != head;q = q->next){
					stream = jhd_queue_data(q,jhd_http2_stream,queue);
					if((stream->state & JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE)==0){
						stream->recv_window_size -=(65535 - 16384);
						if(stream->recv_window_size <= 0){
							event_h2c->recv.state++;
						}
					}
				}
			}
			if(event_h2c->recv.state>0){
				event_h2c->recv.state=0;
				ev->handler = jhd_http2_update_recv_window;
				jhd_http2_update_recv_window(ev);
			}else{
				ev->handler = event_h2c->conf->connection_after_setting_ack;
				jhd_unshift_event(ev,&jhd_posted_events);
			}
		}else{
			ev->handler = jhd_http2_send_setting_frame_ack;
			jhd_http2_send_setting_frame_ack(ev);
		}
	}
}
static void jhd_http2_ping_frame_handler(jhd_event_t *ev) {
	jhd_http2_frame *frame;
	ssize_t rc;
	u_char *p;
	event_c = ev->data;
	event_h2c = event_c->data;
	frame = event_h2c->recv.state_param;
	if (ev->timedout) {
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
		event_h2c->conf->connection_read_timeout(ev);
		jhd_free_with_size(frame, sizeof(jhd_http2_frame) + 17);

	} else {
		log_assert(event_h2c->recv.state < 8);
		rc = event_c->recv(event_c, frame->pos +9 + event_h2c->recv.state, 8 - event_h2c->recv.state);
		if (rc > 0) {
			event_h2c->recv.state += rc;
			if (event_h2c->recv.state == 8) {
				p = frame->pos;
				*((uint32_t*)p) = 0x06080000;
				p[4] = 0x01; //ack
				p+=5;
				*((uint32_t*)p) = 0x0;
				frame->type = JHD_HTTP2_FRAME_TYPE_PING_FRAME;
				frame->ack = 1;
				jhd_http2_send_ping_ack(frame);
				event_h2c->recv.state = 0;
				ev->handler = event_h2c->recv.connection_frame_header_read;
				jhd_unshift_event(ev, &jhd_posted_events);
			} else {
				jhd_event_add_timer(ev, event_h2c->conf->read_timeout);
			}
		} else if (rc == JHD_AGAIN) {
			jhd_event_add_timer(ev, event_h2c->conf->read_timeout);
		} else {

			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
			event_h2c->conf->connection_read_error(ev);
		}
	}

	log_notice("<==%s", __FUNCTION__);

}
void jhd_http2_ping_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	if(ev->timedout){
			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
			event_h2c->conf->connection_mem_time_out(ev);

	}else{
		if(event_h2c->recv.payload_len != 8){
			log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_PING_PAYLOAD);
			event_h2c->conf->connection_protocol_error(ev);
		}else{
			JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
			if(stream_id != 0){
				event_h2c->conf->connection_protocol_error(ev);
			}else{
				frame = jhd_alloc(sizeof(jhd_http2_frame)+17);
				if(frame == NULL){
					jhd_wait_mem(ev,sizeof(jhd_http2_frame)+17);
					jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
				}
				jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+17);
				frame->type = JHD_HTTP2_FRAME_TYPE_PING_FRAME;
				frame->ack = 1;
				event_h2c->recv.state = 0;
				event_h2c->recv.state_param = frame;
				ev->handler = jhd_http2_ping_frame_handler;
				jhd_http2_ping_frame_handler(ev);
			}
		}
	}
	log_notice("<==%s",__FUNCTION__);
}

static void jhd_http2_window_update_frame_handler(jhd_event_t *ev) {
	ssize_t rc;
	uint32_t window_size;
	u_char *p;
	jhd_queue_t *head, *q;
	jhd_http2_stream *stream;
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;
	if (ev->timedout == 1) {
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
		event_h2c->conf->connection_read_timeout(ev);
	} else {
		rc = event_c->recv(event_c, event_h2c->recv.buffer + event_h2c->recv.state, 4 - event_h2c->recv.state);
		if (rc > 0) {
			event_h2c->recv.state += rc;
			if (event_h2c->recv.state == 4) {
				event_h2c->recv.state = 0;
				p = event_h2c->recv.buffer;
				window_size = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3]);
				if (window_size == 0 || window_size > 2147483647) {
					log_http2_err(JHD_HTTP2_FLOW_CTRL_ERROR_UPDATE_VALUE);
					event_h2c->conf->connection_protocol_error(ev);
					return;
				}
				if (event_h2c->recv.stream == ((void*) (0xFFFFFFFFFFFFFFFFULL))) {
					event_h2c->recv.stream = &jhd_http2_invalid_stream;
					rc = event_h2c->send.window_size + window_size;
					if (rc > 2147483647) {
						log_http2_err(JHD_HTTP2_FLOW_CTRL_ERROR_CONNECTION);
						event_h2c->conf->connection_protocol_error(ev);
					} else if (event_h2c->send.window_size) {
						event_h2c->send.window_size = rc;
					} else {
						event_h2c->send.window_size = rc;
						head = &event_h2c->flow_control;

						while (jhd_queue_has_item(head)) {
							q = head->next;
							jhd_queue_remove(q);
							stream = jhd_queue_data(q, jhd_http2_stream, flow_control);
							event_h2c->recv.stream = stream;
							stream->listener->remote_recv(ev);
							if (event_h2c->send.window_size == 0) {
								break;
							}
						}
					}
				} else if (event_h2c->recv.stream != &jhd_http2_invalid_stream) {
					rc = event_h2c->recv.stream->send_window_size + window_size;
					if (rc > 2147483647) {
						log_http2_err(JHD_HTTP2_FLOW_CTRL_ERROR_STREAM);
						event_h2c->conf->connection_protocol_error(ev);
					} else if (event_h2c->recv.stream->send_window_size < 1) {
						event_h2c->recv.stream->send_window_size = rc;
						if (rc > 0) {
							event_h2c->recv.stream->listener->remote_recv(ev);
						}
					} else {
						event_h2c->recv.stream->send_window_size = rc;
					}
				} else {
					ev->handler = event_h2c->recv.connection_frame_header_read;
					jhd_unshift_event(ev, &jhd_posted_events);
				}
			} else {
				jhd_event_add_timer(ev, event_h2c->conf->read_timeout);
			}
		} else if (rc == JHD_AGAIN) {
			jhd_event_add_timer(ev, event_h2c->conf->read_timeout);
		} else {

			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
			event_h2c->conf->connection_read_error(ev);
		}
	}
}


void jhd_http2_window_update_frame_header_check(jhd_event_t *ev){
	uint32_t stream_id;
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);

#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len != 4){
		log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_WINDOW_UPDATE_PAYLOAD);
		event_h2c->conf->connection_protocol_error(ev);
	}else{
		JHD_HTTP2_SET_STRAM_ID_IN_CHECK(stream_id);
		if(stream_id  == 0){
			event_h2c->recv.stream = (void*)(0xFFFFFFFFFFFFFFFFULL);
		}else{
			if(event_h2c->recv.stream->id != stream_id){
				event_h2c->recv.stream = jhd_http2_stream_get(event_h2c,stream_id);
				if(event_h2c->recv.stream == NULL){
					event_h2c->recv.stream = &jhd_http2_invalid_stream;
				}
			}
		}
		event_h2c->recv.state = 0;
		ev->handler = jhd_http2_window_update_frame_handler;
		jhd_http2_window_update_frame_handler(ev);
	}
}








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

void jhd_http2_frame_header_read(jhd_event_t *ev){
	ssize_t ret;
	ssize_t len;
	u_char frame_type;
	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	if(ev->timedout){
		log_http2_err(JHD_HTTP2_ENHANCE_YOUR_CALM_READ_FRAME_HEADER);
		log_err("timeout");
		event_h2c->conf->connection_read_timeout(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}

	len = 9 - event_h2c->recv.state;

	log_assert(len > 0);

	ret = event_c->recv(event_c,event_h2c->recv.buffer+ event_h2c->recv.state,len);
	if(ret >0){
		if(ret == len){
			event_h2c->recv.payload_len = (event_h2c->recv.buffer[0] << 16) | (event_h2c->recv.buffer[1] << 8) | (event_h2c->recv.buffer[2]);
			if(event_h2c->recv.payload_len> 16384){
				log_http2_err(JHD_HTTP2_FRAME_MAX_SIZE_ERROR);
				log_err("invalid frame payload length[%u]",event_h2c->recv.payload_len);
				event_h2c->conf->connection_protocol_error(ev);
				log_notice("<==%s with timedout",__FUNCTION__);
				return;
			}
			frame_type= event_h2c->recv.buffer[3];
			if(event_h2c->recv.frame_type > JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME){

				log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_FRAME_TYPE);
				log_err("invalid frame type[0X%02X]",frame_type);
				event_h2c->conf->connection_protocol_error(ev);
				log_notice("<==%s with timedout",__FUNCTION__);
				return;
			}
			event_h2c->recv.frame_flag = event_h2c->recv.buffer[4];
			event_h2c->recv.state = 0;
			ev->handler=event_h2c->conf->frame_payload_handler_pts[frame_type];
			ev->handler(ev);
			log_notice("<==%s with timedout",__FUNCTION__);
		}else{
			event_h2c->recv.state +=ret;
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
			log_notice("<==%s EAGAIN",__FUNCTION__);
		}
	}else if(ret == JHD_AGAIN){
		if(event_h2c->recv.state==0){
			if(event_h2c->processing ==0){
				event_h2c->conf->connection_idle(ev);
				log_notice("<==%s IDLE",__FUNCTION__);
			}else{
				if(ev->timer.key){
					jhd_event_del_timer(ev);
				}
				log_notice("<==%s ",__FUNCTION__);
			}
		}else{
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
			log_notice("<==%s EAGAIN",__FUNCTION__);
		}

	}else{
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
		event_h2c->conf->connection_read_error(ev);
		log_notice("<==%s error",__FUNCTION__);
	}
}



void jhd_http2_send_setting_frame(jhd_event_t *ev){
	u_char *p;
	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	if(ev->timedout){
		log_err("timeout");
		event_h2c->recv.state_param = NULL;
		event_h2c->conf->connection_read_timeout(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	frame = jhd_alloc(sizeof(jhd_http2_frame)+9+18);
	if(frame == NULL){
		jhd_wait_mem(ev,sizeof(jhd_http2_frame)+9+18);
		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		return;
	}
	jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+9+18);
    frame->type = JHD_HTTP2_FRAME_TYPE_SETTINGS_FRAME;
    p = frame->pos;
    //000018  len  type 04
    *((uint32_t*)p) = 0x04120000;
    p[4] = 0;
    p+=5;
    *((uint32_t*)p) = 0;
	p+=4;
	//SETTINGS_ENABLE_PUSH (0x2)
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
	ev->handler = event_h2c->recv.connection_frame_header_read;
	jhd_unshift_event(ev,&jhd_posted_events);
}
void jhd_http2_send_setting_frame_ack(jhd_event_t *ev){
	jhd_http2_frame *frame;
	u_char *p;
	event_c = ev->data;
	event_h2c = event_c->data;

	if(ev->timedout){
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_mem_time_out(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	frame = jhd_alloc(sizeof(jhd_http2_frame)+9);
	if(frame == NULL){
		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		jhd_wait_mem(ev,sizeof(jhd_http2_frame)+9);
	}else{
		jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+9);

		frame->type = JHD_HTTP2_FRAME_TYPE_SETTINGS_FRAME;
		frame->ack = 1;
		p = frame->pos;

		//000000  len  type 04
		*((uint32_t*)p) = 0x04000000;
		p[4] = 0x01;//ack
		p+=5;
		*((uint32_t*)p) = 0;
		jhd_http2_send_queue_frame(frame);
		ev->handler = event_h2c->recv.connection_frame_header_read;
		jhd_unshift_event(ev,&jhd_posted_events);
	}
}
//void jhd_http2_send_ping_frame(jhd_event_t *ev){
//
//	jhd_http2_frame *frame;
//	event_c = ev->data;
//	event_h2c = event_c->data;
//	u_char *p;
//	frame = event_h2c->recv.state_param;
//
//	if((ev)->timedout){
//		log_err("timeout");
//		event_h2c->recv.state_param = NULL;
//		event_h2c->conf->connection_read_timeout(ev);
//		if(frame){
//			 log_assert(frame->tag =jhd_http2_send_ping_frame);
//             jhd_http2_frame_free_by_direct(frame);
//		}
//		log_notice("<==%s with timedout",__FUNCTION__);
//		return;
//	}
//	if(frame == NULL){
//		frame = jhd_alloc(sizeof(jhd_http2_frame));
//		if(frame == NULL){
//			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
//			JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
//			return;
//		}
//		memset(frame,0,sizeof(jhd_http2_frame));
//		frame->free_func = jhd_http2_frame_free_by_direct;
//		log_assert_code(frame->tag = jhd_http2_send_ping_frame;)
//	}
//
//	p = frame->data = jhd_alloc(9 + 8);
//	if(frame->data == NULL){
//		event_h2c->recv.state_param = frame;
//		jhd_wait_mem(ev,9 + 8);
//		JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
//		return;
//	}
//	event_h2c->recv.state_param = NULL;
//
//
//	frame->data_len = 8 + 9;
//	frame->len = 8 + 9 ;
//    frame->pos = frame->data;
//    frame->type = JHD_HTTP2_FRAME_TYPE_PING_FRAME;
//
//    //000018  len  type 04
//    *((uint32_t*)p) = 0x06080000;
//    p[4] = 0;
//    p+=5;
//    *((uint32_t*)p) = 0;
//	p+=4;
//	*((uint64_t*)p) = jhd_current_msec;
//	jhd_http2_send_queue_frame(frame);
//	ev->handler = event_h2c->recv.connection_frame_header_read;
//	jhd_unshift_event(ev,&jhd_posted_events);
//}

//void jhd_http2_send_ping_frame_ack(jhd_event_t *ev){
//	jhd_http2_frame *frame;
//	uint32_t len;
//	event_c = ev->data;
//	event_h2c = event_c->data;
//
//	event_c = ev->data;
//	event_h2c = event_c->data;
//	u_char *p;
//
//	frame = event_h2c->recv.state_param;
//
//	if(ev->timedout){
//		log_err("timeout");
//		event_h2c->recv.state_param = NULL;
//		event_h2c->conf->connection_read_timeout(ev);
//		if(frame){
//			 log_assert(frame->tag =jhd_http2_send_ping_frame_ack);
//             jhd_http2_frame_free_by_direct(frame);
//		}
//		log_notice("<==%s with timedout",__FUNCTION__);
//		return;
//	}
//	if(frame == NULL){
//		frame = jhd_alloc(sizeof(jhd_http2_frame));
//		if(frame == NULL){
//			jhd_wait_mem(ev,sizeof(jhd_http2_frame));
//			JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
//			return;
//		}
//		memset(frame,0,sizeof(jhd_http2_frame));
//		frame->free_func = jhd_http2_frame_free_by_direct;
//		log_assert_code(frame->tag = jhd_http2_send_ping_frame_ack;)
//	}
//
//	p = frame->data = jhd_alloc(9 + 8);
//	if(frame->data == NULL){
//		event_h2c->recv.state_param = frame;
//		jhd_wait_mem(ev,9 + 8);
//		JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev);
//		return;
//	}
//	event_h2c->recv->state_param = NULL;
//
//
//	frame->data_len = 8 + 9;
//	frame->len = 8 + 9 ;
//    frame->pos = frame->data;
//    frame->type = JHD_HTTP2_FRAME_TYPE_PING_FRAME;
//
//    //000018  len  type 04
//    *((uint32_t*)p) = 0x06080000;
//    p[4] = 0x01; //ack
//    p+=5;
//    *((uint32_t*)p) = 0;
//	p+=4;
//	*((uint64_t*)p) = *((uint64_t*)event_h2c->recv.buffer);
//	jhd_http2_send_ping_ack(frame);
//	ev->handler = event_h2c->recv.connection_frame_header_read;
//	jhd_unshift_event(ev,&jhd_posted_events);
//}




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
		if(ev->timedout){
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

jhd_http2_stream jhd_http2_invalid_stream={
				NULL,//jhd_http2_stream_listener *listener;
				NULL,//void *lis_ctx;
				0,//uint32_t id;
				JHD_HTTP2_STREAM_STATE_CLOSE_BOTH, //u_char state;
				0,//int recv_window_size;
				0,//int send_window_size;
				{NULL,NULL},//jhd_queue_t queue;
				{NULL,NULL},//jhd_queue_t wait_flow_control;
				};
