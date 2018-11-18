#include <http2/jhd_http2.h>

void jhd_http2_frame_header_read(jhd_event_t *ev){
	ssize_t ret;
	ssize_t len;
	u_char frame_type;
	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

#ifdef JHD_LOG_ASSERT_ENABLE
		if(event_h2c->first_frame_header_read == 0){
			log_assert(event_h2c->recv.state == 0);
			event_h2c->first_frame_header_read = 1;
		}
#endif
		len = 9 - event_h2c->recv.state;
		log_assert(len > 0);
		ret = event_c->recv(event_c,event_h2c->recv.buffer + event_h2c->recv.state,len);
		if(ret > 0){
			if(ret == len){
				event_h2c->recv.payload_len = (event_h2c->recv.buffer[0] << 16) | (event_h2c->recv.buffer[1] << 8) | (event_h2c->recv.buffer[2]);
				if(event_h2c->recv.payload_len > 16384){
					log_http2_err(JHD_HTTP2_FRAME_MAX_SIZE_ERROR);
					log_err("invalid frame payload length[%u]",event_h2c->recv.payload_len);
					event_h2c->conf->connection_read_error(ev);
					log_notice("<==%s with timedout",__FUNCTION__);
					return;
				}
				frame_type = event_h2c->recv.buffer[3];
				if(event_h2c->recv.frame_type > JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME){

					log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_FRAME_TYPE);
					log_err("invalid frame type[0X%02X]",frame_type);
					event_h2c->conf->connection_read_error(ev);
					log_notice("<==%s with timedout",__FUNCTION__);
					return;
				}
#ifdef JHD_LOG_ASSERT_ENABLE
				event_h2c->first_frame_header_read = 0;
#endif
				event_h2c->recv.frame_flag = event_h2c->recv.buffer[4];
				JHD_HTTP2_SET_STRAM_ID_IN_CHECK(event_h2c->recv.sid);
				event_h2c->recv.state = 0;
				ev->handler = event_h2c->conf->frame_payload_handler_pts[frame_type];
				ev->handler(ev);
				log_notice("<==%s with timedout",__FUNCTION__);
			}else{
				event_h2c->recv.state += ret;
				jhd_event_add_timer(ev,event_h2c->conf->read_timeout,jhd_http2_common_read_timeout);
				log_notice("<==%s EAGAIN",__FUNCTION__);
			}
		}else if(ret == JHD_AGAIN){
			if(event_h2c->recv.state == 0){
				if(event_h2c->processing == 0){
					event_h2c->conf->connection_idle(ev);
					log_notice("<==%s IDLE",__FUNCTION__);
				}else{
					if(ev->timer.key){
						jhd_event_del_timer(ev);
					}
					log_notice("<==%s ",__FUNCTION__);
				}
			}else{
				jhd_event_add_timer(ev,event_h2c->conf->read_timeout,jhd_http2_common_read_timeout);
				log_notice("<==%s EAGAIN",__FUNCTION__);
			}
		}else{
			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
			event_h2c->conf->connection_read_error(ev);
			log_notice("<==%s error",__FUNCTION__);
		}

}
