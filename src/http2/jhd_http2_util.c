#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_time.h>


 void jhd_http2_frame_free_by_direct(void *data){
	jhd_http2_frame *frame = data;
	log_assert(data != NULL);
	log_assert(frame->free_func == jhd_http2_frame_free_by_direct  );
	if(frame->data != NULL){
		jhd_free_with_size(frame->data,frame->data_len);
	}
	jhd_free_with_size(frame,sizeof(jhd_http2_frame));
}

 void jhd_http2_frame_free_by_single(void *data){
	 jhd_http2_frame *frame = data;
	 log_assert(data != NULL);
	 log_assert(frame->free_func == jhd_http2_frame_free_by_single);
	 jhd_free_with_size(frame,frame->data_len);
 }
 void jhd_http2_recv_skip(jhd_event_t *ev){
 	ssize_t rc;
 	log_notice("==>%s",__FUNCTION__);
 	log_assert_worker();
 	event_c = ev->data;
 	event_h2c = event_c->data;
 	log_assert(event_h2c->recv.state_param != NULL);

 	if(ev->timedout){
 		ev->timedout = 0;
 		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
 		event_h2c->conf->connection_read_timeout(ev);
 		log_notice("<==%s",__FUNCTION__);
 		return;
 	}
 	log_assert(event_h2c->recv.state >0);
	rc = event_c->recv(event_c,jhd_calc_buffer,event_h2c->recv.state);
	if(rc > 0){
		event_h2c->recv.state-=rc;
		if(((size_t)rc) == event_h2c->recv.state){
			event_h2c->recv.state = 0;
			ev->handler = event_h2c->recv.state_param;
			ev->handler(ev);
		}else{
			event_h2c->recv.state-=rc;
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
		}
	}else if (rc == JHD_AGAIN){
		jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
	}else{
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
		event_h2c->conf->connection_read_error(ev);
	}
 	log_notice("<==%s",__FUNCTION__);
 }

 void jhd_http2_recv_payload(jhd_event_t *ev){
 	ssize_t rc;
 	size_t len;
 	u_char *p;

 	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	p = event_h2c->recv.alloc_buffer[0];
	len = event_h2c->recv.payload_len;

	if(ev->timedout){
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
		event_h2c->conf->connection_read_timeout(ev);
		jhd_free_with(p,len);
		goto func_return;
	}

 	p += event_h2c->recv.state;

 	len = event_h2c->recv.payload_len - event_h2c->recv.state;

 	log_assert(len >0);

 	rc = event_c->recv(event_c,p,len);
 	if(rc > 0){
 		if(((size_t)rc) == len){
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
 		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
 		event_h2c->conf->connection_read_error(ev);
 		jhd_free_with_size(p,len);
 	}
 func_return:
 	 log_notice("<==%s",__FUNCTION__);

 }

 void jhd_http2_recv_buffer(jhd_event_t *ev){
 	ssize_t rc;
 	size_t len;
 	log_assert_worker();
 	event_c = ev->data;
 	event_h2c = event_c->data;

 	if(ev->timedout){
 		ev->timedout = 0;
 		log_err("timeout");
 		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
 		event_h2c->conf->connection_read_timeout(ev);
 	}else{
		len = event_h2c->recv.payload_len - event_h2c->recv.state;
		log_assert(len >0 && len < sizeof(event_h2c->recv.buffer));
		rc = event_c->recv(event_c,event_h2c->recv.buffer+event_h2c->recv.state,len);
		if(rc > 0){
			if(((size_t)rc) == len){
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
			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
			event_h2c->conf->connection_read_error(ev);
		}
 	}
 }


 void jhd_http2_goaway_payload_recv(jhd_event_t *ev) {
	ssize_t rc;
	size_t len;
	u_char *p;

	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	if (ev->timedout) {
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
		event_h2c->conf->connection_read_timeout(ev);
	} else {
		len = event_h2c->recv.payload_len - event_h2c->recv.state;
		log_assert(len > 0);
		rc = event_c->recv(event_c, jhd_calc_buffer, len);
		if (rc > 0) {
			if (((size_t) rc) == len) {
				if (event_h2c->recv.state < 8) {
					p = event_h2c->recv.buffer + event_h2c->recv.state;
					memcpy(p, jhd_calc_buffer, 8 - event_h2c->recv.state);
				}
				event_h2c->recv.state = 0;
				ev->handler = event_h2c->recv.state_param;
				ev->handler(ev);
			} else {
				if (event_h2c->recv.state < 8) {
					p = event_h2c->recv.buffer + event_h2c->recv.state;
					len = 8 - event_h2c->recv.state;
					if (len > rc) {
						len = (size_t) rc;
					}
					memcpy(p, jhd_calc_buffer, len);
				}
				event_h2c->recv.state += (size_t) rc;
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





 //TODO impl
// void jhd_http2_buffering_stream_recv_window_change(jhd_event_t *ev){
//	 log_assert(event_c == ev->data);
//	 log_assert(event_h2c == event_c->data);
//	 jhd_http2_stream *stream = event_h2c->recv.stream;
//
//	 event_h2c->recv.state = 2147483647;//maybe  a suitable value
//
//
//
// }

 //TODO impl
// void jhd_http2_nobuffering_stream_recv_window_change(jhd_event_t *ev){
//
//	 log_assert(event_c == ev->data);
//	 log_assert(event_h2c == event_c->data);
//	 jhd_http2_stream *stream = event_h2c->recv.stream;
//
//	 //waiting writed to (proxy remote  or  local dis)
//	 event_h2c->recv.state = 0;//maybe  a suitable value
//
//	 //or waiting read from remote
//
//	 event_h2c->recv.state = 16384;//maybe a suiable value (one buffer)
//
// }
