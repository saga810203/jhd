#include <http2/jhd_http2_server.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_queue.h>
#include <jhd_core.h>
#include <tls/jhd_tls_ssl_internal.h>

void jhd_http2_server_connection_read_event_error_with_clean_force(jhd_event_t *ev){
	jhd_connection_t *c = ev->data;
	jhd_http2_connection_free(ev);
	c->close(c);
}


static void server_send_goaway_with_read_error(jhd_event_t *ev){
	jhd_http2_frame *frame;
    u_char *p;
	event_c = ev->data;
	event_h2c = event_c->data;
	log_assert(event_h2c->goaway_sent =0);

	frame = jhd_alloc(sizeof(jhd_http2_frame)+ 17);
	if(frame != NULL){
		jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+17);
		frame->type = JHD_HTTP2_FRAME_TYPE_GOAWAY_FRAME;
		p = frame->pos;
		*((uint32_t*)p) = 0x07080000;
		p[4] = 0;
		p += 5;
		*((uint32_t*)p) = 0x0;
		p += 4;
		jhd_http2_set_stream_id(p,event_h2c->recv.last_stream_id);
		p += 4;
		*((uint32_t*)p) = event_h2c->recv.state;
		jhd_http2_send_queue_frame(event_c,event_h2c,frame);
		event_h2c->goaway_sent = 1;
		ev->handler = event_h2c->recv.state_param;
		ev->handler(ev);
	}else{
		jhd_wait_mem(ev,sizeof(jhd_http2_frame)+17);
		jhd_event_add_timer(ev,0xFFFFFFFFFFFFFFFFULL,jhd_http2_server_connection_read_event_error_with_clean_force);
	}
}




static void server_ssl_connection_cleanup_with_timer(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_tls_ssl_context *ssl;

	jhd_queue_init(&free_queue);

	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  || jhd_quit || (h2c->recv.state >1024000/*// 1000  2000  4000 8000  16000 32000 64000 128000 256000  512000  1024000*/) ){
		jhd_http2_connection_free(ev);
		c->close(c);
		return;
	}
	if(h2c->processing){
		head = &h2c->flow_control;
		while(jhd_queue_has_item(head)){
			q = jhd_queue_next(head);
			stream = jhd_queue_data(q,jhd_http2_stream,flow_control);

			jhd_queue_only_remove(&stream->queue);
			jhd_queue_only_remove(q);
			jhd_queue_insert_tail(&free_queue,&stream->queue);
			--h2c->processing;

			h2c->recv.stream = stream;
			stream->listener->reset(ev);
			h2c->recv.stream = &jhd_http2_invalid_stream;
		}
	}
	ssl = c->ssl;
	if((h2c->processing) || (h2c->send.head != NULL) || (ssl->out_msglen) ){
		h2c->recv.state *=2;
		jhd_event_add_timer(ev,h2c->recv.state,server_ssl_connection_cleanup_with_timer);
		goto func_free;
	}
	jhd_http2_connection_free(ev);
	c->close(c);
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}

static void server_check_quit_and_send_error_with_timer_clean(jhd_event_t *ev){
	event_c  =  ev->data;
	event_h2c =  event_c->data;
	if(event_h2c->send_error  | jhd_quit){
		if(ev->timer.key){
			jhd_event_del_timer(ev);
		}
		server_ssl_connection_cleanup_with_timer(ev);
	}
}

static void server_ssl_connection_read_event_error_with_timer_clean_after_goaway_sent(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	int i;
	jhd_queue_init(&free_queue);



	ev->handler = server_check_quit_and_send_error_with_timer_clean;

	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  | jhd_quit){
		jhd_http2_connection_free(ev);
		c->close(c);
		return;
	}
	if(h2c->processing){
		head = &h2c->flow_control;
		while(jhd_queue_has_item(head)){
			q = jhd_queue_next(head);
			stream = jhd_queue_data(q,jhd_http2_stream,flow_control);

			jhd_queue_only_remove(q);
			jhd_queue_only_remove(&stream->queue);
			jhd_queue_insert_tail(&free_queue,&stream->queue);
			--h2c->processing;

			h2c->recv.stream = stream;
			stream->listener->reset(ev);
			h2c->recv.stream = &jhd_http2_invalid_stream;
		}
		if(h2c->processing){
			for(i = 0, head = h2c->streams; ((i < 32) && (h2c->processing)) ; ++i,++head){
				for(q = jhd_queue_next(head); q!= head;){
					stream = jhd_queue_data(q,jhd_http2_stream,queue);
					q = jhd_queue_next(q);
					if((stream->in_close==0)){
						jhd_queue_only_remove(&stream->flow_control);
						jhd_queue_only_remove(&stream->queue);
						jhd_queue_insert_tail(&free_queue,&stream->queue);
						--h2c->processing;

						h2c->recv.stream = stream;
						stream->listener->reset(ev);
						h2c->recv.stream = &jhd_http2_invalid_stream;
					}
				}
			}
		}
	}
	if(h2c->processing || (h2c->send.head != NULL) || (((jhd_tls_ssl_context*)(c->ssl))->out_msglen)){
		h2c->recv.state = 1000;
		jhd_event_add_timer(ev,h2c->recv.state,server_ssl_connection_cleanup_with_timer);
		goto func_free;
	}
	jhd_http2_connection_free(ev);
	c->close(c);
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}

static void server_send_goaway_with_read_error_by_timer_clean(jhd_event_t *ev){
	jhd_http2_frame *frame;
    u_char *p;
	event_c = ev->data;
	event_h2c = event_c->data;
	log_assert(event_h2c->goaway_sent =0);

	frame = jhd_alloc(sizeof(jhd_http2_frame)+ 17);
	if(frame != NULL){
		jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+17);
		frame->type = JHD_HTTP2_FRAME_TYPE_GOAWAY_FRAME;
		p = frame->pos;
		*((uint32_t*)p) = 0x07080000;
		p[4] = 0;
		p += 5;
		*((uint32_t*)p) = 0x0;
		p += 4;
		jhd_http2_set_stream_id(p,event_h2c->recv.last_stream_id);
		p += 4;
		*((uint32_t*)p) = event_h2c->recv.state;
		jhd_http2_send_queue_frame(event_c,event_h2c,frame);
		event_h2c->goaway_sent = 1;
		event_h2c->recv.state = 500;
		ev->handler = server_ssl_connection_read_event_error_with_timer_clean_after_goaway_sent;
		ev->handler(ev);
	}else{
		jhd_wait_mem(ev,sizeof(jhd_http2_frame)+17);
		jhd_event_add_timer(ev,0xFFFFFFFFFFFFFFFFULL,jhd_http2_server_connection_read_event_error_with_clean_force);
	}
}

void jhd_http2_server_ssl_connection_read_event_error_with_timer_clean(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	c = ev->data;
	h2c = c->data;
	h2c->recv_error = 1;

	if(h2c->send_error  | jhd_quit ){
		jhd_http2_connection_free(ev);
		c->close(c);
	}else if(h2c->goaway_sent){
		h2c->recv.state = 500;
		server_ssl_connection_read_event_error_with_timer_clean_after_goaway_sent(ev);
	}else{
		h2c->recv.state = jhd_http2_error_code;
		h2c->recv.sid = 500; ///goaway frame alloc timeout counter
		ev->handler= server_send_goaway_with_read_error_by_timer_clean;
		server_send_goaway_with_read_error_by_timer_clean(ev);
	}
}



static void server_ssl_connection_cleanup_with_write_tigger(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_http2_frame *frame;
	u_char *p;
	jhd_tls_ssl_context *ssl;
	void (*frame_free_func)(void*);


	jhd_queue_init(&free_queue);
	frame = NULL;

	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  || jhd_quit){
		jhd_http2_connection_free(ev);
		c->close(c);
		return;
	}
	if(h2c->processing){
		head = &h2c->flow_control;
		while(jhd_queue_has_item(head)){
			q = jhd_queue_next(head);
			stream = jhd_queue_data(q,jhd_http2_stream,flow_control);

			jhd_queue_only_remove(q);
			jhd_queue_only_remove(&stream->queue);
			jhd_queue_insert_tail(&free_queue,&stream->queue);
			--h2c->processing;

			h2c->recv.stream = stream;
			stream->listener->reset(ev);
			h2c->recv.stream = &jhd_http2_invalid_stream;
		}
	}
	ssl = c->ssl;
	if(h2c->processing  || h2c->send.head != NULL  || ssl->out_msglen){
		goto func_free;
	}
	c->close(c);
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}



static void server_ssl_connection_read_event_error_with_writer_clean_after_goaway(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_http2_frame *frame;
	jhd_tls_ssl_context *ssl;
	u_char i;
	u_char *p;
	void (*frame_free_func)(void*);

	frame = NULL;
	jhd_queue_init(&free_queue);
	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  | jhd_quit){
		jhd_http2_connection_free(ev);
		c->close(c);
		return;
	}
		if(h2c->processing){
			head = &h2c->flow_control;
			while(jhd_queue_has_item(head)){
				q = jhd_queue_next(head);
				stream = jhd_queue_data(q,jhd_http2_stream,flow_control);
				jhd_queue_only_remove(q);
				jhd_queue_only_remove(&stream->queue);
				jhd_queue_insert_tail(&free_queue,&stream->queue);
				--h2c->processing;
				h2c->recv.stream = stream;
				stream->listener->reset(ev);
				h2c->recv.stream = &jhd_http2_invalid_stream;
			}
			if(h2c->processing){
				for(i = 0, head = h2c->streams; ((i < 32) && (h2c->processing)) ; ++i,++head){
					for(q = jhd_queue_next(head); q!= head;){
						stream = jhd_queue_data(q,jhd_http2_stream,queue);
						q = jhd_queue_next(q);
						if((stream->in_close==0)){
							jhd_queue_only_remove(&stream->queue);
							jhd_queue_insert_tail(&free_queue,&stream->queue);
							jhd_queue_only_remove(&stream->flow_control);
							--h2c->processing;
							h2c->recv.stream = stream;
							stream->listener->reset(ev);
							h2c->recv.stream = &jhd_http2_invalid_stream;
						}
					}
				}
			}
		}

		ssl = c->ssl;
		if((h2c->processing) || (h2c->send.head != NULL) || (ssl->out_msglen) ){
			ev->handler = server_ssl_connection_cleanup_with_write_tigger;
			jhd_event_add_timer(ev,0xFFFFFFFFFFFFFFFFULL,jhd_http2_server_connection_read_event_error_with_clean_force);
			goto func_free;
		}

	log_assert(h2c->processing ==0);
	log_assert(h2c->send.head = NULL);
	c->close(c);
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}




void jhd_http2_server_ssl_connection_read_event_error_with_writer_clean(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	c = ev->data;
	h2c = c->data;
	h2c->recv_error = 1;
	if(h2c->send_error  | jhd_quit | h2c->goaway_sent){
		ev->handler = server_ssl_connection_read_event_error_with_writer_clean_after_goaway;
		server_ssl_connection_read_event_error_with_writer_clean_after_goaway(ev);
	}else {
		h2c->recv.state = jhd_http2_error_code;
		h2c->recv.state_param = server_ssl_connection_read_event_error_with_writer_clean_after_goaway;
		ev->handler= server_send_goaway_with_read_error;
		server_send_goaway_with_read_error(ev);
	}
}


