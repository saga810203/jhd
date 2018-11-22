#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_time.h>




static void  invalid_stream_remote_close(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}

static void ignore_stream_remote_close(jhd_http2_stream *stream){
	log_notice("exec %s",__FUNCTION__);
};


static void  invalid_stream_remote_data(jhd_http2_stream *stream,jhd_http2_frame *frame){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);

	frame->free_func(frame);
}

static void ignore_stream_remote_data(jhd_http2_stream *stream,jhd_http2_frame *frame){
	log_notice("exec %s",__FUNCTION__);
	frame->free_func(frame);
}

static void  invalid_stream_remote_empty_data(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}

static void ignore_stream_remote_empty_data(jhd_http2_stream *stream){
	log_notice("exec %s",__FUNCTION__);
}

static void  invalid_stream_remote_recv(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}
static void ignore_stream_remote_recv(jhd_http2_stream *stream){
	log_notice("exec %s",__FUNCTION__);
}


static void  invalid_stream_recv_window_change(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}

static void ignore_stream_recv_window_change(jhd_http2_stream *stream){
	log_notice("exec %s",__FUNCTION__);
}

static void  invalid_stream_send_window_change(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}
static void ignore_stream_send_window_change(jhd_http2_stream *stream){
	log_notice("exec %s",__FUNCTION__);
}


static void  stream_reset_without_request(jhd_http2_stream *stream){
}



static void stream_reset_with_direct_free_request(jhd_http2_stream *stream){
	jhd_http_request *r;
	r = stream->lis_ctx;
	jhd_queue_only_remove(&r->event.queue);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}



jhd_http2_stream_listener server_stream_first_listener ={
		invalid_stream_remote_close,	//	jhd_event_handler_pt remote_close;
		invalid_stream_remote_data,//		jhd_event_handler_pt remote_data;
		invalid_stream_remote_empty_data,
		stream_reset_without_request,//		jhd_event_handler_pt reset;
		invalid_stream_remote_recv,//		jhd_event_handler_pt remote_recv;
		invalid_stream_recv_window_change,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		invalid_stream_send_window_change,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

#ifdef JHD_LOG_ASSERT_ENABLE

static void  invalid_stream_reset(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}
static jhd_http2_stream_listener server_stream_listener_after_request_alloced ={
		invalid_stream_remote_close,	//	jhd_event_handler_pt remote_close;
		invalid_stream_remote_data,//		jhd_event_handler_pt remote_data;
		invalid_stream_remote_empty_data,
		invalid_stream_reset,//		jhd_event_handler_pt reset;
		invalid_stream_remote_recv,//		jhd_event_handler_pt remote_recv;
		invalid_stream_recv_window_change,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		invalid_stream_send_window_change,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};
#endif




















static void  stream_remote_close(jhd_http2_stream *stream){
	jhd_http_request *r;
	r = stream->lis_ctx;
	r->in_close = 1;
}

static void  stream_remote_data(jhd_http2_stream *stream,jhd_http2_frame *frame){
	jhd_http_request *r;
	jhd_http2_frame **pframe;

	log_assert(frame->next  == NULL);
	log_assert(frame->len > 0);
	r = stream->lis_ctx;
	pframe = &r->in_data;
	while(*pframe != NULL){
		pframe = &((*pframe)->next);
	}
	*pframe = frame;
}

static void  stream_remote_reset(jhd_http2_stream *stream){
	jhd_http_request *r;
	jhd_event_handler_pt timeout;
	jhd_event_t *ev;
	r = stream->lis_ctx;
	ev = &r->event;
	if(ev->timer.key){
		timeout =ev->timeout;
		jhd_event_del_timer(ev);
		timeout(ev);
	}
	--r->count;
	if(r->count == 0){

	}
}

static stream_reset_with_free_cache_frame_data(jhd_http2_stream *stream){
	jhd_http_request *r;
	r = stream->lis_ctx;
	jhd_queue_only_remove(&r->event.queue);
	jhd_free_with_size(r->cache_frame.data,r->cache_frame.data_len);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}




static jhd_http2_stream_listener server_stream_listener_with_bad_request_alloc_data_frame ={
		ignore_stream_remote_close,	//	jhd_event_handler_pt remote_close;
		ignore_stream_remote_data,//		jhd_event_handler_pt remote_data;
		ignore_stream_remote_empty_data,
		stream_reset_with_direct_free_request,//		jhd_event_handler_pt reset;
		ignore_stream_remote_recv,//		jhd_event_handler_pt remote_recv;
		ignore_stream_recv_window_change,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		ignore_stream_send_window_change,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};
static jhd_http2_stream_listener server_stream_listener_with_flow_control_and_in_send_queue ={
		ignore_stream_remote_close,	//	jhd_event_handler_pt remote_close;
		ignore_stream_remote_data,//		jhd_event_handler_pt remote_data;
		ignore_stream_remote_empty_data,
		stream_reset_with_direct_free_request,//		jhd_event_handler_pt reset;
		ignore_stream_remote_recv,//		jhd_event_handler_pt remote_recv;
		ignore_stream_recv_window_change,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		ignore_stream_send_window_change,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

static jhd_http2_stream_listener server_stream_listener_with_flow_control_and_not_in_send_queue ={
		ignore_stream_remote_close,	//	jhd_event_handler_pt remote_close;
		ignore_stream_remote_data,//		jhd_event_handler_pt remote_data;
		ignore_stream_remote_empty_data,
		stream_reset_with_direct_free_request,//		jhd_event_handler_pt reset;
		ignore_stream_remote_recv,//		jhd_event_handler_pt remote_recv;
		ignore_stream_recv_window_change,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		ignore_stream_send_window_change,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

static void jhd_http2_free_cache_frame(jhd_http2_frame *frame){
	jhd_http_request * r;
	r =  (jhd_http_request *) (((u_char *) frame) - offsetof(jhd_http_request, cache_frame));
	jhd_free_with_size(frame->data,frame->data_len);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}

static void jhd_http2_frame_cache_frame_write_over(jhd_http2_frame *frame){
	frame->data = NULL;
}

static void jhd_http2_free_cache_frame_write_next_fragmentation(jhd_http2_frame *frame){
	jhd_http_request * r;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	int size;

	r =  (jhd_http_request *) (((u_char *) frame) - offsetof(jhd_http_request, cache_frame));
	stream = r->stream;
	c = stream->connection;
	h2c = c->data;

	size = min(h2c->send.window_size,stream->send_window_size);
	if(size >= ((int)r->payload_len)){
		jhd_queue_

		h2c->send.window_size -= r->payload_len;

	}




}


static void http2_alloc_bad_request_body_frame_data(jhd_event_t *ev){
	jhd_http_request *r;
	jhd_http2_frame *frame;

	r = ev->data;
	frame = &r->cache_frame;
	frame->data = jhd_alloc(frame->data_len);
	if(frame->data == NULL){
		jhd_wait_mem(&r->event,frame->data_len);
		return;
	}









}
static void http2_send_bad_request_body(jhd_http_request *r){
	jhd_http2_frame *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	int size;
	u_char *p;


	frame = &r->cache_frame;
	frame->type = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;
	frame->data_len = 9 + jhd_http_bad_request_context_len;
	frame->data = jhd_alloc(frame->data_len);
	if(frame->data == NULL){
		jhd_wait_mem(&r->event,frame->data_len);
		r->event.handler = http2_alloc_bad_request_body_frame_data;
		r->stream->listener = server_stream_listener_with_bad_request_alloc_data_frame;
		return;
	}
	r->payload_len = jhd_http_bad_request_context_len;
	p = frame->pos = frame->data;
	p += 9;
	r->payload = p;
	memcpy(p,jhd_http_bad_request_context,jhd_http_bad_request_context_len);
	p -= 9;
	stream = r->stream;
	c = stream->connection;
	h2c = c->data;

	size = min(h2c->send.window_size,stream->send_window_size);
	if(size < ((int)r->payload_len)){
		jhd_queue_insert(&h2c->flow_control,&stream->flow_control);
		if(size < 1){
			stream->listener = server_stream_listener_with_flow_control_and_not_in_send_queue;
		}else{
			r->payload_len   -= (uint32_t)size;
			r->payload       += (uint32_t)size;

			stream->listener = server_stream_listener_with_flow_control_and_in_send_queue;

			r->count = 1;

			frame->len = 9  +  ((uint32_t)size);

			p[0] = 0;
			p[1] =((u_char)(size>>8));
			p[2] =(u_char)(size);
			p[4] = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;
			p[5] = 0;
			p += 5;
			jhd_http2_set_stream_id(p,stream->id);

			frame->next = NULL;

			frame->func_free =
		}
		return;
	}

	h2c->send.window_size -= jhd_http_bad_request_context_len;
	frame->len = frame->data_len;
	p[0] = 0;
	p[1] =((u_char)(jhd_http_bad_request_context_len>>8));
	p[2] =(u_char)(jhd_http_bad_request_context_len);
	p[4] = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;
	p[5] = JHD_HTTP2_END_STREAM_FLAG;
	p += 5;
	jhd_http2_set_stream_id(p,stream->id);

	frame->free_func = jhd_http2_free_cache_frame;
	frame->next = NULL;
	jhd_http2_send_queue_frame(c,h2c,frame);
	jhd_queue_only_remove(&stream->queue);
	jhd_free_with_size(stream,sizeof(jhd_http2_stream));
}


static void http2_bad_request_alloc_headers_frame(jhd_event_t *ev){
	uint16_t  mem_len;
	jhd_http2_frame **frame_head,*frame;

	jhd_http_request *r = ev->data;
	frame_head = (jhd_http2_frame**)(&r->state_param);

	mem_len = jhd_http2_alloc_headers_frame(frame_head,&r->state);

	if(mem_len){
		jhd_wait_mem(&r->event,mem_len);
		return;
	}

	jhd_http2_send_response_headers_frmae(r,frame_head,jhd_false);

	while((*frame_head)!= NULL){
		frame = *frame_head;
		*frame_head = frame->next;
		frame->free_func(frame);
	}
	http2_send_bad_request_body(r);
}








static stream_reset_with_alloc_headers_frame_block(jhd_http2_stream *stream){
	jhd_http2_frame **frame_head,*frame;
	jhd_http_request *r;

	r = stream->lis_ctx;
	jhd_queue_only_remove(&r->event.queue);
	frame_head = (jhd_http2_frame**)(&r->state_param);
	while((*frame_head)!= NULL){
		frame = *frame_head;
		*frame_head = frame->next;
		frame->free_func(frame);
	}
	jhd_free_with_size(r,sizeof(jhd_http_request));
}


static jhd_http2_stream_listener server_stream_listener_with_bad_request_alloc_header_frame ={
		ignore_stream_remote_close,	//	jhd_event_handler_pt remote_close;
		ignore_stream_remote_data,//		jhd_event_handler_pt remote_data;
		ignore_stream_remote_empty_data,
		stream_reset_with_alloc_headers_frame_block,//		jhd_event_handler_pt reset;
		ignore_stream_remote_recv,//		jhd_event_handler_pt remote_recv;
		ignore_stream_recv_window_change,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		ignore_stream_send_window_change,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};
static void http2_bad_request(jhd_http_request *r){
	uint16_t  mem_len;
	jhd_http2_frame **frame_head,*frame;

	if(r->content_type.alloced){
		jhd_free_with_size(r->content_type.data,r->content_type.alloced);
	}
	if(r->host.alloced){
		jhd_free_with_size(r->host.data,r->host.alloced);
	}
	if(r->path.alloced){
		jhd_free_with_size(r->path.data,r->path.alloced);
	}
	if(r->user_agent.alloced){
		jhd_free_with_size(r->user_agent.data,r->user_agent.alloced);
	}
	if(r->content_type.alloced){
		jhd_free_with_size(r->content_type.data,r->content_type.alloced);
	}
	log_assert( jhd_queue_empty(&r->headers));


	r->status = 400;
	r->server.data = (u_char*)"jhttpd";
	r->server.len = 6;
	r->server.alloced = 0;
	r->date.alloced = 0;
	r->date.data = jhd_cache_http_date;
	r->date.len =  sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	r->content_type.data =(u_char*) "text/html";
	r->content_type.len = sizeof("text/html") - 1;
	r->content_type.alloced = 0;

	log_assert(jhd_http_bad_request_context_len <= 16384);

	r->content_length = jhd_http_bad_request_context_len;

	r->state = jhd_http2_calc_response_headers_size(r);

	frame_head = (jhd_http2_frame**)(&r->state_param);
	*frame_head = NULL;
	mem_len = jhd_http2_alloc_headers_frame(frame_head,&r->state);

	if(mem_len){
		r->event.handler = http2_bad_request_alloc_headers_frame;
		r->event.timeout = jhd_event_noop;
		r->stream->listener = server_stream_listener_with_bad_request_alloc_header_frame;
		jhd_wait_mem(&r->event,mem_len);
		return;
	}
	jhd_http2_send_response_headers_frmae(r,frame_head,jhd_false);
	while((*frame_head)!= NULL){
		frame = *frame_head;
		*frame_head = frame->next;
		frame->free_func(frame);
	}
	http2_send_bad_request_body(r);
}



static void http2_reqeust_check(jhd_event_t *ev){
	jhd_http_request *r;
	jhd_queue_t h,*head,*q,*tq;
	jhd_http_header *header,*host;
	jhd_http_listening_context *http_ctx;


	jhd_queue_init(&h);
	host = NULL;

	r = ev->data;


	head = &r->headers;
	for(q = jhd_queue_next(head); q != head;){
		header = jhd_queue_data(q,jhd_http_header,queue);
		if(header->name_len == 10){
			if (0 == memcpy(header->name,":authority",10)){

				if(r->host->data){
					goto func_error;
				}
				r->host->data = header->value;
				r->host->len = header->value_len;
				r->host->alloced = header->value_alloced;
				header->value_alloced = 0;
				tq = q;
				q = jhd_queue_next(q);
				jhd_queue_only_remove(tq);
				jhd_queue_insert_tail(&h,tq);
			}else if(0 == memcpy(header->name,"user-agent",10)){
				if(r->user_agent->data){
					goto func_error;
				}
				r->user_agent->data = header->value;
				r->user_agent->len = header->value_len;
				r->user_agent->alloced = header->value_alloced;
				header->value_alloced = 0;
				tq = q;
				q = jhd_queue_next(q);
				jhd_queue_only_remove(tq);
				jhd_queue_insert_tail(&h,tq);

			}
		}else if(header->name_len == 7 && (0 == memcpy(header->name,":method",7))){
			if(r->method != JHD_HTTP_METHOD_NONE){
				goto func_error;
			}
			if(header->value_len == 3 ){
				if(0 == memcpy(header->value,"GET",3)){
					if(r->in_close ==0){
						goto func_error;
					}
					r->method = JHD_HTTP_METHOD_GET;

				}else if(0 == memcpy(header->value,"PUT",3)){
					r->method = JHD_HTTP_METHOD_PUT;

				}else{
					goto func_error;
				}
			}else if(header->value_len == 4 ){
				if(0 == memcpy(header->value,"HEAD",4)){
					if(r->in_close ==0){
						goto func_error;
					}
					r->method = JHD_HTTP_METHOD_HEAD;

				}else if(0 == memcpy(header->value,"POST",4)){
					r->method = JHD_HTTP_METHOD_POST;
				}else{
					goto func_error;
				}
			}else if(header->value_len == 6 && (0 == memcpy(header->value,"DELETE",6)) ){
					if(r->in_close ==0){
						goto func_error;
					}
					r->method = JHD_HTTP_METHOD_DELETE;
			}else if(header->value_len == 7 && (0 == memcpy(header->value,"OPTIONS",7)) ){
				if(r->in_close ==0){
					goto func_error;
				}
				r->method = JHD_HTTP_METHOD_OPTIONS;
			}else{
				goto func_error;
			}
			tq = q;
			q = jhd_queue_next(q);
			jhd_queue_only_remove(tq);
			jhd_queue_insert_tail(&h,tq);
		}else if(header->name_len == 5 && (0 == memcpy(header->name,":path",5))){
			if(r->path->data){
				goto func_error;
			}
			r->path->data = header->value;
			r->path->len = header->value_len;
			r->path->alloced = header->value_alloced;
			header->value_alloced = 0;
			tq = q;
			q = jhd_queue_next(q);
			jhd_queue_only_remove(tq);
			jhd_queue_insert_tail(&h,tq);
		}else if(header->name_len == 4 && (0 == memcpy(header->name,"host",4))){
			if(host){
				goto func_error;
			}
			host = header;
			tq = q;
			q = jhd_queue_next(q);
			jhd_queue_only_remove(tq);
		}else if(header->name_len == 12 && (0 == memcpy(header->name,"content-type",12))){
			if(r->content_type->data){
				goto func_error;
			}
			r->content_type->data = header->value;
			r->content_type->len = header->value_len;
			r->content_type->alloced = header->value_alloced;
			header->value_alloced = 0;
			tq = q;
			q = jhd_queue_next(q);
			jhd_queue_only_remove(tq);
			jhd_queue_insert_tail(&h,tq);
		}else if((header->name_len)  && (':'== header->name[0])){
			tq = q;
			q = jhd_queue_next(q);
			jhd_queue_only_remove(tq);
			jhd_queue_insert_tail(&h,tq);
		}
	}


	if(r->method == JHD_HTTP_METHOD_NONE ||  (NULL  ==  r->path.data)){
		goto func_error;
	}
	if (r->host.data == NULL && NULL != host) {
		r->host.data = host->value;
		r->host.len = host->value_len;
		r->host.alloced = host->value_alloced;
		host->value_alloced = 0;
	}
	http_ctx =(jhd_http_listening_context *) r->stream->connection->listening->lis_ctx;
	http_ctx->handler(http_ctx->data,r);
	goto func_free;

func_error:
	if(jhd_queue_has_item(r->headers)){
		jhd_queue_merge(&h,&r->headers);
		log_assert_code(jhd_queue_init(&r->headers);)
	}
	http2_bad_request(r);
func_free:
	head = &h;
	for(q = jhd_queue_next(head); q != head;){
		header = jhd_queue_data(q,jhd_http_header,queue);
		tq = q;
		q = jhd_queue_next(q);
		jhd_queue_only_remove(tq);

		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_alloced);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_alloced);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	}
	header = host;
	if(header){
		header = jhd_queue_data(q,jhd_http_header,queue);
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_alloced);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_alloced);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	}
}

void jhd_http_request_init_by_http2(jhd_http_request *r,jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream * stream;

	c= ev->data;
	h2c = c->data;
	stream = h2c->recv.stream;

	r->cache_frame.ack = 0;
	r->cache_frame.padded = 0;
	r->cache_frame.data = NULL;
	r->cache_frame.data_len = 0;
	r->cache_frame.free_func = NULL;
	r->cache_frame.len = 0;
	r->cache_frame.next = NULL;
	r->cache_frame.pos = NULL;
	r->cache_frame.type = 0;


	r->content_length = -1;

	r->content_type.alloced = 0;
	r->content_type.data = NULL;
	r->content_type.len = 0;

	r->count = 0;

	r->path.alloced = 0;
	r->path.data = NULL;
	r->path.len = 0;

	r->event.data = r;
	r->event.handler = http2_reqeust_check;
	r->event.timer.key = 0;
	jhd_queue_init(&r->event.queue);

//	jhd_queue_init(&r->headers);

	r->host.alloced = 0;
	r->host.data = NULL;
	r->host.len = 0;

	r->in_close = stream->in_close;

	r->in_data = NULL;

	r->is_http2 = 1;

	r->method = JHD_HTTP_METHOD_NONE;

	r->out_close = 0;

	r->out_headers_sent = 0;

	jhd_queue_init(&r->queue);


	r->state = 0;

	r->state_param = NULL;

	r->user_agent.alloced = 0;
	r->user_agent.data = NULL;
	r->user_agent.len = 0;

	r->stream = stream;


	r->cache_frame.type = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;


	jhd_queue_move(&r->headers,&event_h2c->recv.headers);
	stream->lis_ctx = r ;

log_assert_code(
	stream->listener = &server_stream_listener_after_request_alloced;
)
}
