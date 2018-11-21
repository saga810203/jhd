#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_time.h>




static void  invalid_stream_remote_close(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}


static void  invalid_stream_remote_data(jhd_http2_stream *stream,jhd_http2_frame *frame){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);

	frame->free_func(frame);
}

static void  invalid_stream_remote_empty_data(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}
static void  invalid_stream_remote_recv(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}

static void  invalid_stream_recv_window_change(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}

static void  invalid_stream_send_window_change(jhd_http2_stream *stream){
	log_stderr("invalid call[%s]",__FUNCTION__);
	log_assert(1==2);
}

static void  stream_reset_without_request(jhd_http2_stream *stream){
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


















static void jhd_http2_alloc_headers_frame_timeout(jhd_event_t *ev){
	jhd_queue_t h,*q;
	jhd_http_header *header;
	jhd_http2_frame *frame;
	u_char *p;
	size_t len;
	void (*frame_free_func)(void *);

	http_named_header  date;
	http_named_header  server;
	http_named_header  content_type;

	jhd_http_request *r = ev->data;

	jhd_queue_move(&h,&r->headers);
	frame = r->state_param;

	date.data = r->date.data;
	date.alloced = r->date.alloced;
	server.data = r->server.data;
	server.alloced = r->server.alloced;
	content_type.data = r->content_type.data;
	content_type.alloced = r->content_type.alloced;

	if(date.alloced){
		jhd_free_with_size(date.data,date.alloced);
	}
	if(server.alloced){
		jhd_free_with_size(server.data,server.alloced);
	}
	if(content_type.alloced){
		jhd_free_with_size(content_type.data,content_type.alloced);
	}
	while(frame){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}

	while(jhd_queue_has_item(&h)){
		q = jhd_queue_next(&h);
		jhd_queue_only_remove(q);
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







static void http2_reqeust_check(jhd_event_t *ev){
	jhd_http_request *r;
	jhd_queue_t h,*head,*q,*tq;
	jhd_http_header *header,*host;

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
	if(r->host.data == NULL && (NULL != host)){
		r->host.data = host->value;
		r->host.len = host->value_len;
		r->host.alloced = host->value_alloced;
		host->value_alloced = 0;
	}









	func_error:
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

	if(jhd_queue_has_item(r->headers)){
		jhd_queue_merge(&h,&r->headers);
		jhd_queue_init(&r->headers);
	}


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

	r->count = 1;

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

	jhd_queue_move(&r->headers,&event_h2c->recv.headers);


log_assert_code(
	stream->lis_ctx = r ;
	stream->listener = &server_stream_listener_after_request_alloced;
)
}
