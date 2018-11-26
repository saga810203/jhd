#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_time.h>
#include <http2/jhd_http2_stream_listener.h>
#include <http2/jhd_http2_response_send.h>



//TODO: config

uint32_t   jhd_http_request_default_mem_timeout = 5000;


jhd_http2_stream_listener server_stream_first_listener ={
		jhd_http2_stream_invlid_listener,	//	jhd_event_handler_pt remote_close;
		jhd_http2_stream_invalid_data_listener,//		jhd_event_handler_pt remote_data;
		jhd_http2_stream_invlid_listener,

		jhd_http2_stream_ignore_listener,//		    jhd_event_handler_pt reset;

		jhd_http2_stream_invlid_listener,//		jhd_event_handler_pt remote_recv;
		jhd_http2_stream_invlid_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		jhd_http2_stream_invlid_listener,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

#ifdef JHD_LOG_ASSERT_ENABLE
static jhd_http2_stream_listener server_stream_listener_after_request_alloced ={
		jhd_http2_stream_invlid_listener,	//	jhd_event_handler_pt remote_close;
		jhd_http2_stream_invalid_data_listener,//		jhd_event_handler_pt remote_data;
		jhd_http2_stream_invlid_listener,

		jhd_http2_stream_invlid_listener,//		    jhd_event_handler_pt reset;

		jhd_http2_stream_invlid_listener,//		jhd_event_handler_pt remote_recv;
		jhd_http2_stream_invlid_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		jhd_http2_stream_invlid_listener,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};
#endif


jhd_http2_stream_listener server_stream_listener_with_ignore_request_body_alloc_data_frame = {
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
		jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
		jhd_http2_stream_ignore_listener,

		jhd_http2_stream_listener_by_rest_with_direct_free_request,//		    jhd_event_handler_pt reset;

		jhd_http2_stream_ignore_listener,//		jhd_event_handler_pt remote_recv;
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};




static void http2_alloc_cached_response_body_frame_data(jhd_event_t *ev){
	jhd_http_request *r;
	jhd_http2_frame *frame;

	r = ev->data;
	frame = &r->cache_frame;
	frame->data = jhd_alloc(frame->data_len);
	if(frame->data == NULL){
		jhd_wait_mem(&r->event,frame->data_len);
		return;
	}
	r->payload =frame->data + 9;
	r->payload_len = frame->len;
	memcpy(r->payload,frame->pos,frame->len);
	jhd_http2_stream_send_last_raw_data(r);
}
static void http2_send_cache_response_body(jhd_http_request *r){
	jhd_http2_frame *frame;
	frame = &r->cache_frame;
	frame->data_len = 9 + frame->len;
	frame->data = jhd_alloc(frame->data_len);
	if(frame->data == NULL){
		jhd_wait_mem(&r->event,frame->data_len);
		r->event.handler = http2_alloc_cached_response_body_frame_data;
		((jhd_http2_stream*)(r->stream))->listener = &server_stream_listener_with_ignore_request_body_alloc_data_frame;
		return;
	}
	r->payload =frame->data+ 9;
	r->payload_len = frame->len;
	memcpy(r->payload,frame->pos,frame->len);
	jhd_http2_stream_send_last_raw_data(r);
}


static void http2_cache_response_alloc_headers_frame(jhd_event_t *ev) {
	uint16_t mem_len;
	jhd_http2_frame **frame_head, *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;

	jhd_http_request *r = ev->data;
	frame_head = (jhd_http2_frame**) (&r->state_param);

	mem_len = jhd_http2_alloc_headers_frame(frame_head, &r->state);

	if (mem_len) {
		jhd_wait_mem(&r->event, mem_len);
		return;
	}
	jhd_http2_send_response_headers_frmae(r, frame_head, jhd_false);
	while ((*frame_head) != NULL) {
		frame = *frame_head;
		*frame_head = frame->next;
		frame->free_func(frame);
	}
	if (r->cache_frame.len) {
		http2_send_cache_response_body(r);
	} else {
		stream = r->stream;
		c = stream->connection;
		h2c = c->data;
		jhd_queue_remove(&stream->queue);
		h2c->recv.stream = &jhd_http2_invalid_stream;
		--h2c->processing;
		jhd_free_with_size(stream, sizeof(jhd_http2_stream));
		jhd_free_with_size(r, sizeof(jhd_http_request));
	}

}








static void stream_reset_with_alloc_headers_frame_block(jhd_http2_stream *stream){
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


static jhd_http2_stream_listener server_stream_listener_with_ignore_request_body_alloc_header_frame ={
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
		jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
		jhd_http2_stream_ignore_listener,
		stream_reset_with_alloc_headers_frame_block,//		jhd_event_handler_pt reset;
		jhd_http2_stream_ignore_listener,//		jhd_event_handler_pt remote_recv;
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

static void jhd_http2_send_cached_response(jhd_http_request *r,uint16_t status,u_char* body,uint16_t body_len){
	uint16_t  mem_len;
	jhd_http2_frame **frame_head,*frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;

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

	r->status = status;
	r->server.data = (u_char*)"jhttpd";
	r->server.len = 6;
	r->server.alloced = 0;
	r->date.alloced = 0;
	r->date.data = jhd_cache_http_date;
	r->date.len =  sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	r->content_type.data =(u_char*) "text/html";
	r->content_type.len = sizeof("text/html") - 1;
	r->content_type.alloced = 0;
	r->content_length = body_len;



	r->cache_frame.pos = body;
	r->cache_frame.len = body_len;

	r->state = jhd_http2_calc_response_headers_size(r);
	frame_head = (jhd_http2_frame**)(&r->state_param);
	*frame_head = NULL;
	mem_len = jhd_http2_alloc_headers_frame(frame_head,&r->state);
	if(mem_len){
		r->event.handler = http2_cache_response_alloc_headers_frame;
		r->event.timeout = jhd_event_noop;
		((jhd_http2_stream*)(r->stream))->listener = &server_stream_listener_with_ignore_request_body_alloc_header_frame;
		jhd_wait_mem(&r->event,mem_len);
		return;
	}
	jhd_http2_send_response_headers_frmae(r,frame_head,body_len?jhd_false:jhd_true);
	while((*frame_head)!= NULL){
		frame = *frame_head;
		*frame_head = frame->next;
		frame->free_func(frame);
	}
	if(body_len){
		http2_send_cache_response_body(r);
	}else{
		stream = r->stream;
		c= stream->connection;
		h2c = c->data;
		jhd_queue_remove(&stream->queue);
		h2c->recv.stream = &jhd_http2_invalid_stream;
		--h2c->processing;
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
		jhd_free_with_size(r,sizeof(jhd_http_request));
	}
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

				if(r->host.data){
					goto func_error;
				}
				r->host.data = header->value;
				r->host.len = header->value_len;
				r->host.alloced = header->value_alloced;
				header->value_alloced = 0;
				tq = q;
				q = jhd_queue_next(q);
				jhd_queue_only_remove(tq);
				jhd_queue_insert_tail(&h,tq);
			}else if(0 == memcpy(header->name,"user-agent",10)){
				if(r->user_agent.data){
					goto func_error;
				}
				r->user_agent.data = header->value;
				r->user_agent.len = header->value_len;
				r->user_agent.alloced = header->value_alloced;
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
			if(r->path.data){
				goto func_error;
			}
			r->path.data = header->value;
			r->path.len = header->value_len;
			r->path.alloced = header->value_alloced;
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
			if(r->content_type.data){
				goto func_error;
			}
			r->content_type.data = header->value;
			r->content_type.len = header->value_len;
			r->content_type.alloced = header->value_alloced;
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
	http_ctx =(jhd_http_listening_context *) (((jhd_http2_stream*)(r->stream))->connection->listening->lis_ctx);
	http_ctx->handler(http_ctx->data,r);
	goto func_free;

func_error:
	if(jhd_queue_has_item(&r->headers)){
		jhd_queue_merge(&h,&r->headers);
		log_assert_code(jhd_queue_init(&r->headers);)
	}
	jhd_http2_send_cached_response(r,400,jhd_http_bad_request_context,jhd_http_bad_request_context_len);
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

	r->mem_timeout = jhd_http_request_default_mem_timeout;

	jhd_queue_move(&r->headers,&event_h2c->recv.headers);
	stream->lis_ctx = r ;

log_assert_code(
	stream->listener = &server_stream_listener_after_request_alloced;
)
}











void jhd_http_request_handle_with_bad_by_http2(jhd_http_request *r){
	jhd_queue_t h,*head,*q,*tq;
	jhd_http_header *header;
	jhd_queue_init(&h);

	if(jhd_queue_has_item(&r->headers)){
			jhd_queue_merge(&h,&r->headers);
			log_assert_code(jhd_queue_init(&r->headers);)
	}
	jhd_http2_send_cached_response(r,400,jhd_http_bad_request_context,jhd_http_bad_request_context_len);
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
}
void jhd_http_request_handle_with_nofound_by_http2(jhd_http_request *r){
	jhd_queue_t h,*head,*q,*tq;
	jhd_http_header *header;
	jhd_queue_init(&h);

	if(jhd_queue_has_item(&r->headers)){
			jhd_queue_merge(&h,&r->headers);
			log_assert_code(jhd_queue_init(&r->headers);)
	}
	jhd_http2_send_cached_response(r,404,jhd_http_nofound_request_context,jhd_http_nofound_request_context_len);
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
}
void jhd_http_request_handle_with_internal_error_by_http2(jhd_http_request *r){
	jhd_queue_t h,*head,*q,*tq;
	jhd_http_header *header;
	jhd_queue_init(&h);

	if(jhd_queue_has_item(&r->headers)){
			jhd_queue_merge(&h,&r->headers);
			log_assert_code(jhd_queue_init(&r->headers);)
	}
	jhd_http2_send_cached_response(r,500,jhd_http_internal_error_request_context,jhd_http_internal_error_request_context_len);
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
}
