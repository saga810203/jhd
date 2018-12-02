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




static void http_alloc_cached_response_body_frame_data_timeout(jhd_event_t *ev){
		jhd_http_request *r;
		jhd_http2_stream *stream;
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
		jhd_http2_frame *frame;
		u_char *p;

		r = ev->data;
		stream = r->stream;
		c = stream->connection;
		h2c = c->data;

		jhd_queue_only_remove(stream->queue);

		frame = (jhd_http2_frame*)(stream);
		--h2c->processing;
		h2c->recv.stream = &jhd_http2_invalid_stream;
		p = frame->pos = (u_char*)(((u_char*)frame)+sizeof(jhd_http2_frame));
		frame->type = JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME;
		frame->data_len = sizeof(jhd_http2_stream);
		frame->len = 13;
		frame->free_func = jhd_http2_frame_free_by_single;
		frame->next = NULL;
		*((uint32_t*)p) =0x03040000;
		p[4] = 0;\
		p[5] = (u_char)((stream->id) >> 24);
		p[6] = (u_char)((stream->id) >> 16);
		p[7] = (u_char)((stream->id) >> 8);
		p[8] = (u_char)(stream->id);
		p += 9;
		*((uint32_t*)p) = JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT;
		jhd_http2_send_queue_frame(c,h2c,frame);

		jhd_queue_only_remove(&r->event.queue);
		jhd_http_request_free(r);
}


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
	log_assert(r->cache_frame->len >0);
	frame = &r->cache_frame;
	frame->data_len = 9 + frame->len;
	frame->data = jhd_alloc(frame->data_len);
	if(frame->data == NULL){
		jhd_wait_mem(&r->event,frame->data_len);
		r->event.handler = http2_alloc_cached_response_body_frame_data;
		jhd_event_add_timer(&r->event,r->mem_timeout,http_alloc_cached_response_body_frame_data_timeout);
		((jhd_http2_stream*)(r->stream))->listener = &server_stream_listener_with_ignore_request_body_alloc_data_frame;
		return;
	}
	if(r->event.timer.key){
		jhd_event_del_timer(&r->event);
	}
	r->payload =frame->data+ 9;
	r->payload_len = frame->len;
	memcpy(r->payload,frame->pos,frame->len);
	jhd_http2_stream_send_last_raw_data(r);
}
void jhd_http2_alloc_single_response_headers_frame_timeout(jhd_event_t *ev){
	jhd_http_request *r;
	r = ev->data;
	jhd_http2_reset_stream_by_request(r,JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
	jhd_queue_only_remove(&r->event.queue);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}
void jhd_http2_alloc_multi_response_headers_frame_timeout(jhd_event_t *ev){
	jhd_http_request *r;
	jhd_http2_frame *frame,*next;
	r = ev->data;
	jhd_http2_reset_stream_by_request(r,JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
	jhd_queue_only_remove(&r->event.queue);
	next = (jhd_http2_frame*)(r->state_param);
	while(next){
		frame = next;
		next = next->next;
		frame->free_func(frame);
	}

	jhd_free_with_size(r,sizeof(jhd_http_request));
}


static void http2_cache_response_alloc_headers_frame(jhd_event_t *ev) {
	jhd_http2_frame *frame;
	jhd_http_request *r = ev->data;
	frame = jhd_alloc(256);
	if(frame){
		jhd_http2_send_cache_response_headers_frmae(r,frame);
		http2_send_cache_response_body(r);
	}else{
		jhd_wait_mem(&r->event, 256);
		jhd_event_add_timer(ev,r->http_service->mem_timeout,jhd_http2_alloc_single_response_headers_frame_timeout);
	}
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

static void stream_reset_with_alloc_single_headers_frame_block(jhd_http2_stream *stream){
	jhd_http_request *r;
	r = stream->lis_ctx;
	jhd_queue_only_remove(&r->event.queue);
	log_assert(r->event.timer.key !=0);
	jhd_event_del_timer(&r->event);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}

jhd_http2_stream_listener jhd_http2_server_stream_listener_at_alloc_single_header_frame_block_and_ignore_data_frame ={
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
		jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
		jhd_http2_stream_ignore_listener,
		stream_reset_with_alloc_single_headers_frame_block,//		jhd_event_handler_pt reset;
		jhd_http2_stream_ignore_listener,//		jhd_event_handler_pt remote_recv;
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

static void stream_reset_with_alloc_multi_headers_frame_block(jhd_http2_stream *stream){
	jhd_http2_frame *frame,*next;
	jhd_http_request *r;

	r = stream->lis_ctx;
	jhd_queue_only_remove(&r->event.queue);

	log_assert(r->event.timer.key !=0);
	jhd_event_del_timer(&r->event);

	next = (jhd_http2_frame*)(r->state_param);
	while(next){
		frame = next;
		next = next->next;
		frame->free_func(frame);
	}
	jhd_http_request_free(r);
}

jhd_http2_stream_listener jhd_http2_server_stream_listener_at_alloc_multi_header_frame_block_and_ignore_data_frame={
	jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
	jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
	jhd_http2_stream_ignore_listener,
	stream_reset_with_alloc_multi_headers_frame_block,//		jhd_event_handler_pt reset;
	jhd_http2_stream_ignore_listener,//		jhd_event_handler_pt remote_recv;
	jhd_http2_stream_ignore_listener,//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
	jhd_http2_stream_ignore_listener,//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};



void jhd_http2_send_cached_response(jhd_http_request *r,uint16_t status,u_char* body,uint16_t body_len){

	jhd_http2_frame *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;

	u_char *content_type,*host,*user_agent,*path;
	uint16_t  content_type_len,host_len,user_agent_len,path_len;

	log_assert(body_len >0);
	log_assert((status==400) || (status==404) || (status==500));

	content_type_len = host_len = user_agent_len = path_len = 0;

	if(r->content_type.alloced){
		content_type = r->content_type.data;
		content_type_len = r->content_type.alloced;
		r->content_type.alloced = 0;
	}
	if(r->host.alloced){
		host = r->host.data;
		host_len = r->host.alloced;
		r->host.alloced = 0;
	}
	if(r->path.alloced){
		path = r->path.data;
		path_len = r->path.alloced;
		r->path.alloced = 0;
	}
	if(r->user_agent.alloced){
		user_agent = r->user_agent.data;
		user_agent_len = r->user_agent.alloced ;
		r->user_agent.alloced = 0;
	}
	log_assert( jhd_queue_empty(&r->headers));

	r->status = status;
	r->content_length = body_len;
	r->cache_frame.pos = body;
	r->cache_frame.len = body_len;

	//TODO op this value[256]  only include  state  content_length  content_type server date
	r->state_param = NULL;
	frame = jhd_alloc(256);
	if(frame == NULL){
		r->event.handler = http2_cache_response_alloc_headers_frame;
		((jhd_http2_stream*)(r->stream))->listener = &jhd_http2_server_stream_listener_at_alloc_single_header_frame_block_and_ignore_data_frame;
		jhd_wait_mem(&r->event,256);
		jhd_event_add_timer(&r->event,r->http_service->mem_timeout,jhd_http2_alloc_single_response_headers_frame_timeout);
		goto func_free;
	}
	jhd_http2_send_cache_response_headers_frmae(r,frame);
	http2_send_cache_response_body(r);


func_free:
	if(content_type_len){
		jhd_free_with_size(content_type,content_type_len);
	}
	if(path_len){
		jhd_free_with_size(path,path_len);
	}
	if(user_agent_len){
		jhd_free_with_size(user_agent,user_agent_len);
	}
	if(host_len){
		jhd_free_with_size(host,host_len);
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
		jhd_queue_init(&r->headers);
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
	r->event.queue.next = NULL;


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


void jhd_http_request_handle_with_412_by_http2(jhd_http_request *r) {
	jhd_queue_t h, *head, *q, *tq;
	jhd_http_header *header;

	if(jhd_queue_has_item(&r->headers)){
		jhd_queue_move(&h,&r->headers);
	}else{
		jhd_queue_init(&h);
	}

	jhd_http2_send_cached_response(r, 412, jhd_http_412_request_context, jhd_http_412_request_context_len);
	head = &h;
	for (q = jhd_queue_next(head); q != head;) {
		header = jhd_queue_data(q, jhd_http_header, queue);
		tq = q;
		q = jhd_queue_next(q);
		jhd_queue_only_remove(tq);

		if (header->name_alloced) {
			jhd_free_with_size(header->name, header->name_alloced);
		}
		if (header->value_alloced) {
			jhd_free_with_size(header->value, header->value_alloced);
		}
		jhd_free_with_size(header, sizeof(jhd_http_header));
	}
}

void jhd_http_request_handle_with_nofound_by_http2(jhd_http_request *r){
	jhd_queue_t h,*head,*q,*tq;
	jhd_http_header *header;

	if(jhd_queue_has_item(&r->headers)){
		jhd_queue_move(&h,&r->headers);
	}else{
		jhd_queue_init(&h);
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

	if(jhd_queue_has_item(&r->headers)){
		jhd_queue_move(&h,&r->headers);
	}else{
		jhd_queue_init(&h);
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
