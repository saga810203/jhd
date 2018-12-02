#include <http/jhd_http_static_service.h>
#include <http2/jhd_http2_static.h>
#include <http2/jhd_http2_response_send.h>



static void stream_reset_with_at_alloc_header_frame_of_static_response_block(jhd_http2_stream *stream) {
	jhd_http_request *r;
	r = stream->lis_ctx;
	log_assert(r->event.timer.key != 0);
	log_assert(jhd_queue_queued(&r->event));
	log_assert(r->file_info.fd != -1);
	jhd_queue_only_remove(&r->event.queue);
	jhd_event_del_timer(&r->event);
	jhd_close(r->file_info.fd);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static jhd_http2_stream_listener server_stream_listener_at_alloc_header_frame_of_static_response_block = {
			jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
			jhd_http2_stream_ignore_data_listener, //		jhd_event_handler_pt remote_data;
			jhd_http2_stream_ignore_listener,
			stream_reset_with_at_alloc_header_frame_of_static_response_block, //		jhd_event_handler_pt reset;
			jhd_http2_stream_ignore_listener, //		jhd_event_handler_pt remote_recv;
			jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
			jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

static void http2_alloc_headers_frame_of_static_response_timeout(jhd_event_t *ev) {
		jhd_http_request *r = ev->data;
		jhd_queue_only_remove(&r->event.queue);
		jhd_http2_reset_stream_by_request(r, JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		jhd_close(r->file_info.fd);
		jhd_free_with_size(r, sizeof(jhd_http_request));
}


static void http2_alloc_headers_frame_with_200(jhd_event_t *ev) {
	jhd_http2_frame *frame;
	jhd_http_request *r = ev->data;
	log_assert(r->event.timer.key != 0);

	jhd_event_del_timer(ev);
	frame = jhd_alloc(256);
	log_assert(frame!= NULL);
	http2_send_static_200_response_headers_frmae(r, frame);
}



void jhd_http2_static_request_handle_with_200(jhd_http_request *r){
	jhd_http2_frame *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	u_char *host, *user_agent, *path;
	uint16_t host_len, user_agent_len, path_len;
	host_len = user_agent_len = path_len = 0;

	if (r->host.alloced) {
		host = r->host.data;
		host_len = r->host.alloced;
		r->host.alloced = 0;
	}
	if (r->path.alloced) {
		path = r->path.data;
		path_len = r->path.alloced;
		r->path.alloced = 0;
	}
	if (r->user_agent.alloced) {
		user_agent = r->user_agent.data;
		user_agent_len = r->user_agent.alloced;
		r->user_agent.alloced = 0;
	}
	log_assert(jhd_queue_empty(&r->headers));
	//TODO op this value[256]  only include  state  content_length  content_type server date
	frame = jhd_alloc(256);
	if (frame == NULL) {
		r->event.handler = http2_alloc_headers_frame_with_200;
		((jhd_http2_stream*) (r->stream))->listener = &server_stream_listener_at_alloc_header_frame_of_static_response_block;
		jhd_wait_mem(&r->event, 256);
		jhd_event_add_timer(&r->event, r->http_service->mem_timeout, http2_alloc_headers_frame_of_static_response_timeout);
		goto func_free;
	}
	http2_send_static_200_response_headers_frmae(r, frame);
	func_free: if (path_len) {
		jhd_free_with_size(path, path_len);
	}
	if (user_agent_len) {
		jhd_free_with_size(user_agent, user_agent_len);
	}
	if (host_len) {
		jhd_free_with_size(host, host_len);
	}
}



}
void jhd_http2_static_request_handler_with_206(jhd_http_request *r){




}

static void send_response_headers_frmae_with_304(jhd_http_request *r,jhd_http2_frame *frame){
	uint16_t len;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	u_char *p,*etag;
	u_char etag_buffer[41];

	stream = r->stream;
	c = stream->connection;
	h2c = c->data;

	log_assert(r->event.timer.key ==0);

	frame->type = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->end_header = 1;
	frame->data_len = 256;
	frame->free_func = jhd_http2_frame_free_by_single;
	p = ((u_char*)frame) + sizeof(jhd_http2_frame);
	frame->pos = p;
	p += 9;

	*p = 128 + 11;
	++p;
	//server:jhttpd
	*p = 15;
	++p;
	*p = 54 - 15;
	++p;
	*p = 6;
	++p;
	memcpy(p,"jhttpd",6);
	p += 6; // (2+1+r->server.len);

	//data
	*p = 15;
	++p;
	*p = 33 - 15;
	++p;
	*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	++p;
	memcpy(p,jhd_cache_http_date,sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	//last-modified
	*p = 15;
	++p;
	*p = 44 - 15;
	++p;
	*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	++p;
	jhd_write_http_time(p,r->file_info->mtime);
	p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);

	*p = 15;
	++p;
	*p = 34 - 15;
	++p;
	etag = http_etag_calc(etag_buffer + 40,r->file_info.size,r->file_info.mtime);
	len = etag_buffer + 40 - etag;
	*p = (u_char)(len);
	++p;
	memcpy(p,etag,len);
	p += len;

	len = p - frame->pos;
	frame->len = len;
	len -= 9;
	frame->pos[0] = 0;
	frame->pos[1] = 0;
	frame->pos[2] = (u_char)(len);
	frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG | JHD_HTTP2_END_STREAM_FLAG;
	frame->pos[5] = (u_char)(stream->id >> 24);
	frame->pos[6] = (u_char)(stream->id >> 16);
	frame->pos[7] = (u_char)(stream->id >> 8);
	frame->pos[8] = (u_char)(stream->id);
	frame->next = NULL;
	jhd_http2_send_headers_frame(c,h2c,frame,frame);

	jhd_queue_only_remove(stream->queue);
	--h2c->processing;
	jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	jhd_free_with_size(r,sizeof(jhd_http_request));
}
static void http2_alloc_headers_frame_with_304(jhd_event_t *ev){
	jhd_http2_frame *frame;
	jhd_http_request *r = ev->data;
	frame = jhd_alloc(256);
	log_assert(frame != NULL);
	log_assert(ev->timer.key != 0);
	send_response_headers_frmae_with_304(r,frame);
}
void jhd_http2_static_request_handler_with_304(jhd_http_request *r){
	jhd_http2_frame *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	u_char *host,*user_agent,*path;
	uint16_t host_len,user_agent_len,path_len;
	host_len = user_agent_len = path_len = 0;
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
		user_agent_len = r->user_agent.alloced;
		r->user_agent.alloced = 0;
	}
	log_assert(jhd_queue_empty(&r->headers));

	//TODO op this value[256]  only include  state  content_length  content_type server date
	frame = jhd_alloc(256);
	if(frame){
		send_response_headers_frmae_with_304(r,frame);
	}else{
		r->event.handler = http2_alloc_headers_frame_with_304;
		((jhd_http2_stream*)(r->stream))->listener = &jhd_http2_server_stream_listener_at_alloc_single_header_frame_block_and_ignore_data_frame;
		jhd_wait_mem(&r->event,256);
		jhd_event_add_timer(&r->event,r->http_service->mem_timeout,jhd_http2_alloc_single_response_headers_frame_timeout);
	}
func_free:
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

