#include <http/jhd_http_static_service.h>
#include <http2/jhd_http2_static.h>
#include <http2/jhd_http2_response_send.h>

static void http2_static_aio_read_over_with_206(jhd_event_t *ev) {
	jhd_http_request *r;
	jhd_aio_cb *aio;
	r = ev->data;
	jhd_close(r->file_info.fd);
	if (r->aio->result != ((ssize_t)r->aio->aio.aio_nbytes)) {
		jhd_http2_reset_stream_by_request(r,JHD_HTTP2_INTERNAL_ERROR_READ_FILE_TIMEOUT);
		jhd_aio_free(r->aio);
		jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
		jhd_free_with_size(r, sizeof(jhd_http_request));
	} else {
		r->payload_len = ((uint32_t) (r->aio->result)) - r->aio_skip;
		r->payload += r->aio_skip;
		aio = r->aio;
		jhd_http2_stream_send_last_raw_data(r);
		jhd_aio_free(aio);
	}
}

static void http2_static_aio_read_compele_with_206(jhd_event_t *ev) {
	jhd_http_request *r;
	r = ev->data;
	jhd_close(r->file_info.fd);
	if (r->aio->result != ((ssize_t)r->aio->aio.aio_nbytes)) {
		jhd_http2_reset_stream_by_request(r,JHD_HTTP2_INTERNAL_ERROR_READ_FILE_TIMEOUT);
		jhd_aio_free(r->aio);
		jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
		jhd_free_with_size(r, sizeof(jhd_http_request));
	} else {
		r->payload_len = ((uint32_t) (r->aio->result)) - r->aio_skip;
		r->payload += r->aio_skip;
		http2_stream_send_file_raw_data(r);
	}
}

static void http2_static_206_response_start_read(jhd_http_request *r) {
	size_t len;
	jhd_http2_stream *stream;
	r->payload = r->cache_frame.data + 9;
	r->aio->aio.aio_buf = (uint64_t) (r->payload);
	len = r->cache_frame.data_len - 9;
	stream = r->stream;

	if(r->aio_skip){
		if (len <= r->static_file_size) {
			r->aio->aio.aio_nbytes = r->static_file_size;
			r->event.handler = http2_static_aio_read_over_with_206;
			stream->listener = &http2_server_stream_listener_block_with_static_response_aio_read;
		} else {
			r->aio->aio.aio_nbytes = len;
			r->static_file_size -= len;
			r->event.handler = http2_static_aio_read_compele;
			stream->listener = &http2_server_stream_listener_block_with_static_response_aio_read;
		}
	}else{
		if (len <= r->static_file_size) {
			r->aio->aio.aio_nbytes = r->static_file_size;
			r->event.handler = http2_static_aio_read_over;
			stream->listener = &http2_server_stream_listener_block_with_static_response_aio_read;
		} else {
			r->aio->aio.aio_nbytes = len;
			r->static_file_size -= len;
			r->event.handler = http2_static_aio_read_compele_with_206;
			stream->listener = &http2_server_stream_listener_block_with_static_response_aio_read;
		}
	}
	r->event.timeout = http2_static_aio_read_timeout;
	jhd_aio_submit(r->aio);
}
static void http2_send_static_206_response_alloc_data_buffer(jhd_event_t *ev) {
	jhd_http_request *r;
	r = ev->data;

	log_assert(r->event.timer.key != 0);
	jhd_event_del_timer(ev);

	r->cache_frame.data = jhd_alloc(r->cache_frame.data_len);
	log_assert(r->cache_frame.data != NULL);
	http2_static_206_response_start_read(r);
}

void http2_send_static_206_response_data_frmae(jhd_http_request *r) {
	size_t size;
	jhd_http2_stream *stream;

	r->aio->aio.aio_fildes = r->file_info.fd;

	r->aio_skip = r->file_info.range_start % jhd_aio_block_size;

	size = r->static_file_size = r->file_info.range_end - r->file_info.range_start + r->aio_skip + 1;

	r->aio->aio.aio_offset = r->file_info.range_start - r->aio_skip;

	if (size <= 1024) {
		r->cache_frame.data_len = 1024 + 9;
	} else if (size <= 2048) {
		r->cache_frame.data_len = 2048 + 9;
	} else if (size <= 4096) {
		r->cache_frame.data_len = 4096 + 9;
	} else if (size <= 8192) {
		r->cache_frame.data_len = 8192 + 9;
	} else {
		r->cache_frame.data_len = 16384 + 9;
	}
	r->cache_frame.data = jhd_alloc(r->cache_frame.data_len);
	if (r->cache_frame.data) {
		http2_static_206_response_start_read(r);
	} else {
		r->event.handler = http2_send_static_206_response_alloc_data_buffer;
		jhd_wait_mem(&r->event, r->cache_frame.data_len);
		jhd_event_add_timer(&r->event, r->http_service->mem_timeout, http2_wait_file_data_buffer_timeout);
		stream = r->stream;
		stream->listener = &http2_server_stream_listener_block_with_static_response_alloc_data_buffer;
	}
}




static void http2_static_206_alloc_aio(jhd_event_t *ev) {
	jhd_http_request *r = ev->data;
	log_assert(r->file_info.fd != -1);
	log_assert(r->event.timer.key != 0);
	jhd_event_del_timer(ev);
	r->aio = jhd_aio_get();
	r->aio->aio.aio_data = (uint64_t) ev;
	log_assert(r->aio != NULL);
	http2_send_static_206_response_data_frmae(r);
}

void http2_send_static_206_response_headers_frmae(jhd_http_request *r, jhd_http2_frame *frame) {
	uint16_t len;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	u_char *p, *etag;

	log_assert(r->event.timer.key == 0);
	log_assert(r->file_info.range_start<=r->file_info.range_end);


	stream = r->stream;
	c = stream->connection;
	h2c = c->data;

	frame->type = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->end_header = 1;
	//frame->data = frame;
	frame->data_len = 384;
	frame->free_func = jhd_http2_frame_free_by_single;
	p = ((u_char*) frame) + sizeof(jhd_http2_frame);
	frame->pos = p;
	p += 9;
//status : 206
	*p = 128 + 10;
	++p;
	//server:jhttpd
	*p = 15;
	++p;
	*p = 54 - 15;
	++p;
	*p = 6;
	++p;
	memcpy(p, "jhttpd", 6);
	p += 6;	// (2+1+r->server.len);

	//date
	*p = 15;
	++p;
	*p = 33 - 15;
	++p;
	*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	++p;
	memcpy(p, jhd_cache_http_date, sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	//last-modified
	*p = 15;
	++p;
	*p = 44 - 15;
	++p;
	*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	++p;
	jhd_write_http_time(p, r->file_info.mtime);
	p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);

	//etag
	*p = 15;
	++p;
	*p = 34 - 15;
	++p;
	etag = http_etag_calc(http_etag_buffer + 40, r->file_info.size, r->file_info.mtime);
	len = http_etag_buffer + 40 - etag;
	*p = (u_char) (len);
	++p;
	memcpy(p, etag, len);
	p += len;

	//content_type

	*p = 15;
	++p;
	*p = 31 - 15;
	++p;
	*p = (u_char) r->content_type.len;
	++p;
	memcpy(p, r->content_type.data, r->content_type.len);
	p += r->content_type.len;

	//content_length
	r->content_length = r->file_info.range_end- r->file_info.range_start+1;
	*p = 15;
	++p;
	*p = 28 - 15;
	++p;
	etag = jhd_u64_to_string(http_etag_buffer + 40, (uint64_t) (r->content_length));
	len = http_etag_buffer + 40 - etag;
	*p = (u_char) len;
	++p;
	memcpy(p, etag, len);
	p += len;

	//accept-ranges
	*p = 15;
	++p;
	*p = 18 - 15;
	++p;
	*p = 5;
	++p;
	memcpy(p, "bytes", 5);
	p += 5;


	etag = jhd_u64_to_string(jhd_calc_buffer+100,r->file_info.size);
	--etag;
	*etag= '/';
	--etag;
	etag = jhd_u64_to_string(etag,r->file_info.range_end);
	--etag;
	*etag ='-';
	--etag;
	etag = jhd_u64_to_string(etag,r->file_info.range_start);
	len = jhd_calc_buffer +100 - etag;

	//content-range
	*p = 15;
	++p;
	*p = (u_char)(30 - 15);
	++p;
	*p = (u_char)len;
	++p;
	memcpy(p,etag,len);
	p+=len;

	len = p - frame->pos;
	frame->len = len;
	len -= 9;
	p =frame->pos;
	p[0] = 0;
	p[1] = (u_char)(len >> 8);
	p[2] = (u_char) (len);
	frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG;
	frame->pos[5] = (u_char) (stream->id >> 24);
	frame->pos[6] = (u_char) (stream->id >> 16);
	frame->pos[7] = (u_char) (stream->id >> 8);
	frame->pos[8] = (u_char) (stream->id);
	frame->next = NULL;

	jhd_http2_send_headers_frame(c, h2c, frame, frame);

	r->aio = jhd_aio_get();
	if (r->aio) {
		r->aio->aio.aio_data = (uint64_t) (&r->event);
		http2_send_static_206_response_data_frmae(r);
	} else {
		r->event.handler = http2_static_206_alloc_aio;
		jhd_aio_wait(&r->event);
		jhd_event_add_timer(&r->event, ((jhd_http_static_service_context *) (r->http_service->service_ctx))->wait_aio_timeout,http2_wait_aio_timeout);
		stream->listener = &http2_server_stream_listener_block_with_static_response_alloc_aio;
	}
}



static void http2_alloc_headers_frame_with_206(jhd_event_t *ev) {
	jhd_http2_frame *frame;
	jhd_http_request *r = ev->data;
	log_assert(r->event.timer.key != 0);
	jhd_event_del_timer(&r->event);
	frame = jhd_alloc(384);
	log_assert(frame != NULL);
	http2_send_static_206_response_headers_frmae(r, frame);
}

void jhd_http2_static_request_handler_with_206(jhd_http_request *r) {
	jhd_http2_frame *frame;
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
	//TODO op this value[384]  only include  state  content_length  content_type server date

	frame = jhd_alloc(384);
	if (frame == NULL) {
		r->event.handler = http2_alloc_headers_frame_with_206;
		((jhd_http2_stream*) (r->stream))->listener = &http2_server_stream_listener_at_alloc_header_frame_of_static_response_block;
		jhd_wait_mem(&r->event, 384);
		jhd_event_add_timer(&r->event, r->http_service->mem_timeout, http2_alloc_headers_frame_of_static_response_timeout);
		goto func_free;
	}
	http2_send_static_206_response_headers_frmae(r, frame);
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

