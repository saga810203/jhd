#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <jhd_log.h>
#include <jhd_aio.h>
#include <fcntl.h>

typedef struct {
	uint16_t config_ctx_size;
	void* config_ctx;
	u_char *file_path;
	uint16_t file_path_len;
	//return target_file length;
	uint16_t (*build_target_file)(u_char target_file[8192], void*ctx, jhd_http_request *r);
	size_t *wait_aio_timeout;
} jhd_http_static_service_context;

void http2_stream_send_file_raw_data(jhd_http_request *r);

void http_file_stat(jhd_http_file_info *file_info, u_char* file_loc) {
	time_t now;
	uint32_t hash;
	int64_t rc;
	struct stat fi;
	int fd;
	file_info->fd = -1;
	fd = open((char*) file_loc, O_NONBLOCK | __O_DIRECT);
	if (fd != -1) {
		if (fstat(fd, &fi) == -1) {
			jhd_close(fd);
			return;
		}
		if (S_ISDIR(fi.st_mode)) {
			jhd_close(fd);
			return;
		}
		file_info->size = fi.st_size;
		file_info->mtime = fi.st_mtime;
		file_info->is_file = (S_ISREG(fi.st_mode));
		file_info->is_link = (S_ISLNK(fi.st_mode));
		file_info->is_exec = ((fi.st_mode & S_IXUSR) == S_IXUSR);
		file_info->fd = fd;
	}
}

//static void stream_reset_with_alloc_static_request_headers(jhd_http2_stream *stream){
//	jhd_http_request *r;
//	r = stream->lis_ctx;
//	close(r->file_info->fd);
//	jhd_queue_only_remove(&r->queue);
//	log_assert(r->event.timer.key != 0);
//	jhd_event_del_timer(&r->event);
//	jhd_http_request_free(r);
//}
//
//static jhd_http2_stream_listener server_stream_listener_with_ignore_request_body_alloc_static_headers ={
//		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
//		jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
//		jhd_http2_stream_ignore_listener,
//		stream_reset_with_alloc_static_request_headers,//		jhd_event_handler_pt reset;
//		jhd_http2_stream_ignore_listener,//		jhd_event_handler_pt remote_recv;
//		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
//		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
//};
//void jhd_http2_static_request_headers_alloc_timeout(jhd_event_t *ev){
//		jhd_http_request *r;
//		jhd_http2_stream *stream;
//		jhd_connection_t *c;
//		jhd_http2_connection *h2c;
//		jhd_http2_frame *frame;
//		u_char *p;
//
//		r = ev->data;
//		stream = r->stream;
//		c = stream->connection;
//		h2c = c->data;
//
//		jhd_queue_only_remove(stream->queue);
//		frame = (jhd_http2_frame*)(stream);
//		--h2c->processing;
//		h2c->recv.stream = &jhd_http2_invalid_stream;
//		p = frame->pos = (u_char*)(((u_char*)frame)+sizeof(jhd_http2_frame));
//		frame->type = JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME;
//		frame->data_len = sizeof(jhd_http2_stream);
//		frame->len = 13;
//		frame->free_func = jhd_http2_frame_free_by_single;
//		frame->next = NULL;
//		*((uint32_t*)p) =0x03040000;
//		p[4] = 0;\
//		p[5] = (u_char)((stream->id) >> 24);
//		p[6] = (u_char)((stream->id) >> 16);
//		p[7] = (u_char)((stream->id) >> 8);
//		p[8] = (u_char)(stream->id);
//		p += 9;
//		*((uint32_t*)p) = JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT;
//		jhd_http2_send_queue_frame(c,h2c,frame);
//		jhd_queue_only_remove(&r->event.queue);
//		jhd_http_request_free(r);
//}

static void stream_reset_with_alloc_static_response_headers_frame_block(jhd_http2_stream *stream) {
	jhd_http_request *r;

	r = stream->lis_ctx;
	log_assert(r->event.timer.key != 0);
	jhd_queue_only_remove(&r->event.queue);
	jhd_event_del_timer(&r->event);
	if (r->file_info.fd != -1) {
		jhd_close(r->file_info.fd);
	}
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static jhd_http2_stream_listener server_stream_listener_with_ignore_static_response_alloc_header_frame = {
			jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
			jhd_http2_stream_ignore_data_listener, //		jhd_event_handler_pt remote_data;
			jhd_http2_stream_ignore_listener,
			stream_reset_with_alloc_static_response_headers_frame_block, //		jhd_event_handler_pt reset;
			jhd_http2_stream_ignore_listener, //		jhd_event_handler_pt remote_recv;
			jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
			jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};

static void stream_reset_with_alloc_static_response_aio_block(jhd_http2_stream *stream) {
	jhd_http_request *r;

	r = stream->lis_ctx;

	log_assert(r->event.timer.key != 0);
	log_assert(r->file_info.fd != -1);

	jhd_queue_only_remove(&r->event.queue);
	jhd_event_del_timer(&r->event);
	jhd_close(r->file_info.fd);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static jhd_http2_stream_listener server_stream_listener_block_with_static_response_alloc_aio = { jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
                jhd_http2_stream_ignore_data_listener, //		jhd_event_handler_pt remote_data;
                jhd_http2_stream_ignore_listener, stream_reset_with_alloc_static_response_aio_block, //		jhd_event_handler_pt reset;
                jhd_http2_stream_ignore_listener, //		jhd_event_handler_pt remote_recv;
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                };

static void stream_reset_with_alloc_static_response_data_buffer_block(jhd_http2_stream *stream) {
	jhd_http_request *r;

	r = stream->lis_ctx;
	log_assert(r->event.timer.key != 0);
	log_assert(r->file_info.fd != -1);
	log_assert(r->aio != NULL);

	jhd_queue_only_remove(&r->event.queue);
	jhd_event_del_timer(&r->event);
	jhd_close(r->file_info.fd);
	jhd_aio_free(r->aio);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static jhd_http2_stream_listener server_stream_listener_block_with_static_response_alloc_data_buffer = { jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
                jhd_http2_stream_ignore_data_listener, //		jhd_event_handler_pt remote_data;
                jhd_http2_stream_ignore_listener, stream_reset_with_alloc_static_response_data_buffer_block, //		jhd_event_handler_pt reset;
                jhd_http2_stream_ignore_listener, //		jhd_event_handler_pt remote_recv;
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                };
static void http2_stream_reset_with_alloc_static_response_headers_frame_timeout(jhd_event_t *ev) {
	jhd_http_request *r = ev->data;
	jhd_queue_only_remove(&r->event.queue);
	jhd_http2_reset_stream_by_request(r, JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
	if (r->file_info.fd != -1) {
		jhd_close(r->file_info.fd);
	}
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static void http2_static_200_wait_aio_timeout(jhd_event_t *ev) {
	jhd_http_request *r = ev->data;

	jhd_queue_only_remove(&r->event.queue);
	jhd_http2_reset_stream_by_request(r, JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);

	log_assert(r->file_info.fd != -1);
	jhd_close(r->file_info.fd);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static void http2_static_200_wait_data_buffer_timeout(jhd_event_t *ev) {
	jhd_http_request *r = ev->data;

	jhd_queue_only_remove(&r->event.queue);
	jhd_http2_reset_stream_by_request(r, JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);

	log_assert(r->file_info.fd != -1);
	jhd_close(r->file_info.fd);
	jhd_aio_free(r->aio);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static void http2_static_aio_timeout(jhd_event_t *ev) {
	jhd_http_request *r;
	r = ev->data;
	jhd_http2_reset_stream_by_request(r,
	JHD_HTTP2_INTERNAL_ERROR_READ_FILE_TIMEOUT);
	jhd_close(r->file_info.fd);
	jhd_aio_free(r->aio);
	jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static void http2_stream_reset_with_free_aio_request(jhd_http2_stream *stream) {
	jhd_http_request *r;
	r = stream->lis_ctx;
	jhd_aio_free(r->aio);
	jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
	jhd_close(r->file_info.fd);
	jhd_aio_free(r->aio);
	jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static void stream_listener_by_remote_recv_send_file_raw(jhd_http2_stream *stream) {
	jhd_http_request *r;
	r = stream->lis_ctx;
	http2_stream_send_file_raw_data(r);
}
static void stream_listener_by_rsend_window_change_send_file_raw(jhd_http2_stream *stream) {
	jhd_http_request *r;
	r = stream->lis_ctx;
	http2_stream_send_file_raw_data(r);
}

static jhd_http2_stream_listener server_send_staic_response_with_flow_control_and_not_in_send_queue = { jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
                jhd_http2_stream_ignore_data_listener,	//		jhd_event_handler_pt remote_data;
                jhd_http2_stream_ignore_listener,    //	    remote_empty_data;
                http2_stream_reset_with_free_aio_request, //		    jhd_event_handler_pt reset;
                stream_listener_by_remote_recv_send_file_raw, //		jhd_event_handler_pt remote_recv;
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                stream_listener_by_rsend_window_change_send_file_raw, };

static void http2_stream_file_raw_sent_wait_flow_control(jhd_http2_frame *frame) {
	jhd_http_request *r;
	jhd_http2_stream *stream;
	r = (jhd_http_request*) (((u_char*) frame) - offsetof(jhd_http_request, cache_frame));
	stream = r->stream;
	stream->listener = server_send_staic_response_with_flow_control_and_not_in_send_queue;
}
static void http2_stream_file_raw_sent_wait_flow_control(jhd_http2_frame *frame) {
	jhd_http_request *r;
	jhd_http2_stream *stream;
	r = (jhd_http_request*) (((u_char*) frame) - offsetof(jhd_http_request, cache_frame));
	stream = r->stream;
	stream->listener = server_send_staic_response_with_flow_control_and_not_in_send_queue;
}

static void http_stream_reset_with_change_cache_frame_free_func(jhd_http2_stream *stream) {
	jhd_http_request *r;
	r = stream->lis_ctx;
	r->cache_frame.free_func = jhd_http2_free_request_and_cache_data_with_cache_frame_free;
	jhd_aio_free(r->aio);
}
static void http2_stream_send_next_file_fragmentation_with_cache_frame_free_func(void *frame) {
	http2_stream_send_file_raw_data((jhd_http_request *) (((u_char *) frame) - offsetof(jhd_http_request, cache_frame)));
}

static void stream_listener_change_cache_frame_free_func_with_in_send_queue(jhd_http2_stream *stream) {
	log_assert(jhd_queue_queued(&stream->flow_control));
	jhd_queue_remove(&stream->flow_control);
	((jhd_http_request *) (stream->lis_ctx))->cache_frame.free_func = http2_stream_send_next_file_fragmentation_with_cache_frame_free_func;
}

static jhd_http2_stream_listener server_send_staic_response_with_flow_control_and_in_send_queue = { jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
                jhd_http2_stream_ignore_data_listener,	//		jhd_event_handler_pt remote_data;
                jhd_http2_stream_ignore_listener,    //	    remote_empty_data;
                http_stream_reset_with_change_cache_frame_free_func, //		    jhd_event_handler_pt reset;
                stream_listener_change_cache_frame_free_func_with_in_send_queue, //		jhd_event_handler_pt remote_recv;
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                stream_listener_change_cache_frame_free_func_with_in_send_queue, };

static jhd_http2_stream_listener server_send_staic_response_in_send_queue = { jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
                jhd_http2_stream_ignore_data_listener, //		jhd_event_handler_pt remote_data;
                jhd_http2_stream_ignore_listener,      //	    remote_empty_data;
                http_stream_reset_with_change_cache_frame_free_func, //		    jhd_event_handler_pt reset;
                jhd_http2_stream_ignore_listener, //		jhd_event_handler_pt remote_recv;
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                jhd_http2_stream_ignore_listener, };

static void http2_stream_read_next_file_part_with_cache_frame_free(void *frame) {
	jhd_http_request *r;
	jhd_http2_stream *stream;
	size_t len;
	r = (jhd_http_request*) (((u_char*) frame) - offsetof(jhd_http_request, cache_frame));
	stream = r->stream;

	r->payload = r->cache_frame.data + 9;
	r->aio->aio.aio_offset += r->aio->result;
	len = r->cache_frame.data_len - 9;
	if (r->static_file_size <= len) {
		r->aio->aio.aio_nbytes = r->static_file_size;
		r->event->handler = http2_static_aio_read_over;
		stream->listener = server_stream_listener_block_with_static_response_aio_read;
	} else {
		r->aio->aio.aio_nbytes = len;
		r->static_file_size -= len;
		r->event->handler = http2_static_aio_read_compele;
		stream->listener = server_stream_listener_block_with_static_response_aio_read;
	}
	r->event->timeout = http2_static_aio_timeout;
	jhd_aio_submit(r->aio);
}

void http2_stream_send_file_raw_data(jhd_http_request *r) {
	jhd_http2_frame *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	int size;
	u_char *p;

	stream = r->stream;
	c = stream->connection;
	h2c = c->data;
	frame = &r->cache_frame;

	log_assert(frame->data != NULL);
	log_assert(r->payload != NULL);
	log_assert(frame->data > (r->payload + 9));
	log_assert((frame->data - r->payload) < (16384 + 9));

	log_assert(r->payload_len > 0);
	log_assert(r->payload_len < 16384);
	log_assert(frame->data_len >= (r->payload_len + 9));

	size = stream->send_window_size;
	if (size > h2c->send.window_size) {
		size = h2c->send.window_size;
	}

	if (size < 1) {
		jhd_queue_insert_tail(&h2c->flow_control, &stream->flow_control);
		stream->listener = &server_send_staic_response_with_flow_control_and_not_in_send_queue;
	} else if (size < ((int) r->payload_len)) {
		jhd_queue_insert_tail(&h2c->flow_control, &stream->flow_control);
		h2c->send.window_size -= size;
		stream->send_window_size -= size;
		frame->pos = r->payload;
		frame->len = size + 9;
		p = r->payload - 9;

		r->payload += (uint32_t) size;
		r->payload -= (uint32_t) size;

		p[0] = 0;
		p[1] = ((u_char) (size >> 8));
		p[2] = ((u_char) (size));
//		p[3] = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;
		p[4] = 0;
		p += 5;
		jhd_http2_set_stream_id(p, stream->id);
		frame->next = NULL;
		frame->free_func = http2_stream_file_raw_sent_wait_flow_control;
		jhd_http2_send_queue_frame(c, h2c, frame);
		stream->listener = &server_send_staic_response_with_flow_control_and_in_send_queue;
	} else {
		h2c->send.window_size -= ((int) r->payload_len);
		stream->send_window_size -= ((int) r->payload_len);
		stream->listener = &server_send_staic_response_in_send_queue;
		frame->free_func = http2_stream_read_next_file_part_with_cache_frame_free;
		frame->pos = r->payload;
		frame->len = (((int) r->payload_len + 9));
		p = r->payload - 9;
		p[0] = 0;
		p[1] = ((u_char) (size >> 8));
		p[2] = ((u_char) (size));
//		p[3] = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;
		p[4] = JHD_HTTP2_END_STREAM_FLAG;
		p += 5;
		jhd_http2_set_stream_id(p, stream->id);
		frame->next = NULL;
		jhd_http2_send_queue_frame(c, h2c, frame);
	}
}
static void http2_static_aio_read_compele(jhd_event_t *ev) {
	jhd_http_request *r;
	jhd_aio_cb *aio;
	r = ev->data;
	jhd_close(r->file_info.fd);
	if (r->aio->result != r->aio->aio.aio_nbytes) {
		jhd_http2_reset_stream_by_request(r,
		JHD_HTTP2_INTERNAL_ERROR_READ_FILE_TIMEOUT);
		jhd_aio_free(r->aio);
		jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
		jhd_free_with_size(r, sizeof(jhd_http_request));
	} else {
		r->payload_len = (uint32_t) (r->aio->result);
		http2_stream_send_file_raw_data(r);
	}
}

static void http2_static_aio_read_over(jhd_event_t *ev) {
	jhd_http_request *r;
	jhd_aio_cb *aio;
	r = ev->data;
	jhd_close(r->file_info.fd);
	if (r->aio->result != r->aio->aio.aio_nbytes) {
		jhd_http2_reset_stream_by_request(r,
		JHD_HTTP2_INTERNAL_ERROR_READ_FILE_TIMEOUT);
		jhd_aio_free(r->aio);
		jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
		jhd_free_with_size(r, sizeof(jhd_http_request));
	} else {
		r->payload_len = (uint32_t) (r->aio->result);
		aio = r->aio;
		jhd_http2_stream_send_last_raw_data(r);
		jhd_aio_free(aio);
	}
}

void http2_stream_reset_befor_aio_read_compele(jhd_event_t *ev) {
	jhd_http_request *r;
	r = ev->data;
	jhd_close(r->file_info.fd);
	jhd_aio_free(r->aio);
	jhd_free_with_size(r->cache_frame.data, r->cache_frame.data_len);
	jhd_free_with_size(r, sizeof(jhd_http_request));
}

static void stream_reset_with_aio_read_block(jhd_http2_stream *stream) {
	jhd_http_request *r;
	r = stream->lis_ctx;
	r->event.handler = http2_stream_reset_befor_aio_read_compele;
	r->event.timeout = http2_stream_reset_befor_aio_read_compele;
}

static jhd_http2_stream_listener server_stream_listener_block_with_static_response_aio_read = { jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt remote_close;
                jhd_http2_stream_ignore_data_listener, //		jhd_event_handler_pt remote_data;
                jhd_http2_stream_ignore_listener, stream_reset_with_aio_read_block, //		jhd_event_handler_pt reset;
                jhd_http2_stream_ignore_listener, //		jhd_event_handler_pt remote_recv;
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                jhd_http2_stream_ignore_listener, //	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
                };

void http2_static_200_response_start_read(jhd_http_request *r) {
	size_t len;
	jhd_http2_stream *stream;
	r->payload = r->aio->aio.aio_buf = (uint64_t) (r->cache_frame.data + 9);
	r->aio->aio.aio_offset = 0;
	len = r->cache_frame.data_len - 9;
	stream = r->stream;

	if (len <= r->static_file_size) {
		r->aio->aio.aio_nbytes = r->static_file_size;
		r->event->handler = http2_static_aio_read_over;
		stream->listener = server_stream_listener_block_with_static_response_aio_read;
	} else {
		r->aio->aio.aio_nbytes = len;
		r->static_file_size -= len;
		r->event->handler = http2_static_aio_read_compele;
		stream->listener = server_stream_listener_block_with_static_response_aio_read;
	}
	r->event->timeout = http2_static_aio_timeout;
	jhd_aio_submit(r->aio);
}

void http2_send_static_200_response_alloc_data_buffer(jhd_event_t *ev) {
	jhd_http_request *r;

	r = ev->data;

	log_assert(r->event.timer.key != 0);
	jhd_event_del_timer(ev);

	r->cache_frame.data = jhd_alloc(r->cache_frame.data_len);
	log_assert(r->cache_frame.data != NULL);
	http2_static_200_response_start_read(r);

}

void http2_send_static_200_response_data_frmae(jhd_http_request *r) {
	size_t size;
	jhd_http2_stream *stream;

	size = r->static_file_size = r->file_info->size;
	r->aio->aio.aio_fildes = r->file_info.fd;
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
		http2_static_200_response_start_read(r);
	} else {
		r->event.handler = http2_send_static_200_response_alloc_data_buffer;
		jhd_wait_mem(&r->event, r->cache_frame.data_len + 9);
		jhd_event_add_timer(&r->event, r->http_service->mem_timeout, http2_static_200_wait_data_buffer_timeout);
		stream = r->stream;
		stream->listener = &server_stream_listener_block_with_static_response_alloc_data_buffer;
	}
}

static void http2_static_200_alloc_aio(jhd_event_t *ev) {
	jhd_http_request *r = ev->data;
	log_assert(r->file_info.fd != -1);
	log_assert(r->event.timer.key != 0);

	jhd_event_del_timer(ev);

	r->aio = jhd_aio_get();
	r->aio->aio.aio_data = (uint64_t) ev;
	log_assert(r->aio != NULL);

	http2_send_static_200_response_data_frmae(r);
}

static u_char http_etag_buffer[41];
void http2_send_static_200_response_headers_frmae(jhd_http_request *r, jhd_http2_frame *frame) {
	uint16_t len;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	u_char *p, *etag;

	log_assert(r->event.timer.key == 0);

	stream = r->stream;
	c = stream->connection;
	h2c = c->data;

	frame->type = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->end_header = 1;
	//frame->data = frame;
	frame->data_len = 256;
	frame->free_func = jhd_http2_frame_free_by_single;
	p = ((u_char*) frame) + sizeof(jhd_http2_frame);
	frame->pos = p;
	p += 9;
//status : 200
	*p = 128 + 8;
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
	jhd_write_http_time(p, r->file_info->mtime);
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
	*p = 15;
	++p;
	*p = 28 - 15;
	++p;

	etag = jhd_u64_to_string(http_etag_buffer + 40, (uint64_t) ((r->file_info.size)));
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

	len = p - frame->pos;
	frame->len = len;
	len -= 9;
	frame->pos[0] = 0;
	frame->pos[1] = 0;
	frame->pos[2] = (u_char) (len);
	frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG;

	frame->pos[5] = (u_char) (stream->id >> 24);
	frame->pos[6] = (u_char) (stream->id >> 16);
	frame->pos[7] = (u_char) (stream->id >> 8);
	frame->pos[8] = (u_char) (stream->id);
	frame->next = NULL;

	jhd_http2_send_headers_frame(c, h2c, frame, frame);
	if ((r->file_info.size == 0) || (r->method == JHD_HTTP_METHOD_HEAD)) {
		frame->pos[4] |= JHD_HTTP2_END_STREAM_FLAG;
		jhd_queue_only_remove(stream->queue);
		--h2c->processing;
		jhd_free_with_size(stream, sizeof(jhd_http2_stream));
		jhd_close(r->file_info.fd);
		jhd_free_with_size(r, sizeof(jhd_http_request));
	} else {
		r->aio = jhd_aio_get();
		if (r->aio) {
			r->aio->aio.aio_data = (uint64_t) (&r->event);
			http2_send_static_200_response_data_frmae(r);
		} else {
			r->event->handler = http2_static_200_alloc_aio;
			jhd_aio_wait(&r->event);
			jhd_event_add_timer(&r->event, ((jhd_http_static_service_context *) (r->http_service->service_ctx))->wait_aio_timeout,
			                http2_static_200_wait_aio_timeout);
			stream->listener = server_stream_listener_block_with_static_response_alloc_aio;
		}
	}
}

void http2_send_static_range_response_headers_frmae(jhd_http_request *r, jhd_http2_frame *frame) {
	uint16_t len;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	u_char *p, *etag,*end;

	log_assert(r->event.timer.key == 0);


	log_assert(r->file_info.range_start<=r->file_info.range_end);






	stream = r->stream;
	c = stream->connection;
	h2c = c->data;

	frame->type = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->end_header = 1;
	//frame->data = frame;
	frame->data_len = 256;
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
	jhd_write_http_time(p, r->file_info->mtime);
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
	++p
	*p = 30 -15;
	++p;
	*p = (u_char)len;
	++p;
	memcpy(p,etag,len);
	p+=len;

	len = p - frame->pos;
	frame->len = len;
	len -= 9;
	frame->pos[0] = 0;
	frame->pos[1] = 0;
	frame->pos[2] = (u_char) (len);
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
		http2_send_static_200_response_data_frmae(r);
	} else {
		r->event->handler = http2_static_200_alloc_aio;
		jhd_aio_wait(&r->event);
		jhd_event_add_timer(&r->event, ((jhd_http_static_service_context *) (r->http_service->service_ctx))->wait_aio_timeout,
						http2_static_200_wait_aio_timeout);
		stream->listener = server_stream_listener_block_with_static_response_alloc_aio;
	}
}



static void http2_static_response_200_alloc_headers_frame(jhd_event_t *ev) {
	jhd_http2_frame *frame;
	jhd_http_request *r = ev->data;

	log_assert(r->event.timer.key != 0);

	frame = jhd_alloc(256);
	if (frame) {
		jhd_event_del_timer(&r->event);
		http2_send_static_200_response_headers_frmae(r, frame);
	} else {
		jhd_wait_mem(&r->event, 256);
		jhd_event_add_timer(ev, r->http_service->mem_timeout, http2_stream_reset_with_alloc_static_response_headers_frame_timeout);
	}
}
static void http2_static_response_range_alloc_headers_frame(jhd_event_t *ev) {
	jhd_http2_frame *frame;
	jhd_http_request *r = ev->data;

	log_assert(r->event.timer.key != 0);

	frame = jhd_alloc(256);
	if (frame) {
		jhd_event_del_timer(&r->event);
		http2_send_static_range_response_headers_frmae(r, frame);
	} else {
		jhd_wait_mem(&r->event, 256);
		jhd_event_add_timer(ev, r->http_service->mem_timeout, http2_stream_reset_with_alloc_static_response_headers_frame_timeout);
	}
}
void jhd_http_static_request_out_with_range_by_http2(jhd_http_request *r) {
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
		r->event.handler = http2_static_response_range_alloc_headers_frame;
		((jhd_http2_stream*) (r->stream))->listener = &server_stream_listener_with_ignore_static_response_alloc_header_frame;
		jhd_wait_mem(&r->event, 256);
		jhd_event_add_timer(&r->event, r->http_service->mem_timeout, http2_stream_reset_with_alloc_static_response_headers_frame_timeout);
		goto func_free;
	}
	http2_send_static_range_response_headers_frmae(r, frame);
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


void jhd_http_static_request_out_with_200_by_http2(jhd_http_request *r) {
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
		r->event.handler = http2_static_response_200_alloc_headers_frame;
		((jhd_http2_stream*) (r->stream))->listener = &server_stream_listener_with_ignore_static_response_alloc_header_frame;
		jhd_wait_mem(&r->event, 256);
		jhd_event_add_timer(&r->event, r->http_service->mem_timeout, http2_stream_reset_with_alloc_static_response_headers_frame_timeout);
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

void jhd_http_static_request_out_with_range(jhd_http_request *r) {
	if (r->is_http2) {
		jhd_http_static_request_out_with_range_by_http2(r);
	} else {
		//TODO impl
	}

}

void jhd_http_static_request_out_with_200(jhd_http_request *r) {
	if (r->is_http2) {
		jhd_http_static_request_out_with_200_by_http2(r);
	} else {
		//TODO impl
	}
}

void jhd_http_static_request_headers_out(jhd_http_request *r) {
	jhd_http_header *header;
	jhd_queue_t *head, *q, *hq, h;
	jhd_http_header *if_modified_since;
	jhd_http_header *if_none_match;
	jhd_http_header *range;
	jhd_http_header *if_range;
	u_char *etag, *p, *end, c;
	size_t etag_len;
	time_t iums;

	etag = http_etag_calc(http_etag_buffer + 40, r->file_info.size, r->file_info.mtime);
	etag_len = http_etag_buffer + 40 - etag;

	if_modified_since = NULL;
	if_none_match = NULL;
	if_range = NULL;
	range = NULL;

	head = &r->headers;

	jhd_queue_init(&h);

	for (q = jhd_queue_next(head); q != head;) {
		header = jhd_queue_data(q, jhd_http_header, queue);
		hq = q;
		q = jhd_queue_next(q);
		jhd_queue_only_remove(hq);
		if ((header->name_len == 8) && (memcmp(header->name, "if-range")) == 0) {
			if (if_range) {
				jhd_queue_insert_tail(&h, hq);
				goto func_error;
			} else {
				if_range = header;
			}
		} else if (header->name_len == 17) {
			if (memcmp(header->name, "if-modified-since") == 0) {
				if (if_modified_since) {
					jhd_queue_insert_tail(&h, hq);
					goto func_error;
				} else {
					if_modified_since = header;
				}
			} else {
				jhd_queue_insert_tail(&h, hq);
			}
		} else if (header->name_len == 13) {
			if (memcmp(header->name, "if-none-match") == 0) {
				if (if_none_match) {
					jhd_queue_insert_tail(&h, hq);
					goto func_error;
				} else {
					if_none_match = header;
				}
			} else {
				jhd_queue_insert_tail(&h, hq);
			}
		} else if (header->name_len == 6) {
			if (memcmp(header->name, "range") == 0) {
				if (range) {
					jhd_queue_insert_tail(&h, hq);
					goto func_error;
				} else {
					range = header;
				}
			} else {
				jhd_queue_insert_tail(&h, hq);
			}
		} else {
			jhd_queue_insert_tail(&h, hq);
		}
	}

	if (if_none_match) {
		if (if_none_match->value_len == etag_len && (0 == memcmp(etag, if_none_match->value, etag_len))) {
			jhd_close(r->file_info->fd);
			r->file_info->fd = -1;
			log_assert(jhd_queue_empty(&r->headers));
			jhd_http_request_handle_with_not_modified(r);
			goto func_free;
		}
	} else if (if_modified_since) {
		iums = jhd_parse_http_time(if_modified_since->value, if_modified_since->value_len);
		if (iums == r->file_info->mtime) {
			jhd_close(r->file_info->fd);
			r->file_info->fd = -1;
			log_assert(jhd_queue_empty(&r->headers));
			jhd_http_request_handle_with_not_modified(r);
			goto func_free;
		}
	}

	if (r->file_info.size == 0) {
		jhd_http_static_request_out_with_200(r);
		goto func_free;
	}

	if (range && range->value_len > 7 && (0 == memcmp(range->value, "bytes=", 6))) {
		if (if_range) {
			if (if_range->value_len >= 2 && if_range->value[if_range->value_len - 1] == '"') {
				if ((if_range->value_len != etag_len) || (0 != memcmp(etag, if_range->value, etag_len))) {
					jhd_http_static_request_out_with_200(r);
					goto func_free;
				}
			}
			iums = jhd_parse_http_time(if_range->value, if_range->value_len);
			if (iums != r->file_info.mtime) {
				jhd_http_static_request_out_with_200(r);
				goto func_free;
			}
		}
		r->file_info.range_start = -1;
		r->file_info.range_end = -1;
		p = range->value + 6;
		end = range->value + range->value_len;
		while ((*p == ' ') && (p < end)) {
			++p;
		}
		if (p < end) {
			c = *p;
			++p;
			if (c < '0' || c > '9') {
				jhd_close(r->file_info->fd);
				r->file_info->fd = -1;
				//TODO impl 416 Requested Range Not Satisfiable
				jhd_http_request_handle_with_bad(r);
				goto func_free;
			}
			r->file_info.range_start = c - '0';
			if (p == end) {
				goto func_416;
			}
			do {
				c = *p;
				++p;
				if (c >= '0' && c <= '9') {
					if (r->file_info.range_start >= (0x7FFFFFFFFFFFFFFFLL / 10)) {
						goto func_416;
					}
					r->file_info.range_start = c - '0' + (r->file_info.range_start * 10);
				} else if (c == ' ') {
					break;
				} else if (c == '-') {
					goto parse_range_end;
				} else {
					goto func_416;
				}
			} while (p < end);
			if (p == end) {
				goto func_416;
			}
			while ((*p == ' ') && (p < end)) {
				++p;
			}
			if (p < end) {
				if (*p == '-') {
					++p;
					goto parse_range_end;
				} else {
					goto func_416;
				}
			} else {
				goto func_416;
			}
			parse_range_end: while ((*p == ' ') && (p < end)) {
				++p;
			}
			if (p == end) {
				//TODO file size > 0x7FFFFFFFFFFFFFFFULL     ????????????????????
				r->file_info.range_end = r->file_info.size - 1;
			} else {
				c = *p;
				++p;
				if (c == ',') {
					goto func_200;
				} else if (c == '\0' && p == end) {
					//TODO
					r->file_info.range_end = r->file_info.size - 1;
				} else if (c >= '0' || c <= '9') {
					r->file_info.range_end = c - '0';
					if (p < end) {
						do {
							c = *p;
							++p;
							if (c >= '0' || c <= '9') {
								if (r->file_info.range_end >= (0x7FFFFFFFFFFFFFFFLL / 10)) {
									goto func_416;
								}
								r->file_info.range_end = c - '0' + (r->file_info.range_end * 10);
							} else {
								break;
							}
						} while (p < end);
						if (p < end) {
							do {
								c = *p;
								++p;
								if (c != ' ' && c != '\0') {
									break;
								}
							} while (p < end);
							if (p == end) {
								goto func_200;
							}
						}
					}
				} else {
					goto func_200;
				}
			}
		}

		if (r->file_info.range_start >= r->file_info.range_end) {
			goto func_416;
		}
		jhd_http_static_request_out_with_range(r);
		goto func_free;
	}
func_200:
	jhd_http_static_request_out_with_200(r);
	goto func_free;
func_416:
	jhd_close(r->file_info->fd);
	r->file_info->fd = -1;
	//TODO impl 416 Requested Range Not Satisfiable
	jhd_http_request_handle_with_bad(r);
	goto func_free;

func_error:
	jhd_close(r->file_info->fd);
	r->file_info->fd = -1;
	if (jhd_queue_has_item(&r->headers)) {
		jhd_queue_merge(&h, &r->headers);
		jhd_queue_init(&r->headers);
	}
	jhd_http_request_handle_with_bad(r);
func_free:
	if (if_modified_since) {
		jhd_http_free_header(if_modified_since);
	}
	if (if_none_match) {
		jhd_http_free_header(if_none_match);
	}
	if (if_range) {
		jhd_http_free_header(if_range);
	}
	if (range) {
		jhd_http_free_header(range);
	}
	head = &h;
	for (q = jhd_queue_next(head); q != head;) {
		header = jhd_queue_data(q, jhd_http_header, queue);
		q = jhd_queue_next(q);
		jhd_http_free_header(header);
	}
}

void jhd_http_static_request_handler(jhd_http_request *r) {
	jhd_http_static_service_context *ctx;
	u_char file_loc[8192];
	uint16_t len, idx;
	u_char *req_content_type;
	uint16_t req_content_type_len;

	if (r->method == JHD_HTTP_METHOD_GET || r->method == JHD_HTTP_METHOD_HEAD) {
		ctx = r->http_service->service_ctx;
		len = ctx->build_target_file(file_loc, ctx, r);
		http_file_stat(file_loc, &r->file_info);
		if (r->file_info.fd != -1) {
			if (r->content_type.alloced) {
				req_content_type = r->content_type.data;
				req_content_type_len = r->content_type.alloced;
				r->content_type.alloced = 0;
			} else {
				req_content_type_len = 0;
			}
			idx = len - 1;
			log_assert(file_loc[0] == '/');
			log_assert(file_loc[idx] != '.');
			for (;;) {
				if (file_loc[idx] == '.') {
					++idx;
					jhd_http_content_type_get(file_loc + idx, len - idx, &r->content_type.data, &r->content_type.len);
					break;
				} else if (file_loc[idx] == '/') {
					r->content_type.data = default_http_content_type;
					r->content_type.len = default_http_content_type_len;
					break;
				}
				--idx;
			}
			jhd_http_static_request_headers_out(r);
			if (req_content_type_len) {
				jhd_free_with_size(req_content_type, req_content_type_len);
			}
		} else {
			jhd_http_request_handle_with_nofound(r);
		}
	} else if (r->method == JHD_HTTP_METHOD_OPTIONS) {
		//TODO
		jhd_http_request_handle_with_bad(r);
	} else {
		jhd_http_request_handle_with_bad(r);
	}

}

