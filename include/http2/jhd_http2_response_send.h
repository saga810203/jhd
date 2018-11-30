/*
 * jhd_http2_response_send.h
 *
 *  Created on: Nov 23, 2018
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_RESPONSE_SEND_H_
#define HTTP2_JHD_HTTP2_RESPONSE_SEND_H_

#include <http2/jhd_http2_stream_listener.h>



jhd_inline static void jhd_http2_reset_stream_by_request(jhd_http_request *r,uint32_t err_code){
	jhd_http2_frame *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	u_char *p;

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

	*((uint32_t*)p) = err_code;

	jhd_http2_send_queue_frame(c,h2c,frame);
}



/**
 * raw   data mem point = r->cache_frame.data;
 *
 * raw   next pos = r->payload;
 *
 * raw   len = r->payload_len;
 *
 */
void jhd_http2_stream_send_last_raw_data(jhd_http_request *r);
void jhd_http2_send_cached_response(jhd_http_request *r,uint16_t state,u_char *body,uint16_t body_len);
void jhd_http2_send_not_modified_response(jhd_http_request *r);

void jhd_http2_free_request_and_cache_data_with_cache_frame_free(jhd_http2_frame *frame);





#endif /* HTTP2_JHD_HTTP2_RESPONSE_SEND_H_ */
