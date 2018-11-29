
#ifndef JHD_HTTP2_STREAM_LISTENER_H_
#define JHD_HTTP2_STREAM_LISTENER_H_

#include <http2/jhd_http2.h>






void jhd_http2_stream_invlid_listener(jhd_http2_stream *stream);

void jhd_http2_stream_ignore_listener(jhd_http2_stream *stream);

void jhd_http2_stream_ignore_data_listener(jhd_http2_stream *stream,jhd_http2_frame *frame);
void jhd_http2_stream_invalid_data_listener(jhd_http2_stream *stream,jhd_http2_frame *frame);


void jhd_http2_stream_listener_by_rest_with_direct_free_request(jhd_http2_stream *stream);

void jhd_http2_stream_listener_by_rest_with_direct_free_request_and_cache_frame_data(jhd_http2_stream *stream);
















#endif
