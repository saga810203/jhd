/*
 * jhd_http2_static.h
 *
 *  Created on: 2018年12月2日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_STATIC_H_
#define HTTP2_JHD_HTTP2_STATIC_H_
#include <http/jhd_http_static_service.h>
#include <http2/jhd_http2.h>

void http2_wait_aio_timeout(jhd_event_t *ev);
void http2_wait_file_data_buffer_timeout(jhd_event_t *ev);
void http2_static_aio_read_timeout(jhd_event_t *ev);
void http2_stream_send_file_raw_data(jhd_http_request *r);
void http2_alloc_headers_frame_of_static_response_timeout(jhd_event_t *ev);


void http2_static_aio_read_compele(jhd_event_t *ev) ;
void http2_static_aio_read_over(jhd_event_t *ev);


void jhd_http2_static_request_handle_with_200(jhd_http_request *r);
void jhd_http2_static_request_handle_with_206(jhd_http_request *r);
void jhd_http2_static_request_handle_with_304(jhd_http_request *r);






extern jhd_http2_stream_listener http2_server_stream_listener_at_alloc_header_frame_of_static_response_block;
extern jhd_http2_stream_listener http2_server_stream_listener_block_with_static_response_alloc_aio;
extern jhd_http2_stream_listener http2_server_stream_listener_block_with_static_response_alloc_data_buffer;
extern jhd_http2_stream_listener http2_server_stream_listener_block_with_static_response_aio_read;
#endif /* HTTP2_JHD_HTTP2_STATIC_H_ */
