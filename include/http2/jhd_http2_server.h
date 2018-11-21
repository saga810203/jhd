/*
 * jhd_http2_server.h
 *
 *  Created on: 2018年10月27日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_SERVER_H_
#define HTTP2_JHD_HTTP2_SERVER_H_
#include <http2/jhd_http2.h>









void jhd_http2_server_send_event_handler_with_ssl_clean_force(jhd_event_t *ev);
void jhd_http2_server_send_event_handler_with_ssl_clean_by_timer(jhd_event_t *ev);
void jhd_http2_server_send_event_handler_with_ssl_clean_by_trigger(jhd_event_t *ev);



void jhd_http2_only_by_clean_server_connection_start(jhd_connection_t *c);
void jhd_http2_only_by_tls_server_connection_start(jhd_connection_t *c);
void jhd_http2_with_alpn_server_connection_start(jhd_connection_t *c);






void jhd_http2_server_connection_read_event_error_with_clean_force(jhd_event_t *ev);

void jhd_http2_server_ssl_connection_read_event_error_with_timer_clean(jhd_event_t *ev);

void jhd_http2_server_ssl_connection_read_event_error_with_writer_clean(jhd_event_t *ev);










jhd_http2_stream_listener server_stream_first_listener;


#endif /* HTTP2_JHD_HTTP2_SERVER_H_ */
