/*
 * jhd_http2_server.h
 *
 *  Created on: 2018年10月27日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_SERVER_H_
#define HTTP2_JHD_HTTP2_SERVER_H_
#include <http2/jhd_http2.h>

void jhd_http2_only_by_clean_server_connection_start(jhd_connection_t *c);
void jhd_http2_only_by_tls_server_connection_start(jhd_connection_t *c);
void jhd_http2_with_alpn_server_connection_start(jhd_connection_t *c);


#endif /* HTTP2_JHD_HTTP2_SERVER_H_ */
