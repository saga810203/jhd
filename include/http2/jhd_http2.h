/*
 * jhd_http2.h
 *
 *  Created on: 2018年10月24日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_H_
#define HTTP2_JHD_HTTP2_H_
#include <jhd_config.h>



void jhd_http2_only_by_clean_start(jhd_connection_t *c);
void jhd_http2_only_by_tls_start(jhd_connection_t *c);
void jhd_http2_with_alpn_start(jhd_connection_t *c);

extern jhd_http_core_request_info  jhd_http2_info;

#endif /* HTTP2_JHD_HTTP2_H_ */
