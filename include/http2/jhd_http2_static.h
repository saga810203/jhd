/*
 * jhd_http2_static.h
 *
 *  Created on: 2018年12月2日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_STATIC_H_
#define HTTP2_JHD_HTTP2_STATIC_H_
#include <http/jhd_http_static_service.h>

void jhd_http2_static_request_handle_with_200(jhd_http_request *r);
void jhd_http2_static_request_handle_with_206(jhd_http_request *r);
void jhd_http2_static_request_handle_with_304(jhd_http_request *r);






#endif /* HTTP2_JHD_HTTP2_STATIC_H_ */
