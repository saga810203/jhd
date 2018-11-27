/*
 * jhd_http11_response_send.h
 *
 *  Created on: 2018年11月27日
 *      Author: root
 */

#ifndef HTTP_JHD_HTTP11_RESPONSE_SEND_H_
#define HTTP_JHD_HTTP11_RESPONSE_SEND_H_

void jhd_http11_send_cached_response(jhd_http_request *r,uint16_t state,u_char *body,uint16_t body_len);

#endif /* HTTP_JHD_HTTP11_RESPONSE_SEND_H_ */
