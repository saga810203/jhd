/*
 * jhd_http2_response_send.h
 *
 *  Created on: Nov 23, 2018
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_RESPONSE_SEND_H_
#define HTTP2_JHD_HTTP2_RESPONSE_SEND_H_

#include <http2/jhd_http2_stream_listener.h>




/**
 * raw   data mem point = r->cache_frame.data;
 *
 * raw   next pos = r->payload;
 *
 * raw   len = r->payload_len;
 *
 */
void jhd_http2_stream_send_last_raw_data(jhd_http_request *r);



#endif /* HTTP2_JHD_HTTP2_RESPONSE_SEND_H_ */
