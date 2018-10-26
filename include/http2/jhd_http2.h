/*
 * jhd_http2.h
 *
 *  Created on: 2018年10月24日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_H_
#define HTTP2_JHD_HTTP2_H_
#include <jhd_config.h>




typedef struct {
	uint32_t idle_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;


	uint16_t recv_buffer_size;


	void *extend_param;
}jhd_http2_connection_conf;

typedef struct {
	jhd_http2_connection_conf   h2_conf;
	jhd_http11_connection_conf  h11_conf;
} jhd_listening_config_ctx_with_alpn;



typedef struct{
		uint32_t state;
		u_char *buffer;
		u_char *pos;
		u_char *end;
}jhd_http2_conneciton_recv_part;
typedef struct{
		uint32_t state;
		u_char *recv_buffer;
		u_char *recv_pos;
		u_char *recv_end;
}jhd_http2_conneciton_send_part;


typedef struct {


	jhd_http2_connection_conf *conf;
	void *data;
	jhd_http2_conneciton_recv_part recv;
	jhd_http2_conneciton_send_part send;


//	uint8_t processing;
//	size_t headers_table_size;
//	size_t init_window;
//	size_t frame_size;
//	ngx_pool_t *pool;
//	ngx_uint_t next_sid;
//
//		ngx_http2_connection_recv_part_t recv;
//		ngx_http2_connection_send_part_t send;
//		unsigned recv_error :1;
//		unsigned recv_goaway :1;
//		unsigned send_error :1;
//		unsigned send_goaway :1;
//		unsigned recv_index:1;
//		unsigned recv_paser_value:1;
//		unsigned recv_huff:1;
//
//
//
//
//
//		ngx_queue_t idle_streams;
//
//		ngx_http2_send_frame send_frame;
//		ngx_http2_send_ping send_ping;
//		ngx_http2_send_ping send_headers;



		/*last element*/


		jhd_connection_close_pt  close_pt;

		jhd_queue_t streams[32];

}jhd_http2_connection;


void jhd_http2_only_by_clean_start(jhd_connection_t *c);
void jhd_http2_only_by_tls_start(jhd_connection_t *c);
void jhd_http2_with_alpn_start(jhd_connection_t *c);

extern jhd_http_request_info  jhd_http2_info;

extern u_char* jhd_http2_preface;

#endif /* HTTP2_JHD_HTTP2_H_ */
