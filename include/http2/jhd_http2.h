/*
 * jhd_http2.h
 *
 *  Created on: 2018年10月24日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_H_
#define HTTP2_JHD_HTTP2_H_
#include <jhd_config.h>
#include <http/jhd_http_core.h>


#define JHD_HTTP2_FRAME_TYPE_DATA_FRAME           0x0
#define JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME        0x1
#define JHD_HTTP2_FRAME_TYPE_PRIORITY_FRAME       0x2
#define JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME     0x3
#define JHD_HTTP2_FRAME_TYPE_SETTINGS_FRAME       0x4
#define JHD_HTTP2_FRAME_TYPE_PUSH_PROMISE_FRAME   0x5
#define JHD_HTTP2_FRAME_TYPE_PING_FRAME           0x6
#define JHD_HTTP2_FRAME_TYPE_GOAWAY_FRAME         0x7
#define JHD_HTTP2_FRAME_TYPE_WINDOW_UPDATE_FRAME  0x8
#define JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME   0x9


#define JHD_HTTP2_CONNECTION_HANDLE_READ_TIMEOUT(ev) \
	if((ev)->timedout ==0){\
		log_err("timeout");\
		event_h2c->conf->connection_read_timeout(ev);\
		log_notice("<==%s with timedout",__FUNCTION__);\
		return;\
	}

#define JHD_HTTP2_CONNECTION_ADD_READ_TIMEOUT(ev) jhd_event_add_timer(ev,event_h2c->conf->read_timeout)
#define JHD_HTTP2_CONNECTION_ADD_IDLE_TIMEOUT(ev) jhd_event_add_timer(ev,event_h2c->conf->idle_timeout)
#define JHD_HTTP2_CONNECTION_ADD_WRITE_TIMEOUT(ev) jhd_event_add_timer(ev,event_h2c->conf->write_timeout)
#define JHD_HTTP2_CONNECTION_ADD_MEM_TIMEOUT(ev) jhd_event_add_timer(ev,event_h2c->conf->write_timeout)



typedef  jhd_http_data jhd_http2_frame;

typedef struct {
	uint32_t idle_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;

	uint32_t initial_window_size;

    uint32_t recv_window_size_threshold; // if(connection->recv.window_size <  recv_window_size_threshold then send window_update

	// http2 connection begin idle triger   can add idle timer(server) or send ping frame(client)
    jhd_event_handler_pt connection_idle;
    // in read event triger timeout (readtimeout or idle_timeout or mem_timeout)
    jhd_event_handler_pt connection_read_timeout;
    //
    jhd_event_handler_pt connection_read_error;

    // in read event read connection data invalid
    jhd_event_handler_pt connection_protocol_error;








    uint8_t max_streams;

	void *extend_param;
}jhd_http2_connection_conf;

typedef struct {
	jhd_http2_connection_conf   h2_conf;
	jhd_http11_connection_conf  h11_conf;
} jhd_listening_config_ctx_with_alpn;


typedef struct jhd_http2_stream_s jhd_http2_stream;



typedef struct{
		uint32_t state;
		u_char   buffer[16];

		u_char frame_type;
		u_char frame_flag;
		uint32_t payload_len;

		jhd_http2_stream *stream;

		uint32_t last_stream_id;
        uint32_t window_size;

        void *state_param;
}jhd_http2_conneciton_recv_part;
typedef struct{
		jhd_http2_frame *head;
		jhd_http2_frame *tail;
		u_char   *pos;
		uint16_t len;

}jhd_http2_conneciton_send_part;


typedef struct {


	jhd_http2_connection_conf *conf;
	void *data;
	jhd_http2_conneciton_recv_part recv;
	jhd_http2_conneciton_send_part send;
	uint8_t processing;

//	size_t headers_table_size;
//	size_t init_window;
//	size_t frame_size;
//	ngx_pool_t *pool;
//	ngx_uint_t next_sid;
//
//		ngx_http2_connection_recv_part_t recv;
//		ngx_http2_connection_send_part_t send;
		unsigned recv_error :1;
		unsigned go_away_recved :1;
		unsigned send_error :1;
		unsigned goaway_sent :1;



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



		jhd_http2_frame *alloc_frame;


		jhd_connection_close_pt  close_pt;

		jhd_queue_t streams[32];

}jhd_http2_connection;


typedef struct{
		void (*remote_close_with_empty_data)(jhd_http2_stream *stream);
		void (*remote_data_arrival)(jhd_http2_stream *stream,jhd_http2_frame *frame);
		void (*remote_rst_stream)(jhd_http2_stream *stream);





}jhd_http2_stream_handler;

struct jhd_http2_stream_s{
	jhd_http2_stream_handler *handler;
	uint32_t id;


	int recv_window_size;
	int send_window_size;

	jhd_queue_t queue;
};



void jhd_http2_recv_skip(jhd_event_t *ev);


void jhd_http2_send_event_handler_clean(jhd_event_t *ev);
void jhd_http2_send_event_handler_ssl(jhd_event_t *ev);

#if !defined(JHD_INLINE)
jhd_inline void jhd_http2_send_queue_frame(jhd_http2_frame *frame){
	if(event_h2c->send.tail != NULL){
		event_h2c->send.tail->next = frame;
		event_h2c->send.tail = frame;
	}else{
		event_h2c->send.head = event_h2c->send.tail = frame;
		if(event_c->write.queue.next == NULL){
			jhd_post_event(&event_c->write,&jhd_posted_events);
		}
	}
}

jhd_inline void jhd_http2_send_headers_frame(jhd_http2_frame *begin_headers,jhd_http2_frame * end_headers){
	if(event_h2c->send.tail != NULL){
		event_h2c->send.tail->next = begin_headers;
		event_h2c->send.tail = end_headers;
	}else{
		event_h2c->send.head =begin_headers;
		event_h2c->send.tail = end_headers;
		if(event_c->write.queue.next == NULL){
			jhd_post_event(&event_c->write,&jhd_posted_events);
		}
	}
}


#else
#define jhd_http2_send_queue_frame(F) \
	if(event_h2c->send.tail != NULL){\
		event_h2c->send.tail->next = F;\
		event_h2c->send.tail = F;\
	}else{\
		event_h2c->send.head = event_h2c->send.tail = F;\
		if(event_c->write.queue.next == NULL){\
			jhd_post_event(&event_c->write,&jhd_posted_events);\
		}\
	}

#define jhd_http2_send_headers_frame(WEV,B,E) \
	if(event_h2c->send.tail != NULL){\
		event_h2c->send.tail->next = B;\
		event_h2c->send.tail = E;\
	}else{\
		event_h2c->send.head =B;\
		event_h2c->send.tail = E;\
		if(event_c->write.queue.next == NULL){\
			jhd_post_event(&event_c->write,&jhd_posted_events);\
		}\
	}


#endif
jhd_inline void jhd_http2_send_ping_ack(jhd_http2_frame *frame){
	jhd_http2_frame *prev,*next_frame;
	if(event_h2c->send.head != NULL){
		prev = next_frame = event_h2c->send.head->next;

		while(next_frame!= NULL){
			if((next_frame->type == JHD_HTTP2_FRAME_TYPE_PING_FRAME && next_frame->ack ==1)){
				prev = next_frame;
			}
			next_frame = next_frame->next;
		}
		if(prev == NULL){
			event_h2c->send.tail->next = frame;
			event_h2c->send.tail = frame;
		}else if(((prev->type != JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME) &&(prev->type != JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME)) ||
				(prev->end_header =1)) {
			frame->next = prev->next;
			prev->next = frame;
			if(frame->next == NULL){
				event_h2c->send.tail = frame;
			}
		}else{
			for(;;){
				prev = prev->next;
				if(prev->end_header ==1){
					frame->next = prev->next;
					prev->next = frame;
					if(frame->next == NULL){
						event_h2c->send.tail = frame;
					}
					break;
				}
			}
		}
	}else{
		event_h2c->send.head = event_h2c->send.tail = frame;
		if(event_c->write.queue.next == NULL){
			jhd_post_event(&event_c->write,&jhd_posted_events);
		}
	}
}





void jhd_http2_connection_default_idle_handler(jhd_event_t *ev);
void jhd_http2_connection_default_protocol_error_handler(jhd_event_t *ev);
void jhd_http2_read_frame_header(jhd_event_t *ev);
extern jhd_http_request_info  jhd_http2_info;

extern u_char* jhd_http2_preface;

extern jhd_http2_connection *event_h2c;
extern jhd_http2_connection_conf *event_h2c_conf;

#endif /* HTTP2_JHD_HTTP2_H_ */
