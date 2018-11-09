/*
 * jhd_http2.h
 *
 *  Created on: 2018年10月24日
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_H_
#define HTTP2_JHD_HTTP2_H_
#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_connection.h>
#include <http/jhd_http_core.h>
#include <http2/jhd_http2_hpack.h>





#define JHD_HTTP2_NO_FLAG              0x00
#define JHD_HTTP2_ACK_FLAG             0x01
#define JHD_HTTP2_END_STREAM_FLAG      0x01
#define JHD_HTTP2_END_HEADERS_FLAG     0x04
#define JHD_HTTP2_PADDED_FLAG          0x08
#define JHD_HTTP2_PRIORITY_FLAG        0x20


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

#define JHD_HTTP2_STREAM_STATE_CLOSE_BOTH         0x03
#define JHD_HTTP2_STREAM_STATE_CLOSE_LOCAL        0x01
#define JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE       0x02
#define JHD_HTTP2_STREAM_STATE_OPEN               0x00




#define JHD_HTTP2_RECV_PART_BUFFER_LEN  16

#if JHD_HTTP2_RECV_PART_BUFFER_LEN < 16
#error "JHD_HTTP2_RECV_PART_BUFFER_LEN >=16"
#endif


#define jhd_http2_prefix(bits)  ((1 << (bits)) - 1)

#define JHD_HTTP2_SET_STRAM_ID_IN_CHECK(val) val = (event_h2c->recv.buffer[5] << 24) |(event_h2c->recv.buffer[6] << 16) |(event_h2c->recv.buffer[7] << 8) |(event_h2c->recv.buffer[8])



typedef  jhd_http_data jhd_http2_frame;

typedef struct {
	unsigned server_side:1;
	unsigned ssl:1;
	uint32_t idle_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;


	uint32_t initial_window_size;
	uint32_t max_header_table_size;
	uint32_t max_streams;
    uint32_t recv_window_size_threshold; // if(connection->recv.window_size <  recv_window_size_threshold then send window_update

	// http2 connection begin idle triger   can add idle timer(server) or send ping frame(client)
    // only in frame header read with readed ==0
    jhd_event_handler_pt connection_idle;
    // in read event triger timeout (readtimeout or idle_timeout or mem_timeout)
    jhd_event_handler_pt connection_read_timeout;
    // in read event triger error (do del timer,hand..)
    jhd_event_handler_pt connection_read_error;

    // in read event triger error (do del timer,hand..)
    jhd_event_handler_pt connection_send_error;

    //
    jhd_event_handler_pt connection_send_timeout;

    // in read event read connection data invalid
    jhd_event_handler_pt connection_protocol_error;



    //
    jhd_event_handler_pt connection_mem_time_out;

    //  too long  max_header_size  too long header name   too long header val
    jhd_event_handler_pt connection_unsupported_error;

    jhd_event_handler_pt *frame_payload_handler_pts;


    // in server is frame_header read  or in client handler queued idle stream
    jhd_event_handler_pt connection_after_setting_ack;

	void *extend_param;
}jhd_http2_connection_conf;

typedef struct {
	jhd_http2_connection_conf   h2_conf;
	jhd_http11_connection_conf  h11_conf;
} jhd_http_listenning_ctx;


typedef struct jhd_http2_stream_s jhd_http2_stream;


typedef struct{
		uint32_t state;
		union{
		u_char   buffer[JHD_HTTP2_RECV_PART_BUFFER_LEN];
		u_char * alloc_buffer[2];
		};
		u_char frame_type;
		u_char frame_flag;
		uint32_t payload_len;

		jhd_http2_stream *stream;

		uint32_t last_stream_id;
        uint32_t window_size;
        uint32_t init_window_size;

        jhd_http2_hpack hpack;


        jhd_queue_t headers;

        u_char *pos;
        u_char *end;


        jhd_event_handler_pt connection_frame_header_read;
        jhd_event_handler_pt connection_end_headers_handler;


        void *state_param;
}jhd_http2_conneciton_recv_part;
typedef struct{
		jhd_http2_frame *head;
		jhd_http2_frame *tail;

		uint16_t frame_szie;
		uint32_t window_size;
		uint32_t initial_window_size;

		jhd_http2_hpack hpack;

        uint16_t max_fragmentation;
}jhd_http2_conneciton_send_part;


typedef struct {
	jhd_http2_connection_conf *conf;
	void *data;
	jhd_http2_conneciton_recv_part recv;
	jhd_http2_conneciton_send_part send;
	uint32_t processing;
	unsigned recv_error :1;
	unsigned goaway_recved :1;
	unsigned send_error :1;
	unsigned goaway_sent :1;

	jhd_connection_close_pt  close_pt;
	uint32_t max_streams;
	jhd_queue_t flow_control;
	jhd_queue_t wait_close;
	jhd_queue_t streams[32];
}jhd_http2_connection;


typedef struct{
		//notify
		jhd_event_handler_pt remote_close;
		//handler  set  ev->handler
		jhd_event_handler_pt remote_data;
		//handler  set  ev->handler;
		jhd_event_handler_pt remote_empty_data;
		//notify
		jhd_event_handler_pt reset;
		//handler do send frame but disable block  not set ev->handler
		jhd_event_handler_pt remote_recv;
		//notify   change stream->recv_window_size   ==  return value(event_h2c->recv.state);
		jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)

		//notify  don't change connection state  can send data
		jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
}jhd_http2_stream_listener;



struct jhd_http2_stream_s{
	jhd_http2_stream_listener *listener;
	void *lis_ctx;
	uint32_t id;
	u_char state;
	int recv_window_size;
	int send_window_size;
	jhd_queue_t queue;
	jhd_queue_t flow_control;
};











extern jhd_http_request_info  jhd_http2_info;

extern const char* jhd_http2_preface;

extern jhd_http2_connection *event_h2c;
extern jhd_http2_connection_conf *event_h2c_conf;


extern jhd_http2_stream jhd_http2_invalid_stream;

extern jhd_http2_frame jhd_http2_empty_frame;
extern jhd_http2_frame jhd_http2_empty_end_stream_stream;








static jhd_inline int jhd_http2_parse_int(uint32_t *value,u_char prefix,u_char *start, u_char *end,u_char shift_limit){
    u_char   *p, octet, shift;
    p = start;
    if(p >= end){
    	return JHD_AGAIN;
    }
    *value = *p & prefix;
    ++p;
    if (*value == prefix) {
    	shift = 0;
		for(;;){
			if(p >= end){
				return JHD_AGAIN;
			}
			if(shift > shift_limit){
				jhd_err = JHD_HTTP2_ENHANCE_YOUR_CALM;
				return JHD_ERROR;
			}
			octet = *p;
			++p;
			*value += ((octet & 0x7f) << shift);
			if (octet < 128) {
				break;
			}
			shift +=7;
		}
    }
    return p - start;
}





int jhd_http2_huff_decode(u_char *src, uint16_t src_len, u_char *dst,uint16_t dst_len);


void jhd_http2_frame_free_by_direct(void *data);
void jhd_http2_frame_free_by_single(void *data);
void jhd_http2_recv_skip(jhd_event_t *ev);
void jhd_http2_recv_payload(jhd_event_t *ev);
void jhd_http2_recv_buffer(jhd_event_t *ev);






void jhd_http2_headers_frame_parse_item(jhd_event_t *ev);



void jhd_http2_unsupported_frame_type(jhd_event_t *ev);

void jhd_http2_data_frame_header_check(jhd_event_t *ev);
void jhd_http2_priority_frame_header_check(jhd_event_t *ev);
void jhd_http2_rst_stream_frame_header_check(jhd_event_t *ev);
void jhd_http2_setting_frame_header_check(jhd_event_t *ev);
void jhd_http2_ping_frame_header_check(jhd_event_t *ev);
void jhd_http2_window_update_frame_header_check(jhd_event_t *ev);
void jhd_http2_headers_frame_payload_handler(jhd_event_t *ev);

void jhd_http2_goaway_payload_recv(jhd_event_t *ev);











void jhd_http2_send_event_handler_clean(jhd_event_t *ev);
void jhd_http2_send_event_handler_ssl(jhd_event_t *ev);

#if !defined(JHD_INLINE)

static jhd_inline void jhd_http2_set_stream_id(u_char *p,uint32_t sid){
	p[0] = (u_char)(sid >> 24);
	p[1] = (u_char)(sid >> 16);
	p[2] = (u_char)(sid >> 8);
	p[3] = (u_char)(sid);
}




static jhd_inline void jhd_http2_send_queue_frame(jhd_connection_t *c,jhd_http2_connection* h2c,jhd_http2_frame *frame){
	if(h2c->send.tail != NULL){
		h2c->send.tail->next = frame;
		h2c->send.tail = frame;
	}else{
		h2c->send.head = h2c->send.tail = frame;
		jhd_post_event(&c->write,&jhd_posted_events);
	}
}

static jhd_inline void jhd_http2_send_headers_frame(jhd_connection_t *c,jhd_http2_connection* h2c,jhd_http2_frame *begin_headers,jhd_http2_frame * end_headers){
	if(h2c->send.tail != NULL){
		h2c->send.tail->next = begin_headers;
		h2c->send.tail = end_headers;
	}else{
		h2c->send.head =begin_headers;
		h2c->send.tail = end_headers;
		jhd_post_event(&c->write,&jhd_posted_events);
	}
}


static jhd_inline void jhd_http2_send_data_frame(jhd_connection_t *c,jhd_http2_connection* h2c,jhd_http2_frame *frame){
	log_assert(frame->type == JHD_HTTP2_FRAME_TYPE_DATA_FRAME);
	log_assert()



}


static jhd_inline void jhd_http2_do_recv_skip(jhd_event_t *ev,jhd_http2_connection *h2c,uint32_t size,jhd_event_handler_pt handler){
	h2c->recv.state = size;
	h2c->recv.state_param = handler;
	ev->handler = jhd_http2_recv_skip;
	jhd_unshift_event(ev,&jhd_posted_events);
}

static jhd_inline void jhd_http2_do_recv_payload(jhd_event_t *ev,jhd_http2_connection *h2c,jhd_event_handler_pt handler){
	h2c->recv.state_param = handler;
	ev->handler = jhd_http2_recv_payload;
	jhd_unshift_event(ev,&jhd_posted_events);
}

static jhd_inline void jhd_http2_do_recv_buffer(jhd_event_t *ev,jhd_http2_connection *h2c,jhd_event_handler_pt handler){
	h2c->recv.state_param = handler;
	h2c->recv.state = 0;
	ev->handler = jhd_http2_recv_buffer;
	jhd_unshift_event(ev,&jhd_posted_events);
}

static jhd_inline void jhd_http2_single_frame_init(jhd_http2_frame *frame,uint32_t len){
	frame->pos=frame->data = (u_char*)(((u_char*)frame)+sizeof(jhd_http2_frame));
	frame->data_len = len;
	frame->len = len - sizeof(jhd_http2_frame);
	frame->free_func = jhd_http2_frame_free_by_single;
}
#ifdef JHD_LOG_ASSERT_ENABLE

static jhd_inline void jhd_http2_frame_init(jhd_http2_frame *frame,void *tag,void (*free_handler)(void *)){
	frame->data = NULL;
	frame->tag = tag;
	frame->free_func = free_handler;
}

#else
static jhd_inline void jhd_http2_frame_init(jhd_http2_frame *frame,void (*free_handler)(void *)){
	frame->data = NULL;
	frame->free_func = free_handler;
}

#endif

#else

#define void jhd_http2_single_frame_init(F,L) \
	(F)->pos = (F)->data = (u_char*)(((u_char*)(F))+sizeof(jhd_http2_frame));\
	(F)->data_len =  L;\
	(F)->len = L - sizeof(jhd_http2_frame);\
	(F)->free_func = jhd_http2_frame_free_by_single
}

#ifdef JHD_LOG_ASSERT_ENABLE
#define jhd_http2_frame_init(F,T,H) (F)->data = NULL;(F)->tag = T;(F)->free_func = H

#else
#define jhd_http2_frame_init(F,H) (F)->data = NULL;(F)->free_func = H

#endif


#define jhd_http2_do_recv_skip(E,H2C,SIZE,HAND) (H2C)->recv.state = SIZE;(H2C)->recv.state_param = HAND;(E)->handler = jhd_http2_recv_skip;jhd_unshift_event(E,&jhd_posted_events)

#define jhd_http2_do_recv_payload(E,H2C,HAND) (H2C)->recv.state_param = HAND;(E)->handler = jhd_http2_recv_payload;jhd_unshift_event(E,&jhd_posted_events)

#define jhd_http2_do_recv_buffer(E,H2C,HAND) (H2C)->recv.state_param = HAND;(E)->handler = jhd_http2_recv_buffer;jhd_unshift_event(E,&jhd_posted_events)


#define jhd_http2_send_queue_frame(C,H,F) \
	if(H->send.tail != NULL){\
		H->send.tail->next = F;\
		H->send.tail = F;\
	}else{\
		H->send.head = H->send.tail = F;\
		jhd_post_event(&C->write,&jhd_posted_events);\
	}

#define jhd_http2_send_headers_frame(C,H,B,E) \
	if(H->send.tail != NULL){\
		H->send.tail->next = B;\
		H->send.tail = E;\
	}else{\
		H->send.head =B;\
		H->send.tail = E;\
		jhd_post_event(&C->write,&jhd_posted_events);\
	}

#define jhd_http2_stream_init(S) memset(S,0,sizeof(jhd_http2_stream))

#define jhd_http2_set_stream_id(P,SID) P[0] = (u_char)((SID) >> 24);P[1] = (u_char)((SID) >> 16);P[2] = (u_char)((SID) >> 8);P[3] = (u_char)(sid)

#endif






static jhd_inline void jhd_http2_send_ping_ack(jhd_http2_frame *frame){
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


static jhd_inline jhd_http2_stream * jhd_http2_stream_get(jhd_http2_connection *h2c,uint32_t sid){
	jhd_http2_stream *stream;
	jhd_queue_t *q,*head;
	head = &(event_h2c->streams[(sid >1) & 0x1F]);
	for(q = head->next; q != head ; q = q->next){
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		if(stream->id == sid){
			log_assert(stream->state  != JHD_HTTP2_STREAM_STATE_CLOSE_BOTH);
			return stream;
		}
	}
	return NULL;
}


void jhd_http2_connection_default_idle_handler(jhd_event_t *ev);
void jhd_http2_connection_default_protocol_error_handler(jhd_event_t *ev);
void jhd_http2_frame_header_read(jhd_event_t *ev);


void jhd_http2_headers_frame_parse_item(jhd_event_t *ev);

void jhd_http2_send_setting_frame(jhd_event_t *ev);
void jhd_http2_send_setting_frame_ack(jhd_event_t *ev);
void jhd_http2_send_ping_frame(jhd_event_t *ev);







#define  jhd_http2_build_goaway_frame(F_V,P_V,SID,EC) \
	F_V = jhd_alloc(sizeof(jhd_http2_frame)+ 17);\
	if(F_V != NULL){\
		jhd_http2_single_frame_init(F_V,sizeof(jhd_http2_frame)+17);\
		F_V->type = JHD_HTTP2_FRAME_TYPE_GOAWAY_FRAME;\
		P_V = F_V->pos;\
		*((uint32_t*)P_V) = 0x07080000;\
		P_V[4] = 0;\
		P_V += 5;\
		*((uint32_t*)P_V) = 0x0;\
		P_V += 4;\
		jhd_http2_set_stream_id(P_V,SID);\
		P_V += 4;\
		*((uint32_t*)P_V) = EC;












extern uint32_t jhd_http2_error_code;

#ifdef JHD_LOG_LEVEL_ERR

extern char *jhd_http2_error_file;
extern char *jhd_http2_error_func;
extern int   jhd_http2_error_line;

#define log_http2_err(CODE)  jhd_http2_error_code = CODE; jhd_http2_error_file = (char*)__FILE__;jhd_http2_error_func=(char*)__FUNCTION__;jhd_http2_error_line=(int)__LINE__


#else

#define log_http2_err(CODE)  jhd_http2_error_code = CODE

#endif


#endif /* HTTP2_JHD_HTTP2_H_ */
