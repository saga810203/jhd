#ifndef HTTP_JHD_HTTP_CORE_H_
#define HTTP_JHD_HTTP_CORE_H_
#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_pool.h>
#include <jhd_queue.h>
#include <jhd_event.h>




typedef struct jhd_http_listening_context_s jhd_http_listening_context;
typedef struct jhd_http_header_s jhd_http_header;
typedef struct jhd_http_request_s jhd_http_request;
typedef struct jhd_http_request_info_s jhd_http_request_info;
typedef enum {
	JHD_HTTP_METHOD_NONE,
	JHD_HTTP_METHOD_GET,
	JHD_HTTP_METHOD_POST,
	JHD_HTTP_METHOD_PUT,
	JHD_HTTP_METHOD_DELETE,
	JHD_HTTP_METHOD_HEAD,
	JHD_HTTP_METHOD_OPTIONS,
} jhd_http_method;



typedef struct {
	u_char   *data;
	u_char   *pos;
	void (*free_func)(void* data);
	void *next;
	u_int16_t data_len;
	uint16_t len;
	unsigned type:4;
	union{
		unsigned ack:1;
		unsigned end_stream:1;
	};
	union{
		unsigned end_header:1;
		unsigned padded:1;
	};
}jhd_http_data;

typedef struct{
	int fd;
	time_t                   mtime;
	size_t 					 size;
    unsigned                 is_file:1;
    unsigned                 is_link:1;
    unsigned                 is_exec:1;

}jhd_http_file_info;


typedef struct {
	uint32_t idle_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;


	void *extend_param;
}jhd_http11_connection_conf;


typedef struct {
	unsigned server_side:1;
	unsigned ssl:1;
	uint32_t idle_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;
    uint32_t recv_window_size_threshold; // if(connection->recv.window_size <  recv_window_size_threshold then send window_update
	// http2 connection begin idle triger   can add idle timer(server) or send ping frame(client)
    // only in frame header read with readed ==0
    jhd_event_handler_pt connection_idle;
    // in read event triger error (do del timer,hand..)
    jhd_event_handler_pt connection_read_error;
    jhd_event_handler_pt *frame_payload_handler_pts;
    jhd_event_handler_pt connection_write;
    jhd_event_handler_pt connection_frame_header_read_after_goaway;
	void *extend_param;
}jhd_http2_connection_conf;







struct jhd_http_listening_context_s{
	jhd_http2_connection_conf   h2_conf;
	jhd_http11_connection_conf  h11_conf;
	void (*handler)(void *data,jhd_http_request *r);
	uint8_t  size;
	uint8_t  capcity;
	void 	 *data;
};


typedef struct {
	u_char *ptr;
	size_t  len;
}header_parse_param;

struct jhd_http_header_s{
     u_char *name;
     u_char *value;
     uint16_t name_len;
     uint16_t value_len;
     uint16_t name_alloced;
     uint16_t value_alloced;
     union{
    	jhd_queue_t queue;
    	header_parse_param parse_param;
     };
};



typedef struct{
	u_char *data;
	uint16_t len;
	uint16_t alloced;
}http_named_header;

struct jhd_http_request_s{
	jhd_event_t event;
	jhd_queue_t queue;

	jhd_queue_t  headers;

	union{
		uint32_t state;
		uint32_t payload_len;
	};
	union{
		void *state_param;
//		jhd_http2_frame *headers_frame;

		u_char *payload;
	};

	union{
		http_named_header   user_agent;
		http_named_header   etag;
	};
	http_named_header content_type;

	ssize_t   content_length;

	union{
		http_named_header  path;
		http_named_header  date;
	};
	union{
		http_named_header host;
		http_named_header server;
	};
	union{
	jhd_http_method method;
	uint16_t status;
	};
	union{
	void *stream;
	void *http11_connection;
	};
	union{
		jhd_http_data *in_data;
		jhd_http_data 	*out_data;
	};

	union{
	jhd_http_data cache_frame;
	jhd_http_file_info file_info;
	};
	unsigned is_http2:1;
	unsigned in_close:1;
	unsigned out_close:1;
	unsigned out_headers_sent:1;






    uint32_t mem_timeout;
	u_char count;
};

jhd_inline static void jhd_http_request_free(jhd_http_request *r){
	jhd_http_header *header;
	jhd_queue_t *head,*q;
	log_assert(r->event.queue.next== NULL);
	log_assert(r->event.timer.key == 0);

	if(r->user_agent.alloced){
		jhd_free_with_size(r->user_agent.data,r->user_agent.alloced);
	}
	if(r->content_type.alloced){
		jhd_free_with_size(r->content_type.data,r->content_type.alloced);
	}
	if(r->path.alloced){
		jhd_free_with_size(r->path.data,r->path.alloced);
	}
	if(r->host.alloced){
		jhd_free_with_size(r->host.data,r->host.alloced);
	}
	head = &r->headers;
	for(q = jhd_queue_next(head); q != head;){
		header = jhd_queue_data(q,jhd_http_header,queue);
		q = jhd_queue_next(q);
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_alloced);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_alloced);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	}
}

struct jhd_http_request_info_s{

};






typedef struct{
	jhd_queue_t queue; //in all (all in config)
	u_char *listening_addr_text;
	u_char listening_addr_text_len;



    jhd_queue_t services;
    u_char *host;
    uint16_t host_len;
}jhd_http_server;



typedef struct{
	jhd_queue_t queue;
	void *service_ctx;
	jhd_bool (*match)(void *service_ctx,jhd_http_request *request);
	void (*server_ctx_free_func)(void *);
	int (*service_func)(void *service_ctx,jhd_http_request *request);
	uint32_t  mem_timeout;
}jhd_http_service;



#if !defined(JHD_INLINE)

static jhd_inline void jhd_http_header_init(jhd_http_header *header){
	memset(header,0,sizeof(jhd_http_header));
}
static jhd_inline void jhd_http_header_free(jhd_http_header *header){
	if(header->name_alloced){
		jhd_free_with_size(header->name,header->name_alloced);
	}
	if(header->value_alloced){
		jhd_free_with_size(header->value,header->value_alloced);
	}
}
static jhd_inline void jhd_http_free_header(jhd_http_header *header){
	if(header->name_alloced){
		jhd_free_with_size(header->name,header->name_alloced);
	}
	if(header->value_alloced){
		jhd_free_with_size(header->value,header->value_alloced);
	}
	jhd_free_with_size(header,sizeof(jhd_http_header));
}

#else
#define jhd_http_header_init(H) memset(H,0,sizeof(jhd_http_header))

#define jhd_http_header_free(H) \
	if((H)->name_alloced){\
		jhd_free_with_size((H)->name,(H)->name_alloced);\
	}\
	if((H)->value_alloced){\
		jhd_free_with_size((H)->value,(H)->value_alloced);\
	}

#define jhd_http_free_header(H) \
	if((H)->name_alloced){\
		jhd_free_with_size((H)->name,(H)->name_alloced);\
	}\
	if((H)->value_alloced){\
		jhd_free_with_size((H)->value,(H)->value_alloced);\
	}\
	jhd_free_with_size((H),sizeof(jhd_http_header))
}

#endif


void jhd_http_listening_context_free(void *ctx);

int jhd_http11_server_connection_alloc(void **pcon,jhd_event_t *ev,jhd_http11_connection_conf *conf);



void jhd_http11_init(jhd_event_t *ev);

void jhd_http_request_init_by_http2(jhd_http_request *r,jhd_event_t *ev);
void jhd_http_request_init_by_http11(jhd_http_request *r,jhd_event_t *ev);
void jhd_http_request_handle_with_bad_by_http2(jhd_http_request *r);
void jhd_http_request_handle_with_nofound_by_http2(jhd_http_request *r);
void jhd_http_request_handle_with_internal_error_by_http2(jhd_http_request *r);
void jhd_http_request_handle_with_bad_by_http11(jhd_http_request *r);
void jhd_http_request_handle_with_nofound_by_http11(jhd_http_request *r);
void jhd_http_request_handle_with_internal_error_by_http11(jhd_http_request *r);

void jhd_http_request_handle_with_bad(jhd_http_request *r);
void jhd_http_request_handle_with_nofound(jhd_http_request *r);
void jhd_http_request_handle_with_internal_error(jhd_http_request *r);

extern jhd_http_request_info  jhd_http11_info;


extern jhd_queue_t  jhd_http_serveres;

extern const char *jhd_http_bad_request_context;
extern uint16_t jhd_http_bad_request_context_len;

extern const char *jhd_http_nofound_request_context;
extern uint16_t jhd_http_nofound_request_context_len;

extern const char *jhd_http_internal_error_request_context;
extern uint16_t jhd_http_internal_error_request_context_len;

#endif /* HTTP_JHD_HTTP_CORE_H_ */
