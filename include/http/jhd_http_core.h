#ifndef HTTP_JHD_HTTP_CORE_H_
#define HTTP_JHD_HTTP_CORE_H_
#include <jhd_config.h>
#include <jhd_log.h>
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
} jhd_http_method;



typedef struct {
log_assert_code(void *tag;)
	unsigned type:4;
	union{
		unsigned ack:1;
		unsigned end_stream:1;
	};
	union{
		unsigned end_header:1;
		unsigned padded:1;
	};
	u_char   *data;
	u_int16_t data_len;
	u_char   *pos;
	uint16_t len;
	void (*free_func)(struct jhd_http_data* data);
	void * next;
}jhd_http_data;




typedef struct {
	uint32_t idle_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;


	void *extend_param;
}jhd_http11_connection_conf;










struct jhd_http_listening_context_s{
	uint8_t  size;
	uint8_t  capcity;
	void **  data;
};


struct jhd_http_header_s{
     u_char *name;
     u_char *value;
     uint16_t name_len;
     uint16_t value_len;
     uint16_t name_alloced;
     uint16_t value_alloced;
	jhd_queue_t queue;
};

struct jhd_http_request_s{
	jhd_queue_t  headers;
	u_char *uri;
	jhd_http_method method;



	void *extend_data;

};

struct jhd_http_request_info_s{

};



















#if !define(JHD_INLINE)

jhd_inline void jhd_http_header_init(jhd_http_header *header){
	memset(header,0,sizeof(jhd_http_header));
}
jhd_inline void jhd_http_header_free(jhd_http_header *header){
	if(header->name_alloced){
		jhd_free_with_size(header->name,header->name_alloced);
	}
	if(header->value_alloced){
		jhd_free_with_size(header->value,header->value_alloced);
	}
}
jhd_inline void jhd_http_free_header(jhd_http_header *header){
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

extern jhd_http_request_info  jhd_http11_info;

#endif /* HTTP_JHD_HTTP_CORE_H_ */
