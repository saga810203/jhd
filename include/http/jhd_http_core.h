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
	unsigned type:4;
	union{
		unsigned ack:1;
		unsigned end_stream:1;
	};
	union{
		unsigned end_header:1;
		unsigned padded:1;
	};
	//TODO impl
	unsigned free_data:1;
	u_char   *data;
	u_int16_t data_len;
	u_char   *pos;
	uint16_t len;
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
     u_char name_alloced;
     u_char value_alloced;
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















typedef struct {
	uint32_t idle_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;


	void *extend_param;
}jhd_http2_connection_conf;









void jhd_http_listening_context_free(void *ctx);

int jhd_http11_server_connection_alloc(void **pcon,jhd_event_t *ev,jhd_http11_connection_conf *conf);

extern jhd_http_request_info  jhd_http11_info;

#endif /* HTTP_JHD_HTTP_CORE_H_ */
