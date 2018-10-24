#ifndef HTTP_JHD_HTTP_CORE_H_
#define HTTP_JHD_HTTP_CORE_H_
#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_event.h>

typedef struct jhd_http_listening_context_s jhd_http_listening_context;
typedef struct jhd_http_core_header_s jhd_http_core_header;
typedef struct jhd_http_core_request_s jhd_http_core_request;
typedef struct jhd_http_core_request_info_s jhd_http_core_request_info;
typedef enum {
	JHD_HTTP_METHOD_NONE,
	JHD_HTTP_METHOD_GET,
	JHD_HTTP_METHOD_POST,
	JHD_HTTP_METHOD_PUT,
	JHD_HTTP_METHOD_DELETE,
} jhd_http_method;

struct jhd_http_listening_context_s{
	uint8_t  size;
	uint8_t  capcity;
	void **  data;
};


struct jhd_http_core_header_s{
     u_char *name;
     u_char *value;
     uint16_t name_len;
     uint16_t value_len;
     u_char name_alloced;
     u_char value_alloced;
	jhd_queue_t queue;
};

struct jhd_http_core_request_s{
	jhd_queue_t  headers;
	u_char *uri;
	jhd_http_method method;



	void *extend_data;

};

struct jhd_http_core_request_info_s{

};


void jhd_http_listening_context_free(void *ctx);



extern jhd_http_core_request_info  jhd_http11_info;
#endif /* HTTP_JHD_HTTP_CORE_H_ */
