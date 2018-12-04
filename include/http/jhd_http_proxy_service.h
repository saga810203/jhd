#ifndef HTTP_JHD_HTTP_PROXY_SERVICE_H_
#define HTTP_JHD_HTTP_PROXY_SERVICE_H_
#include <http/jhd_http_core.h>
#include <jhd_log.h>

typedef struct {
	jhd_queue_t queue;
	u_char *data;
	uint16_t len;
}jhd_http_proxy_control_header;

typedef struct {
	u_char *host;
	u_int16_t  host_len;
	jhd_sockaddr_t sockaddr;






} jhd_http_proxy_host;

typedef struct {
	uint16_t config_ctx_size;
	void* config_ctx;
	//return proxy_path length;
	uint16_t (*build_proxy_path)(u_char* proxy_path, void*ctx, jhd_http_request *r);

	jhd_queue_t enabled_proxy_headers;
	jhd_queue_t enabled_response_headers;
	unsigned send_real_ip:1;
	unsigned send_user_agent:1;
	unsigned sned_content_type:1;
} jhd_http_proxy_service_context;

jhd_bool jhd_http_proxy_control_header_queue_included(jhd_queue_t *head,u_char *header_name,uint16_t header_name_len);

void jhd_http_proxy_filter_request_headers_with_control_header_queue(jhd_queue_t *contorl_head,jhd_http_request *r,jhd_queue_t *dst_head);


int jhd_http_proxy_service_context_enabled_proxy_headers(jhd_http_proxy_service_context *ctx,u_char *header_name,uint16_t header_name_len);
int jhd_http_proxy_service_context_enabled_response_headers(jhd_http_proxy_service_context *ctx,u_char *header_name,uint16_t header_name_len);




void jhd_http_proxy_request_handler(jhd_http_request *r);

#endif /* HTTP_JHD_HTTP_PROXY_SERVICE_H_ */
