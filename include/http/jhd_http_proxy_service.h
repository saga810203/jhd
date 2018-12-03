#ifndef HTTP_JHD_HTTP_PROXY_SERVICE_H_
#define HTTP_JHD_HTTP_PROXY_SERVICE_H_
#include <http/jhd_http_core.h>
#include <jhd_log.h>

typedef struct {
	uint16_t config_ctx_size;
	void* config_ctx;
	//return proxy_path length;
	uint16_t (*build_proxy_path)(u_char proxy_path[8192], void*ctx, jhd_http_request *r);
} jhd_http_proxy_service_context;


#endif /* HTTP_JHD_HTTP_PROXY_SERVICE_H_ */
