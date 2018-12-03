/*
 * jhd_http_static_service.h
 *
 *  Created on: 2018年12月2日
 *      Author: root
 */

#ifndef HTTP_JHD_HTTP_STATIC_SERVICE_H_
#define HTTP_JHD_HTTP_STATIC_SERVICE_H_
#include <http/jhd_http_core.h>
#include <jhd_log.h>
#include <jhd_aio.h>
#include <fcntl.h>

typedef struct {
	uint16_t config_ctx_size;
	void* config_ctx;
	u_char *file_path;
	uint16_t file_path_len;
	//return target_file length;
	uint16_t (*build_target_file)(u_char target_file[8192], void*ctx, jhd_http_request *r);
	size_t *wait_aio_timeout;
} jhd_http_static_service_context;


jhd_inline static u_char *http_etag_calc(u_char* dst,size_t size,time_t mtime){
	*dst ='"';
	--dst;
	dst = jhd_u64_to_hex(dst,size);
	--dst;
	*dst='-';
	--dst;
	dst = jhd_u64_to_hex(dst,mtime);
	--dst;
	*dst ='"';
	return dst;
}


extern u_char http_etag_buffer[41];

#endif /* HTTP_JHD_HTTP_STATIC_SERVICE_H_ */
