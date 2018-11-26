#include <http/jhd_http_core.h>
#include <jhd_log.h>
#include <jhd_aio.h>
#include <fcntl.h>


typedef struct{
	u_char *file_path;
	uint16_t file_path_len;
	void(*build_target_file)(u_char target_file[8192],void*ctx,jhd_http_request *r);


}jhd_http_static_service_context;


typedef struct {
	jhd_http_header *if_unmodified_since;
	jhd_http_header *if_match;
	jhd_http_header *if_modified_since;
	jhd_http_header *if_none_match;
	jhd_http_header *range;
	jhd_http_header *if_range;


}jhd_http_file_headers;

void http_file_stat(jhd_http_file_info *file_info,u_char* file_loc){
    time_t                          now;
    uint32_t                        hash;
    int64_t                       	rc;
    struct stat                 	fi;
    int fd;

    file_info->fd = -1;

    fd = open((char*)file_loc,O_NONBLOCK |__O_DIRECT);
    if(fd != -1){

    	if(fstat(fd,&fi) == -1){
    		close(fd);
    		return;
    	}
    	if( S_ISDIR(fi.st_mode)){
    		close(fd);
    		return;
    	}

    	file_info->size = fi.st_size;
    	file_info->mtime = fi.st_mtime;
    	file_info->is_file = (S_ISREG(fi.st_mode));
    	file_info->is_link = (S_ISLNK(fi.st_mode));
    	file_info->is_exec = ((fi.st_mode & S_IXUSR) == S_IXUSR);
      	file_info->fd = fd;
    }
}

jhd_http_static_request_headers_alloc(jhd_event_t *ev){

}


void jhd_http_static_request_handler(void *ctx,jhd_http_request *r){
	jhd_http_static_service_context *svs_ctx;
	u_char file_loc[8192];
	if(r->method == JHD_HTTP_METHOD_GET || r->method == JHD_HTTP_METHOD_HEAD){
		svs_ctx = ctx;
		svs_ctx->build_target_file(file_loc,ctx,r);
		http_file_stat(file_loc,&r->file_info);
		if(r->file_info.fd != -1){
			r->event.handler = jhd_http_static_request_headers_alloc;
			jhd_http_static_request_headers_alloc(&r->event);
		}else{
			jhd_http_request_handle_with_nofound(r);
		}
	}else if(r->method == JHD_HTTP_METHOD_OPTIONS){
        //TODO
		jhd_http_request_handle_with_bad(r);
	}else{
		jhd_http_request_handle_with_bad(r);
	}
}




