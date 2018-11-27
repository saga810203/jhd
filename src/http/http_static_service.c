#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <jhd_log.h>
#include <jhd_aio.h>
#include <fcntl.h>


typedef struct{
	u_char *file_path;
	uint16_t file_path_len;
	void(*build_target_file)(u_char target_file[8192],void*ctx,jhd_http_request *r);


}jhd_http_static_service_context;




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

u_char *http_etag_calc(u_char* dst,size_t size,time_t mtime){
	dst = jhd_u64_to_hex(dst,size);
	--dst;
	*dst='-';
	--dst;
	return jhd_u64_to_hex(dst,mtime);
}


//static void stream_reset_with_alloc_static_request_headers(jhd_http2_stream *stream){
//	jhd_http_request *r;
//	r = stream->lis_ctx;
//	close(r->file_info->fd);
//	jhd_queue_only_remove(&r->queue);
//	log_assert(r->event.timer.key != 0);
//	jhd_event_del_timer(&r->event);
//	jhd_http_request_free(r);
//}
//
//static jhd_http2_stream_listener server_stream_listener_with_ignore_request_body_alloc_static_headers ={
//		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
//		jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
//		jhd_http2_stream_ignore_listener,
//		stream_reset_with_alloc_static_request_headers,//		jhd_event_handler_pt reset;
//		jhd_http2_stream_ignore_listener,//		jhd_event_handler_pt remote_recv;
//		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
//		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
//};
//void jhd_http2_static_request_headers_alloc_timeout(jhd_event_t *ev){
//		jhd_http_request *r;
//		jhd_http2_stream *stream;
//		jhd_connection_t *c;
//		jhd_http2_connection *h2c;
//		jhd_http2_frame *frame;
//		u_char *p;
//
//		r = ev->data;
//		stream = r->stream;
//		c = stream->connection;
//		h2c = c->data;
//
//		jhd_queue_only_remove(stream->queue);
//		frame = (jhd_http2_frame*)(stream);
//		--h2c->processing;
//		h2c->recv.stream = &jhd_http2_invalid_stream;
//		p = frame->pos = (u_char*)(((u_char*)frame)+sizeof(jhd_http2_frame));
//		frame->type = JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME;
//		frame->data_len = sizeof(jhd_http2_stream);
//		frame->len = 13;
//		frame->free_func = jhd_http2_frame_free_by_single;
//		frame->next = NULL;
//		*((uint32_t*)p) =0x03040000;
//		p[4] = 0;\
//		p[5] = (u_char)((stream->id) >> 24);
//		p[6] = (u_char)((stream->id) >> 16);
//		p[7] = (u_char)((stream->id) >> 8);
//		p[8] = (u_char)(stream->id);
//		p += 9;
//		*((uint32_t*)p) = JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT;
//		jhd_http2_send_queue_frame(c,h2c,frame);
//		jhd_queue_only_remove(&r->event.queue);
//		jhd_http_request_free(r);
//}


static int jhd_http_test_if_match(u_char *etag,size_t etag_len, jhd_http_header *if_match,int weak)
{
    u_char     *start, *end, ch;


    if (if_match->value_len == 1 && if_match->value[0] == '*') {
        return 1;
    }

    if (etag_len == NULL) {
        return 0;
    }



    start = if_match->value;
    end = start + if_match->value_len;

    while (start < end) {
        if (weak
            && end - start > 2
            && start[0] == 'W'
            && start[1] == '/')
        {
            start += 2;
        }

        if (etag_len > (size_t) (end - start)) {
            return 0;
        }

        if (memcmp(start, etag, etag_len) != 0) {
            goto skip;
        }

        start += etag_len;

        while (start < end) {
            ch = *start;

            if (ch == ' ' || ch == '\t') {
                start++;
                continue;
            }

            break;
        }

        if (start == end || *start == ',') {
            return 1;
        }

    skip:

        while (start < end && *start != ',') { start++; }
        while (start < end) {
            ch = *start;

            if (ch == ' ' || ch == '\t' || ch == ',') {
                start++;
                continue;
            }

            break;
        }
    }

    return 0;
}


static u_char http_etag_buffer[41];
void jhd_http_static_request_headers_out(jhd_http_request *r){
	jhd_http_header *header;
	jhd_queue_t *head,*q,*hq,h;
	jhd_http_header *if_modified_since;
	jhd_http_header *if_none_match;
	jhd_http_header *range;
	jhd_http_header *if_range;

	u_char *etag;
	size_t etag_len;

	time_t iums;

	etag = http_etag_calc(http_etag_buffer+ 40,r->file_info.size,r->file_info.mtime);
	etag_len = http_etag_buffer+ 40 - etag;



	if_modified_since = NULL;
	if_none_match = NULL;

	if_range = NULL;
	range = NULL;

	head = &r->headers;

	jhd_queue_init(&h);

	for(q = jhd_queue_next(head); q != head;){
		header = jhd_queue_data(q,jhd_http_header,queue);
		hq = q;
		q = jhd_queue_next(q);
		jhd_queue_only_remove(hq);
		if((header->name_len == 8) &&(memcmp(header->name,"if-range"))==0){
			if(if_range){
				jhd_queue_insert_tail(&h,hq);
				goto func_error;
			}else{
				if_range = header;
			}
		}else if(header->name_len == 17){
			if(memcmp(header->name,   "if-modified-since")==0){
				if(if_modified_since){
					jhd_queue_insert_tail(&h,hq);
					goto func_error;
				}else{
					if_modified_since = header;
				}
			}else{
				jhd_queue_insert_tail(&h,hq);
			}
		}else if(header->name_len == 13){
			if(memcmp(header->name,   "if-none-match")==0){
				if(if_none_match){
					jhd_queue_insert_tail(&h,hq);
					goto func_error;
				}else{
					if_none_match = header;
				}
			}else{
				jhd_queue_insert_tail(&h,hq);
			}
		}else if(header->name_len == 6){
			if(memcmp(header->name,   "range")==0){
				if(range){
					jhd_queue_insert_tail(&h,hq);
					goto func_error;
				}else{
					range = header;
				}
			}else{
				jhd_queue_insert_tail(&h,hq);
			}
		}else{
			jhd_queue_insert_tail(&h,hq);
		}
	}

    if(if_none_match){
    	if(if_none_match->value_len == etag_len &&(0 == memcmp(etag,if_none_match->value,etag_len))){
    		close(r->file_info->fd);
    	    jhd_http_request_handle_with_not_modified(r);
    	    goto func_free;
    	}
    }else if(if_modified_since){
    	 iums = jhd_parse_http_time(if_modified_since->value,if_modified_since->value_len);
    	 if(iums == r->file_info->mtime){
     		close(r->file_info->fd);
     	    jhd_http_request_handle_with_not_modified(r);
     	    goto func_free;
    	 }
    }














func_error:
	close(r->file_info->fd);
    jhd_queue_merge(&h,&r->headers);
    jhd_queue_init(&r->headers);
    jhd_http_request_handle_with_bad(r);
func_free:
	if(if_modified_since){
		jhd_http_free_header(if_modified_since);
	}
	if(if_none_match){
		jhd_http_free_header(if_none_match);
	}
	if(if_range){
		jhd_http_free_header(if_range);
	}
	if(range){
		jhd_http_free_header(range);
	}
	head = &h;
	for(q = jhd_queue_next(head);q != head;){
		header = jhd_queue_data(q,jhd_http_header,queue);
		q = jhd_queue_next(q);
		jhd_http_free_header(header);
	}
}


void jhd_http_static_request_handler(void *ctx,jhd_http_request *r){
	jhd_http_static_service_context *svs_ctx;
	u_char file_loc[8192];
	if(r->method == JHD_HTTP_METHOD_GET || r->method == JHD_HTTP_METHOD_HEAD){
		svs_ctx = ctx;
		svs_ctx->build_target_file(file_loc,ctx,r);
		http_file_stat(file_loc,&r->file_info);
		if(r->file_info.fd != -1){

			jhd_http_static_request_headers_out(r);
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




