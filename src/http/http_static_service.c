#include <http/jhd_http_static_service.h>
#include <http2/jhd_http2_static.h>



u_char http_etag_buffer[41];

void http_file_stat(jhd_http_file_info *file_info, u_char* file_loc) {
	struct stat fi;
	int fd;
	file_info->fd = -1;
	fd = open((char*) file_loc, O_NONBLOCK | __O_DIRECT);
	if (fd != -1) {
		if (fstat(fd, &fi) == -1) {
			jhd_close(fd);
			return;
		}
		if (S_ISDIR(fi.st_mode)) {
			jhd_close(fd);
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


void jhd_http_static_request_handle_with_304(jhd_http_request *r){
	if(r->is_http2){
		jhd_http2_static_request_handle_with_304(r);
	}else{
		//TODO impl
	}

}

void jhd_http_static_request_handle_with_206(jhd_http_request *r) {
	if (r->is_http2) {
		jhd_http2_static_request_handle_with_206(r);
	} else {
		//TODO impl
	}

}

static void jhd_http_static_request_handle_with_200(jhd_http_request *r) {
	if (r->is_http2) {
		jhd_http2_static_request_handle_with_200(r);
	} else {
		//TODO impl
	}
}

void jhd_http_static_request_headers_out(jhd_http_request *r) {
	jhd_http_header *header;
	jhd_queue_t *head, *q, *hq, h;
	jhd_http_header *if_modified_since;
	jhd_http_header *if_none_match;
	jhd_http_header *range;
	jhd_http_header *if_range;
	u_char *etag, *p, *end, c;
	size_t etag_len;
	time_t iums;

	etag = http_etag_calc(http_etag_buffer + 40, r->file_info.size, r->file_info.mtime);
	etag_len = http_etag_buffer + 40 - etag;

	if_modified_since = NULL;
	if_none_match = NULL;
	if_range = NULL;
	range = NULL;

	head = &r->headers;

	jhd_queue_init(&h);

	for (q = jhd_queue_next(head); q != head;) {
		header = jhd_queue_data(q, jhd_http_header, queue);
		hq = q;
		q = jhd_queue_next(q);
		jhd_queue_only_remove(hq);
		if (header->name_len == 8){
			if(memcmp(header->name, "if-range",8) == 0) {
				if (if_range) {
					jhd_queue_insert_tail(&h, hq);
					goto func_error;
				} else {
					if_range = header;
				}
			}else{
				jhd_queue_insert_tail(&h, hq);
			}
		} else if (header->name_len == 17) {
			if (memcmp(header->name, "if-modified-since",17) == 0) {
				if (if_modified_since) {
					jhd_queue_insert_tail(&h, hq);
					goto func_error;
				} else {
					if_modified_since = header;
				}
			} else {
				jhd_queue_insert_tail(&h, hq);
			}
		} else if (header->name_len == 13) {
			if (memcmp(header->name, "if-none-match",13) == 0) {
				if (if_none_match) {
					jhd_queue_insert_tail(&h, hq);
					goto func_error;
				} else {
					if_none_match = header;
				}
			} else {
				jhd_queue_insert_tail(&h, hq);
			}
		} else if (header->name_len == 5) {
			if (memcmp(header->name, "range",5) == 0) {
				if (range) {
					jhd_queue_insert_tail(&h, hq);
					goto func_error;
				} else {
					range = header;
				}
			} else {
				jhd_queue_insert_tail(&h, hq);
			}
		} else {
			jhd_queue_insert_tail(&h, hq);
		}
	}

	if (if_none_match) {
		if (if_none_match->value_len == etag_len && (0 == memcmp(etag, if_none_match->value, etag_len))) {
			goto func_304;
		}
	} else if (if_modified_since) {
		iums = jhd_parse_http_time(if_modified_since->value, if_modified_since->value_len);
		if (iums == r->file_info.mtime) {
			goto func_304;
		}
	}
	if (r->file_info.size == 0) {
		goto func_200;
	}

	if (range && range->value_len > 7 && (0 == memcmp(range->value, "bytes=", 6))) {
		if (if_range) {
			if (if_range->value_len >= 2 && if_range->value[if_range->value_len - 1] == '"') {
				if ((if_range->value_len != etag_len) || (0 != memcmp(etag, if_range->value, etag_len))) {
					goto func_200;
				}
			}
			iums = jhd_parse_http_time(if_range->value, if_range->value_len);
			if (iums != r->file_info.mtime) {
				goto func_200;
			}
		}
		r->file_info.range_start = -1;
		r->file_info.range_end = -1;
		p = range->value + 6;
		end = range->value + range->value_len;
		while ((*p == ' ') && (p < end)) {
			++p;
		}
		if (p < end) {
			c = *p;
			++p;
			if (c < '0' || c > '9') {
				goto func_416;
			}
			r->file_info.range_start = c - '0';
			if (p == end) {
				goto func_416;
			}
			do {
				c = *p;
				++p;
				if (c >= '0' && c <= '9') {
					if (r->file_info.range_start >= (0x7FFFFFFFFFFFFFFFLL / 10)) {
						goto func_416;
					}
					r->file_info.range_start = c - '0' + (r->file_info.range_start * 10);
				} else if (c == ' ') {
					break;
				} else if (c == '-') {
					goto parse_range_end;
				} else {
					goto func_416;
				}
			} while (p < end);
			if (p == end) {
				goto func_416;
			}
			while ((*p == ' ') && (p < end)) {
				++p;
			}
			if (p < end) {
				if (*p == '-') {
					++p;
					goto parse_range_end;
				} else {
					goto func_416;
				}
			} else {
				goto func_416;
			}
			parse_range_end: while ((*p == ' ') && (p < end)) {
				++p;
			}
			if (p == end) {
				//TODO file size > 0x7FFFFFFFFFFFFFFFULL     ????????????????????
				r->file_info.range_end = r->file_info.size - 1;
			} else {
				c = *p;
				++p;
				if (c == ',') {
					goto func_200;
				} else if (c == '\0' && p == end) {
					//TODO
					r->file_info.range_end = r->file_info.size - 1;
				} else if (c >= '0' || c <= '9') {
					r->file_info.range_end = c - '0';
					if (p < end) {
						do {
							c = *p;
							++p;
							if (c >= '0' || c <= '9') {
								if (r->file_info.range_end >= (0x7FFFFFFFFFFFFFFFLL / 10)) {
									goto func_416;
								}
								r->file_info.range_end = c - '0' + (r->file_info.range_end * 10);
							} else {
								break;
							}
						} while (p < end);
						if (p < end) {
							do {
								c = *p;
								++p;
								if (c != ' ' && c != '\0') {
									break;
								}
							} while (p < end);
							if (p == end) {
								goto func_200;
							}
						}
					}
				} else {
					goto func_200;
				}
			}
			if(r->file_info.range_end >= r->file_info.size){
				r->file_info.range_end = r->file_info.size - 1;
			}
			if (r->file_info.range_start > r->file_info.range_end) {
				goto func_416;
			}
			jhd_http_static_request_handle_with_206(r);
			goto func_free;
		}
	}
func_200:
	jhd_http_static_request_handle_with_200(r);
	goto func_free;
func_416:
	jhd_close(r->file_info.fd);
	//TODO impl 416 Requested Range Not Satisfiable
	jhd_http_request_handle_with_bad(r);
	goto func_free;

func_304:
	jhd_close(r->file_info.fd);
	log_assert(jhd_queue_empty(&r->headers));
	jhd_http_static_request_handle_with_304(r);
	goto func_free;
func_error:
	jhd_close(r->file_info.fd);
	if (jhd_queue_has_item(&r->headers)) {
		jhd_queue_merge(&h, &r->headers);
		jhd_queue_init(&r->headers);
	}
	jhd_http_request_handle_with_bad(r);
func_free:
	if (if_modified_since) {
		jhd_http_free_header(if_modified_since);
	}
	if (if_none_match) {
		jhd_http_free_header(if_none_match);
	}
	if (if_range) {
		jhd_http_free_header(if_range);
	}
	if (range) {
		jhd_http_free_header(range);
	}
	head = &h;
	for (q = jhd_queue_next(head); q != head;) {
		header = jhd_queue_data(q, jhd_http_header, queue);
		q = jhd_queue_next(q);
		jhd_http_free_header(header);
	}
}

void jhd_http_static_request_handler(jhd_http_request *r) {
	jhd_http_static_service_context *ctx;
	uint16_t len, idx;
	u_char *req_content_type;
	uint16_t req_content_type_len;

	if (r->method == JHD_HTTP_METHOD_GET || r->method == JHD_HTTP_METHOD_HEAD) {
		ctx = r->http_service->service_ctx;
		len = ctx->build_target_file(jhd_calc_buffer, ctx, r);
		http_file_stat(&r->file_info,jhd_calc_buffer);
		if (r->file_info.fd != -1) {
			if (r->content_type.alloced) {
				req_content_type = r->content_type.data;
				req_content_type_len = r->content_type.alloced;
				r->content_type.alloced = 0;
			} else {
				req_content_type_len = 0;
			}
			idx = len - 1;
			log_assert(jhd_calc_buffer[0] == '/');
			log_assert(jhd_calc_buffer[idx] != '.');
			for (;;) {
				if (jhd_calc_buffer[idx] == '.') {
					++idx;
					jhd_http_content_type_get(jhd_calc_buffer + idx, len - idx, &r->content_type.data, &r->content_type.len);
					break;
				} else if (jhd_calc_buffer[idx] == '/') {
					r->content_type.data = (u_char*)default_http_content_type;
					r->content_type.len = default_http_content_type_len;
					break;
				}
				--idx;
			}
			jhd_http_static_request_headers_out(r);
			if (req_content_type_len) {
				jhd_free_with_size(req_content_type, req_content_type_len);
			}
		} else {
			jhd_http_request_handle_with_nofound(r);
		}
	} else if (r->method == JHD_HTTP_METHOD_OPTIONS) {
		//TODO
		jhd_http_request_handle_with_bad(r);
	} else {
		jhd_http_request_handle_with_bad(r);
	}

}

