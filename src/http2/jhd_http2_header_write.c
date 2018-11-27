#include <jhd_config.h>
#include <jhd_log.h>
#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <jhd_string.h>

#define jhd_http2_integer_octets(v)  (1 + (v) / 127)
#define jhd_http2_literal_size(h)  (jhd_http2_integer_octets(sizeof(h) - 1) + sizeof(h) - 1)



#ifdef JHD_LOG_ASSERT_ENABLE
static void http2_check_headers_frame(jhd_http2_frame *begin,jhd_http2_frame *end,jhd_bool end_stream){
    log_assert(begin->pos[3] == JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME);
    if(begin == end){
    	log_assert(begin->pos[4] & JHD_HTTP2_END_HEADERS_FLAG);
    	if(end_stream){
    		log_assert(begin->pos[4] & JHD_HTTP2_END_STREAM_FLAG);
    	}
    }else{
    	log_assert(0==(begin->pos[4] & JHD_HTTP2_END_HEADERS_FLAG));
    	if(end_stream){
    		log_assert(begin->pos[4] & JHD_HTTP2_END_STREAM_FLAG);
    	}
    	log_assert(end->pos[4] & JHD_HTTP2_END_HEADERS_FLAG);
    	log_assert(end->pos[3] == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME);

    	begin = begin->next;
    	do{
    		log_assert(begin->pos[3] == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME);
    		log_assert(begin->pos[4] == 0);
    	}while(begin != end);
    }
}
#endif



static size_t jhd_http2_write_header(jhd_http_header *header){
	u_char *p ;
	uint16_t idx ;

	p = jhd_calc_buffer;
	if(header->name_alloced){
		log_assert(header->name_len <= 126);
		*p = 0;
		++p;
		*p = header->name_len;
		++p;
		memcpy(p,header->name,header->name_len);
		p += header->name_len;
	}else{
		//TODO add to index
		idx = jhd_http2_hpack_find_static_name(header->name,header->name_len);
		log_assert(idx>0  && (idx < 62));

		if(idx > 14){
			*p = 15;
			++p;
			idx -= 15;
			if(idx > 127){
				*p = (idx & 0x7F) | 0x80;
				++p;
				idx >>= 7;
				log_assert(idx <127);
				*p = idx;
				++p;
			}else{
				*p = idx;
				++p;
			}
		}else{
			*p = idx;
			++p;
		}
	}

	idx = header->value_len;
	if(idx > 127){
		*p = 127;
		++p;
		idx -=127;
		if(idx > 127){
			*p = (idx & 0x7F) | 0x80;
			++p;
			idx >>= 7;
			log_assert(idx <127);
			*p = idx;
			++p;
		}else{
			*p = idx;
			++p;
		}
	}else{
		*p = idx;
		++p;
	}
	memcpy(p,header->value,header->value_len);
	return header->value_len + p - jhd_calc_buffer;
}



uint32_t jhd_http2_calc_response_headers_size(jhd_http_request *r){
	jhd_queue_t *head,*q;
	jhd_http_header *header;
	uint32_t ret;

	log_assert(r->status >=100 &&(r->status <=999));
	if(r->status == 200){
		ret = 1;
	}else if(r->status == 204){
		ret = 1;
	}else if(r->status == 206){
		ret = 1;
	}else if(r->status == 304){
		ret = 1;
	}else if(r->status == 400){
		ret = 1;
	}else if(r->status == 404){
		ret = 1;
	}else if(r->status == 500){
		ret = 1;
	}else{
		ret =  5; //  jhd_http2_literal_size("100");
	}
	log_assert(r->server.len < 127);
    ret += (2/*static hapck idx = 00001111 (54-15 )*/+1/* server.len */+r->server.len);
    ret += (2/*static hapck idx = 00001111 (41-15 )*/+1/* content_type.len */+r->content_type.len);
    if(r->content_length>=0){
    	ret += (2/*static hapck idx = 00001111 (38-15 )*/+1/* */+sizeof(INT64_MAX_STRING)-1);
    }
    //
    ret += (2/*static hapck idx = 00001111 (31-15 )*/+1/* content_type.len */+sizeof("Wed, 31 Dec 1986 18:00:00 GMT")-1);

    head = &r->headers;
    q = jhd_queue_next(head);
    while(q != head){
    	header = jhd_queue_data(q,jhd_http_header,queue);
    	q = jhd_queue_next(q);
    	ret += (1/*0x00*/ + 1/*1~126*/ +header->name_len + 4 + header->value_len);
    }
    return ret;
}

/**
 * return 0 is ok  other require memory size
 */
uint16_t jhd_http2_alloc_headers_frame(jhd_http2_frame **frame,uint32_t *len){
	uint16_t mlen,flen,blen;

	while(*frame){
		frame = (jhd_http2_frame **)(&((*frame)->next));
	}
	do{
		blen = 16384  - sizeof(jhd_http2_frame);
		if(*len  < blen ){
			blen = *len;
		}
		flen = blen+ 9;
		mlen = flen +  sizeof(jhd_http2_frame);


		*frame = jhd_alloc(mlen);
		if(*frame == NULL){
			return mlen;
		}

		(*frame)->pos=(u_char*)(((u_char*)(*frame))+sizeof(jhd_http2_frame));
		(*frame)->data_len = mlen;
		(*frame)->len = flen;
		(*frame)->free_func = jhd_http2_frame_free_by_single;
		(*frame)->next = NULL;

		*len -= blen;
		frame = (jhd_http2_frame **)(&((*frame)->next));
	}while(*len >0);
	return 0;
}



int jhd_http2_write_request_headers_frame(jhd_event_t *ev){

	return 0;
}
void jhd_http2_send_not_modified_response_headers_frmae(jhd_http_request *r,jhd_http2_frame *frame){
	uint16_t len;
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
		jhd_http2_stream *stream;
		u_char *p;

		stream = r->stream;
		c = stream->connection;
		h2c = c->data;

		frame->type = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
		frame->end_header = 1;
		//frame->data = frame;
		frame->data_len = 256;
		frame->free_func = jhd_http2_frame_free_by_single;
		p = ((u_char*)frame) + sizeof(jhd_http2_frame);
		frame->pos = p;
		p+=9;

		*p = 128 + 11;
		++p;
		//server:jhttpd
		*p = 15;
		++p;
		*p = 54 - 15;
		++p;
		*p = 6;
		++p;
		memcpy(p,"jhttpd",6);
		p += 6;// (2+1+r->server.len);

		//data
		*p = 15;
		++p;
		*p = 33 - 15;
		++p;
		*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
		++p;
		memcpy(p,jhd_cache_http_date,sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
		p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
		//last-modified
		*p = 15;
		++p;
		*p = 44 - 15;
		++p;
		*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
		++p;
		jhd_write_http_time(p,r->file_info->mtime);
		p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);

		len = p - frame->pos;
		frame->len = len;
		len -= 9;
		frame->pos[0] = 0;
		frame->pos[1] = 0;
		frame->pos[2] = (u_char)(len);
		frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
		frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG | JHD_HTTP2_END_STREAM_FLAG;
		frame->pos[5] = (u_char)(stream->id >> 24);
		frame->pos[6] = (u_char)(stream->id >> 16);
		frame->pos[7] = (u_char)(stream->id >> 8);
		frame->pos[8] = (u_char)(stream->id);
		frame->next = NULL;
	    jhd_http2_send_headers_frame(c,h2c,frame,frame);

	    jhd_queue_only_remove(stream->queue);
	    --h2c->processing;
	    jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	    if(r->event.timer.key){
	    	jhd_event_del_timer(&r->event);
	    }
	    jhd_free_with_size(r,jhd_http_request);
}

void jhd_http2_send_cache_response_headers_frmae(jhd_http_request *r,jhd_http2_frame *frame){
	uint16_t len;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	u_char *p,*begin,*end;

	log_assert((r->status == 400) ||(r->status == 404) || (r->status == 500) );

	stream = r->stream;
	c = stream->connection;
	h2c = c->data;
	frame->type = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->end_header = 1;
	//frame->data = frame;
	frame->data_len = 256;
	frame->free_func = jhd_http2_frame_free_by_single;
	p = ((u_char*)frame) + sizeof(jhd_http2_frame);
	frame->pos = p;
	p+=9;
	if(r->status == 400){
		*p = 128 + 12;
	}else if(r->status == 404){
		*p = 128 + 13;
	}else /*(r->status == 500)*/{
		*p = 128 + 14;
	}
	++p;
	//content_type:text/html
	*p = 15;
	++p;
	*p = 31 -15;
	++p;
	*p = 9; //sizeof("text/html") - 1;
	++p;
	memcpy(p,"text/html",9);
	p+=  9;//r->content_type.len;

	//server:jhttpd
	*p = 15;
	++p;
	*p = 54 - 15;
	++p;
	*p = 6;
	++p;
	memcpy(p,"jhttpd",6);
	p += 6;// (2+1+r->server.len);

	*p = 15;
	++p;
	*p = 33 - 15;
	++p;
	*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	++p;
	memcpy(p,jhd_cache_http_date,sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);

	if(r->content_length>=0){
		*p = 15;
		++p;
		*p = 28 - 15;
		++p;
		end = jhd_calc_buffer + 100;
		begin = jhd_u64_to_string(end,(uint64_t)((r->content_length)));
		len = end - begin;
		*p = (u_char)len;
		++p;
		memcpy(p,begin,len);
		p += len;
	}
	len = p - frame->pos;
	frame->len = len;
	len -= 9;
	frame->pos[0] = 0;
	frame->pos[1] = 0;
	frame->pos[2] = (u_char)(len);
	frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
	frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG;
	frame->pos[5] = (u_char)(stream->id >> 24);
	frame->pos[6] = (u_char)(stream->id >> 16);
	frame->pos[7] = (u_char)(stream->id >> 8);
	frame->pos[8] = (u_char)(stream->id);
	frame->next = NULL;
    jhd_http2_send_headers_frame(c,h2c,frame,frame);
}



/**
 * return with frame_head unused frame  NULL or single_frame
 */
void jhd_http2_send_response_headers_frmae(jhd_http_request *r,jhd_http2_frame **frame_head,jhd_bool end_stream){
	jhd_http2_frame *frame;
	uint16_t len,slen;
	jhd_queue_t  *head,*q;
	jhd_http_header *header;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	u_char *p,*begin,*end;

	stream = r->stream;
	c = stream->connection;
	h2c = c->data;

	frame = *frame_head;

	log_assert(frame->len > 9);

	p = frame->pos+9;
	len = frame->len -9;

	if (r->status == 200) {
		*p = 128 + 8;
		--len;
		++p;

	} else if (r->status == 204) {
		*p = 128 + 9;
		--len;
		++p;
	} else if (r->status == 206) {
		*p = 128 + 10;
		--len;
		++p;
	} else if (r->status == 304) {
		*p = 128 + 11;
		--len;
		++p;
	} else if (r->status == 400) {
		*p = 128 + 12;
		--len;
		++p;
	} else if (r->status == 404) {
		*p = 128 + 13;
		--len;
		++p;
	} else if (r->status == 500) {
		*p = 128 + 14;
		--len;
		++p;
	} else {
		*p = 8;  // index name  withouting incom
		++p;
		*p = 3;
		++p;
		*p = (r->status /  100) + '0';
		++p;
		*p = ((r->status %  100) / 10) + '0';
		++p;
		*p = ((r->status %  100) / 10) + '0';
		++p;

		len -= 5;
	}

	*p = 15;
	++p;
	*p = 31 -15;
	++p;
	*p = r->content_type.len;
	++p;
	memcpy(p,r->content_type.data,r->content_type.len);
	len -= (2+1+r->content_type.len);
	p+= (r->content_type.len);

	*p = 15;
	++p;
	*p = 54 - 15;
	++p;
	*p = r->server.len;
	++p;
	memcpy(p,r->server.data,r->server.len);
	len -= (2+1+r->server.len);
	p += (r->server.len);

	*p = 15;
	++p;
	*p = 33 - 15;
	++p;
	*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	++p;
	memcpy(p,r->date.data,sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	len -= (2+1+sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	p += (sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);

	if(r->content_length>=0){
		*p = 15;
		++p;
		*p = 28 - 15;
		++p;

		end = jhd_calc_buffer + 100;

		begin = jhd_u64_to_string(end,(uint64_t)((r->content_length)));

		slen = end - begin;


		*p = (u_char)slen;
		++p;
		memcpy(p,begin,slen);
		len -= (2+1+slen);
		p += (slen);
	}

    head = &r->headers;

    if(jhd_queue_has_item(head)){
    	q = jhd_queue_next(head);
    	for(;;){
 			header = jhd_queue_data(q,jhd_http_header,queue);
 			q = jhd_queue_next(q);
			slen = jhd_http2_write_header(header);
			if(slen < len){
				memcpy(p,jhd_calc_buffer,slen);
				len -=slen;
				p+=slen;
				if(q == head){
					slen = p - frame->pos;
					frame->len = slen;
					slen -= 9;
					frame->pos[0] = 0;
					frame->pos[1] = (u_char)(slen >> 8);
					frame->pos[2] = (u_char)(slen);
					if(frame == *frame_head){
						frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
					}else{
						frame->pos[3] = JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME;
					}
					frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG;
					frame->pos[5] = (u_char)(stream->id >> 24);
					frame->pos[6] = (u_char)(stream->id >> 16);
					frame->pos[7] = (u_char)(stream->id >> 8);
					frame->pos[8] = (u_char)(stream->id);

					p = (u_char*)(frame->next);
					frame->next = NULL;
					break;
				}
			}else if(slen == len){
				memcpy(p,jhd_calc_buffer,slen);
				slen = frame->len -9;
				frame->pos[0] = 0;
				frame->pos[1] = (u_char)(slen >> 8);
				frame->pos[2] = (u_char)(slen);

				frame->pos[5] = (u_char)(stream->id >> 24);
				frame->pos[6] = (u_char)(stream->id >> 16);
				frame->pos[7] = (u_char)(stream->id >> 8);
				frame->pos[8] = (u_char)(stream->id);

				if(frame == *frame_head){
					frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
				}else{
					frame->pos[3] = JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME;
				}

				if(q == head){
					frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG;
					p = (u_char*)(frame->next);
					frame->next = NULL;
					break;
				}
				frame->pos[4] = 0;
				log_assert(frame->next != NULL);
				frame = frame->next;
				p = frame->pos +9;
				len = frame->len -9;
			}else{
				memcpy(p,jhd_calc_buffer,len);

				log_assert(frame->next!= NULL);
				log_assert(((jhd_http2_frame*)(frame->next))->len -9 > (slen - len));

				p = ((jhd_http2_frame*)(frame->next))->pos + 9;

				memcpy(p,jhd_calc_buffer+len,slen - len);

				p +=(slen-len);

				len = ((jhd_http2_frame*)(frame->next))->len -9 + len - slen /* -(slen - len)*/;

				slen = frame->len - 9;

				frame->pos[0] = 0;
				frame->pos[1] = (u_char)(slen >> 8);
				frame->pos[2] = (u_char)(slen);

				if(frame == *frame_head){
					frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
				}else{
					frame->pos[3] = JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME;
				}
				frame->pos[4] = 0;

				frame->pos[5] = (u_char)(stream->id >> 24);
				frame->pos[6] = (u_char)(stream->id >> 16);
				frame->pos[7] = (u_char)(stream->id >> 8);
				frame->pos[8] = (u_char)(stream->id);

				frame = frame ->next;


				if(q == head){
					slen = p - frame->pos;
					frame->len = slen;
					slen -= 9;
					frame->pos[0] = 0;
					frame->pos[1] = (u_char)(slen >> 8);
					frame->pos[2] = (u_char)(slen);
					frame->pos[3] = JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME;
					frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG;
					frame->pos[5] = (u_char)(stream->id >> 24);
					frame->pos[6] = (u_char)(stream->id >> 16);
					frame->pos[7] = (u_char)(stream->id >> 8);
					frame->pos[8] = (u_char)(stream->id);
					p = (u_char*)(frame->next);
					frame->next = NULL;
					break;
				}
			}
    	}
    }else{
    	slen = p - frame->pos;
    	frame->len = slen;
		slen -= 9;
		frame->pos[0] = 0;
		frame->pos[1] = (u_char)(slen >> 8);
		frame->pos[2] = (u_char)(slen);
		frame->pos[3] = JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME;
		frame->pos[4] = JHD_HTTP2_END_HEADERS_FLAG;
		frame->pos[5] = (u_char)(stream->id >> 24);
		frame->pos[6] = (u_char)(stream->id >> 16);
		frame->pos[7] = (u_char)(stream->id >> 8);
		frame->pos[8] = (u_char)(stream->id);
		p = (u_char*)(frame->next);
		frame->next = NULL;
    }
    if(end_stream){
    	(*frame_head)->pos[4] |=JHD_HTTP2_END_STREAM_FLAG;;
    }
    log_assert_code(http2_check_headers_frame(*frame_head,frame,end_stream);)
    jhd_http2_send_headers_frame(c,h2c,*frame_head,frame);
    *frame_head = (jhd_http2_frame*)p;
}





