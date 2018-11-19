#include <jhd_config.h>
#include <jhd_log.h>
#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>

#define jhd_http2_integer_octets(v)  (1 + (v) / 127)
#define jhd_http2_literal_size(h)  (jhd_http2_integer_octets(sizeof(h) - 1) + sizeof(h) - 1)



static size_t jhd_http2_write_header(jhd_http_header *header){
	u_char *p ;
	uint16_t idx ;

	p = jhd_calc_buffer;
	if(header->name_alloced){
		log_assert(header->name <= 126);
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


static void jhd_http2_alloc_headers_frame_timeout(jhd_event_t *ev){
	jhd_queue_t h,*q;
	jhd_http_header *header;
	jhd_http2_frame *frame;
	u_char *p;
	size_t len;
	void (*frame_free_func)(void *);

	http_named_header  date;
	http_named_header  server;
	http_named_header  content_type;

	jhd_http_request *r = ev->data;

	jhd_queue_move(&h,&r->headers);
	frame = r->headers_frame;

	date.data = r->date.data;
	date.alloced = r->date.alloced;
	server.data = r->server.data;
	server.alloced = r->server.alloced;
	content_type.data = r->content_type.data;
	content_type.alloced = r->content_type.alloced;

	if(date.alloced){
		jhd_free_with_size(date.data,date.alloced);
	}
	if(server.alloced){
		jhd_free_with_size(server.data,server.alloced);
	}
	if(content_type.alloced){
		jhd_free_with_size(content_type.data,content_type.alloced);
	}
	while(frame){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}

	while(jhd_queue_has_item(&h)){
		q = jhd_queue_next(&h);
		jhd_queue_only_remove(q);
		header = jhd_queue_data(q,jhd_http_header,queue);
		if(header->name_alloced){
			jhd_free_with_size(header->name,header->name_alloced);
		}
		if(header->value_alloced){
			jhd_free_with_size(header->value,header->value_alloced);
		}
		jhd_free_with_size(header,sizeof(jhd_http_header));
	}
}

int jhd_http2_write_request_headers_frame(jhd_event_t *ev){


}







static void jhd_http2_send_response_headers_frmae(jhd_event_t * ev){
	jhd_http2_frame *frame;
	uint16_t len,slen;
	jhd_queue_t h, *head,*q;
	jhd_http_header *header;


	u_char *p,*begin,*end;

	jhd_http_request *r = ev->data;
	frame = r->state_param;

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
	p+= (2+1+r->content_type.len);

	*p = 15;
	++p;
	*p = 54 - 15;
	++p;
	*p = r->server.len;
	++p;
	memcpy(p,r->server.data,r->server.len);
	len -= (2+1+r->server.len);
	p += (2+1+r->server.len);



	*p = 15;
	++p;
	*p = 44 - 15;
	++p;
	*p = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
	++p;
	memcpy(p,r->date.data,sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	len -= (2+1+sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
	p += (2+1+sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);

	if(r->content_length>=0){
		*p = 15;
		++p;
		*p = 28 - 15;
		++p;

		end = jhd_calc_buffer + 100;

		begin = jhd_u64_to_string(end,(uint64_t)r->content_length);

		slen = end - begin;


		*p = (u_char)slen;
		++p;
		memcpy(p,begin,slen);
		len -= (2+1+slen);
		p += (2+1+slen);
	}

	jhd_queue_init(&h);
    head = &r->headers;

    if(jhd_queue_has_item(head)){
    	for(;;){
    		q = jhd_queue_next(head);
			jhd_queue_only_remove(q);
			jhd_queue_insert_tial(&h,q);
			header = jhd_queue_data(q,jhd_http_header,queue);

			slen = jhd_http2_write_header(header);

			if(slen < len){
				memcpy(p,jhd_calc_buffer,slen);
				len -=slen;
				p+=slen;
				if(jhd_queue_emtpy(head)){
					slen = p - frame->pos;
					frame->len = slen;
					slen -= 9;
					frame->pos[0] = 0;
					frame->pos[1] = (u_char)(slen >> 8);
					frame->pos[2] = (u_char)(slen);
					frame->pos[5] = (u_char)(r->stream->id >> 24);
					frame->pos[6] = (u_char)(r->stream->id >> 16);
					frame->pos[7] = (u_char)(r->stream->id >> 8);
					frame->pos[8] = (u_char)(r->stream->id);
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

				frame->pos[5] = (u_char)(r->stream->id >> 24);
				frame->pos[6] = (u_char)(r->stream->id >> 16);
				frame->pos[7] = (u_char)(r->stream->id >> 8);
				frame->pos[8] = (u_char)(r->stream->id);

				if(jhd_queue_emtpy(head)){
					p = (u_char*)(frame->next);
					frame->next = NULL;
					break;
				}
				log_assert(frame->next != NULL);
				frame = frame->next;
				p = frame->pos +9;
				len = frame->len -9;
			}else{
				memcpy(p,jhd_calc_buffer,len);

				log_assert(frame->next!= NULL);
				log_assert(((jhd_http2_frame)(frame->next))->len -9 > (slen - len));



				p = ((jhd_http2_frame)(frame->next))->pos + 9;

				memcpy(p,jhd_calc_buffer+len,slen - len);

				p +=(slen-len);

				len = ((jhd_http2_frame)(frame->next))->len -9 + len - slen /* -(slen - len)*/;

				slen = frame->len - 9;

				frame->pos[0] = 0;
				frame->pos[1] = (u_char)(slen >> 8);
				frame->pos[2] = (u_char)(slen);

				frame->pos[5] = (u_char)(r->stream->id >> 24);
				frame->pos[6] = (u_char)(r->stream->id >> 16);
				frame->pos[7] = (u_char)(r->stream->id >> 8);
				frame->pos[8] = (u_char)(r->stream->id);


				frame = frame ->next;


				if(jhd_queue_emtpy(head)){
					slen = p - frame->pos;
					frame->len = slen;
					slen -= 9;
					frame->pos[0] = 0;
					frame->pos[1] = (u_char)(slen >> 8);
					frame->pos[2] = (u_char)(slen);
					frame->pos[5] = (u_char)(r->stream->id >> 24);
					frame->pos[6] = (u_char)(r->stream->id >> 16);
					frame->pos[7] = (u_char)(r->stream->id >> 8);
					frame->pos[8] = (u_char)(r->stream->id);
					p = (u_char*)(frame->next);
					frame->next = NULL;
					break;
				}
			}
    	}
    }else{


    }

















}
static void jhd_http2_alloc_response_headers_frame(jhd_event_t *ev){
	jhd_http2_frame **frame;
	uint16_t len;
	jhd_http_request *r = ev->data;
	frame = &r->headers_frame;
	while((*frame)->next){
		*frame = (*frame)->next;
	}
	do{
		if(r->state > (16384  - sizeof(jhd_http2_frame))){
			len = (16384  - sizeof(jhd_http2_frame));
		}else{
			len = r->state;
		}
		*frame = jhd_alloc(len+ 9 +sizeof(jhd_http2_frame));
		if(*frame == NULL){
			jhd_wait_mem(ev,len + 9+sizeof(jhd_http2_frame));
			jhd_event_add_timer(ev,0xFFFFFFFFFFFFFFFFULL,jhd_http2_alloc_headers_frame_timeout);
			return;
		}

		(*frame)->pos=(u_char*)(((u_char*)(*frame))+sizeof(jhd_http2_frame));
		(*frame)->data_len = len + 9 + sizeof(jhd_http2_frame);
		(*frame)->len = len + 9 ;
		(*frame)->free_func = jhd_http2_frame_free_by_single;
		(*frame)->next = NULL;

		r->state -= len;
		frame = &((*frame)->next);
	}while(r->state >0);
	if(ev->timer.key){
		jhd_event_del_timer(ev);
		ev->timeout = jhd_event_noop;
	}



}

void jhd_http2_write_response_headers_frame(jhd_event_t *ev){
	jhd_queue_t *head,*q;
	jhd_http_header *header;
	jhd_http_request *r = ev->data;

	log_assert(r->status >=100 &&(r->status <=999));
	if(r->status == 200){
		r->state = 1;
	}else if(r->status == 204){
		r->state = 1;
	}else if(r->status == 206){
		r->state = 1;
	}else if(r->status == 304){
		r->state = 1;
	}else if(r->status == 400){
		r->state = 1;
	}else if(r->status == 404){
		r->state = 1;
	}else if(r->status == 500){
		r->state = 1;
	}else{
		r->state =   5; //  jhd_http2_literal_size("100");
	}
	log_assert(r->server.len < 127);
    r->state += (2/*static hapck idx = 00001111 (54-15 )*/+1/* server.len */+r->server.len);
    r->state += (2/*static hapck idx = 00001111 (41-15 )*/+1/* content_type.len */+r->content_type.len);
    if(r->content_length>=0){
    	r->state += (2/*static hapck idx = 00001111 (38-15 )*/+1/* */+sizeof(INT64_MAX_STRING)-1);
    }
    //
    r->state += (2/*static hapck idx = 00001111 (31-15 )*/+1/* content_type.len */+sizeof("Wed, 31 Dec 1986 18:00:00 GMT")-1);

    head = &r->headers;
    q = jhd_queue_next(head);
    while(q != head){
    	header = jhd_queue_data(q,jhd_http_header,queue);
    	q = jhd_queue_next(q);
    	r->state += (1/*0x00*/ + 1/*1~126*/ +header->name_len + 4 + header->value_len);
    }

    r->headers_frame = NULL;
    ev->handler = jhd_http2_alloc_response_headers_frame;
    jhd_http2_alloc_headers_frame(ev);
}
