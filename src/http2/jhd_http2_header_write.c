#include <jhd_config.h>
#include <jhd_log.h>
#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>

#define jhd_http2_integer_octets(v)  (1 + (v) / 127)
#define jhd_http2_literal_size(h)  (jhd_http2_integer_octets(sizeof(h) - 1) + sizeof(h) - 1)


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

static void jhd_http2_alloc_headers_frame(jhd_event_t *ev){
	jhd_http2_frame **frame;
	uint16_t len;
	jhd_http_request *r = ev->data;
	frame = &r->headers_frame;
	while((*frame)->next){
		*frame = (*frame)->next;
	}
	do{
		if(r->state > (16384 - 9 - sizeof(jhd_http2_frame))){
			len = (16384 - 9 - sizeof(jhd_http2_frame));
		}else{
			len = r->state;
		}
		*frame = jhd_alloc(len+9+sizeof(jhd_http2_frame));
		if(*frame == NULL){
			jhd_wait_mem(ev,len+9+sizeof(jhd_http2_frame));
			jhd_event_add_timer(ev,0xFFFFFFFFFFFFFFFFULL,jhd_http2_alloc_headers_frame_timeout);
			return;
		}
		jhd_http2_single_frame_init(*frame,len+9+sizeof(jhd_http2_frame));

		r->state -= len;
		frame = &((*frame)->next);
	}while(r->state >0);
	if(ev->timer.key){
		jhd_event_del_timer(ev);
	}






}

void jhd_http2_write_response_headers_frame(jhd_event_t *ev){
	jhd_queue_t *head,*q;
	jhd_http_header *header;
	jhd_http_request *r = ev->data;
	if(r->state == 200){
		r->state = 1;
	}else if(r->state == 204){
		r->state = 1;
	}else if(r->state == 206){
		r->state = 1;
	}else if(r->state == 304){
		r->state = 1;
	}else if(r->state == 400){
		r->state = 1;
	}else if(r->state == 404){
		r->state = 1;
	}else if(r->state == 500){
		r->state = 1;
	}else{
		r->state =  2 + 4; //  jhd_http2_literal_size("100");
	}
	log_assert(r->server.len < 127);
    r->state += (2/*static hapck idx = 00001111 (54-15 )*/+1/* server.len */+r->server.len);
    r->state += (2/*static hapck idx = 00001111 (41-15 )*/+1/* content_type.len */+r->content_type.len);
    if(r->content_length>=0){
    	r->state += (2/*static hapck idx = 00001111 (38-15 )*/+1/* */+sizeof(INT64_MAX_STRING)-1);
    }
    //
    r->state += (2/*static hapck idx = 00001111 (41-15 )*/+1/* content_type.len */+sizeof("Wed, 31 Dec 1986 18:00:00 GMT")-1);

    head = &r->headers;
    q = jhd_queue_next(head);
    while(q != head){
    	header = jhd_queue_data(q,jhd_http_header,queue);
    	q = jhd_queue_next(q);
    	r->state += (1/*0x00*/ + 1/*1~126*/ +header->name_len + 4 + header->value_len);
    }

    r->headers_frame = NULL;
    ev->handler = jhd_http2_alloc_headers_frame;
    jhd_http2_alloc_headers_frame(ev);
}
