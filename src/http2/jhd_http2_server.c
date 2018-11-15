#include <http2/jhd_http2_server.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_queue.h>
#include <jhd_core.h>
#include <tls/jhd_tls_ssl_internal.h>


typedef struct{
		jhd_http_method mothed;
		u_char *uri;
		uint16_t uri_len;
		u_char *host;
		uint8_t host_len;
}jhd_http2_connection_server_param;






static void server_rst_stream(jhd_event_t *ev){
	jhd_http_header *header;
	jhd_queue_t h,*q;
	jhd_http2_frame *frame;
	uint32_t sid;
	u_char *p;

	event_h2c = ((jhd_connection_t*)ev->data)->data;

	if(ev->timedout){
		ev->timedout = 0;
		log_err("timeout");
		jhd_queue_move(&h,&event_h2c->recv.headers);
		event_h2c->conf->connection_read_error(ev);
		goto func_free;
	}
	frame = jhd_alloc(sizeof(jhd_http2_frame)+13);
	if(frame==NULL){
		jhd_wait_mem(ev,sizeof(jhd_http2_frame)+13);
		jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		return;
	}
	jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+13);
	frame->type = JHD_HTTP2_FRAME_TYPE_RST_STREAM_FRAME;

	p = frame->pos;
	//IN X86   00 00 03 08 = uint32_t
	*((uint32_t*)p) =0x03040000;
	p[4] = 0;
	p+=5;
	sid = event_h2c->recv.last_stream_id ;
	jhd_http2_set_stream_id(p,sid);
	p+=4;
	*((uint32_t*)p) = event_h2c->recv.state;
	jhd_http2_send_queue_frame(event_c,event_h2c,frame);
	event_h2c->recv.state = 0;
	ev->handler = event_h2c->recv.connection_frame_header_read;
	jhd_unshift_event(ev,&jhd_posted_events);
	jhd_queue_move(&h,&event_h2c->recv.headers);
func_free:
	for(q = h.next; q!= &h; q= q->next){
		jhd_queue_only_remove(q);
		header = jhd_queue_data(q,jhd_http_header,queue);
		jhd_http_free_header(header);
	}
}



































static void server_service(jhd_event_t *ev){
	jhd_http2_frame *frame;
	event_h2c = ((jhd_connection_t*)ev->data)->data;



	ev->handler = event_h2c->recv.connection_frame_header_read;
	jhd_unshift_event(ev,&jhd_posted_events);
}

static void server_create_request(jhd_event_t *ev){
	jhd_queue_t h,*head,*q;
	jhd_http_header *header;

	event_c = ev->data;
	event_h2c = event_c->data;


	event_h2c->recv.state_param =server_service= event_h2c->conf->extend_param;

	if(ev->timedout){
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		jhd_queue_move(&h, &event_h2c->recv.headers);

		if (event_h2c->recv.uri_header) {
			jhd_queue_insert(&h, &event_h2c->recv.uri_header->queue);
			event_h2c->recv.uri_header = NULL;
		}
		if (event_h2c->recv.host_header) {
			jhd_queue_insert(&h, &event_h2c->recv.host_header->queue);
			event_h2c->recv.host_header = NULL;
		}
		if (event_h2c->recv.method_header) {
			jhd_queue_insert(&h, &event_h2c->recv.method_header->queue);
			event_h2c->recv.method_header = NULL;
		}
		event_h2c->conf->connection_read_error(ev);
		for (q = h.next; q != &h; q = q->next) {
			jhd_queue_only_remove(q);
			header = jhd_queue_data(q, jhd_http_header, queue);
			jhd_http_free_header(header);
		}
	}else{








	}


}

static void server_end_headers_handler(jhd_event_t *ev){
	event_h2c = ((jhd_connection_t*)ev->data)->data;
	jhd_http2_stream *stream ;
	jhd_http_header *header;
	jhd_queue_t h,*head,*q;

	event_c = ev->data;
	event_h2c = event_c->data;

	if(ev->timedout){
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		jhd_queue_move(&h, &event_h2c->recv.headers);

		if (event_h2c->recv.uri_header) {
			jhd_queue_insert(&h, &event_h2c->recv.uri_header->queue);
			event_h2c->recv.uri_header = NULL;
		}
		if (event_h2c->recv.host_header) {
			jhd_queue_insert(&h, &event_h2c->recv.host_header->queue);
			event_h2c->recv.host_header = NULL;
		}
		if (event_h2c->recv.method_header) {
			jhd_queue_insert(&h, &event_h2c->recv.method_header->queue);
			event_h2c->recv.method_header = NULL;
		}
		event_h2c->conf->connection_read_error(ev);
		for (q = h.next; q != &h; q = q->next) {
			jhd_queue_only_remove(q);
			header = jhd_queue_data(q, jhd_http_header, queue);
			jhd_http_free_header(header);
		}


	}else{
		if(event_h2c->processing == 255){
			log_assert(event_h2c->recv.state_param == NULL);
			event_h2c->recv.state = JHD_HTTP2_REFUSED_STREAM_MAX_STREAM;
			ev->handler = server_rst_stream;
			server_rst_stream(ev);
		}else{
            if(event_h2c->recv.method_header == NULL){
            	head = &event_h2c->recv.headers;
            	for(q = jhd_queue_next(head);q != head;){
            		header = jhd_queue_data(q,jhd_http_header,queue);
            		q = jhd_queue_next(q);
            		if(header->name_len == 7 &&(0 == memcmp(header->name,":method"))){
            			if(event_h2c->recv.method_header){
            				log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_HEADERS_PAYLOAD);
            				goto func_error;
            			}
            			jhd_queue_only_remove(&header->queue);
            			event_h2c->recv.method_header = header;
            		}else if(header->name_len == 5 &&(0 == memcmp(header->name,":path"))){
            			if(event_h2c->recv.uri_header){
            				log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_HEADERS_PAYLOAD);
            				goto func_error;
            			}
            			jhd_queue_only_remove(&header->queue);
            			event_h2c->recv.uri_header = header;
            		}else  if(header->name_len == 10 &&(0 == memcmp(header->name,":authority"))){
            			if(event_h2c->recv.host_header){
            				log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_HEADERS_PAYLOAD);
            				goto func_error;
            			}
            			jhd_queue_only_remove(&header->queue);
            			event_h2c->recv.host_header = header;
            		}
            	}
            }
			stream = jhd_alloc(sizeof(jhd_http2_stream));
			if(stream== NULL){
				jhd_wait_mem(ev,sizeof(jhd_http2_stream));
				jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
			}else{
				//memset(stream,0,sizeof(jhd_http2_stream));
				stream->id = event_h2c->recv.last_stream_id;
				stream->recv_window_size = event_h2c->recv.init_window_size;
				stream->send_window_size = event_h2c->send.initial_window_size;

				if(event_h2c->recv.frame_flag & JHD_HTTP2_END_STREAM_FLAG){
					stream->in_close = 1;
				}
				stream->connection = event_h2c;
				jhd_queue_init(&stream->flow_control);
				q = &event_h2c->streams[(stream->id >> 1) & 0x1F/*31*/];
				jhd_queue_insert_tail(q,&stream->queue);
				++event_h2c->processing;
				event_h2c->recv.stream = stream;
				event_h2c->recv.state_param = stream;

				ev->handler =server_create_request;
				ev->handler(ev);
			}
		}
	}




func_invalid_headers:
		if (event_h2c->recv.uri_header) {
			jhd_queue_insert(&event_h2c->recv.headers, &event_h2c->recv.uri_header->queue);
			event_h2c->recv.uri_header = NULL;
		}
		if (event_h2c->recv.host_header) {
			jhd_queue_insert(&event_h2c->recv.headers, &event_h2c->recv.host_header->queue);
			event_h2c->recv.host_header = NULL;
		}
		if (event_h2c->recv.method_header) {
			jhd_queue_insert(&event_h2c->recv.headers, &event_h2c->recv.method_header->queue);
			event_h2c->recv.method_header = NULL;
		}






}


static void server_send_goaway_with_read_error(jhd_event_t *ev){
	jhd_http2_frame *frame;
    u_char *p;
	event_c = ev->data;
	event_h2c = event_c->data;
	log_assert(event_h2c->goaway_sent =0);
	if (ev->timedout) {
		ev->timedout = 0;
		ev->handler = event_h2c->recv.state_param;
		ev->handler(ev);
	} else {
		frame = jhd_alloc(sizeof(jhd_http2_frame)+ 17);
		if(frame != NULL){
			jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+17);
			frame->type = JHD_HTTP2_FRAME_TYPE_GOAWAY_FRAME;
			p = frame->pos;
			*((uint32_t*)p) = 0x07080000;
			p[4] = 0;
			p += 5;
			*((uint32_t*)p) = 0x0;
			p += 4;
			jhd_http2_set_stream_id(p,event_h2c->recv.last_stream_id);
			p += 4;
			*((uint32_t*)p) = event_h2c->recv.state;
			jhd_http2_send_queue_frame(event_c,event_h2c,frame);
			event_h2c->goaway_sent = 1;
			ev->handler = event_h2c->recv.state_param;
			ev->handler(ev);
		}else{
			jhd_wait_mem(ev,sizeof(jhd_http2_frame)+17);
			jhd_event_add_timer(ev,0xFFFFFFFFFFFFFFFFULL);
		}
	}
}


static void server_connection_read_event_error_with_clean_force(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_http2_frame *frame;
	u_char i;
	u_char *p;
	void (*frame_free_func)(void*);

	c = ev->data;
	h2c = c->data;
	jhd_queue_init(&free_queue);



	if(h2c->processing){
		for(i = 0, head = h2c->streams; i < 32 ; ++i,++head){
			while(jhd_queue_has_item(head)){
				q = jhd_queue_next(head);
				stream = jhd_queue_data(q,jhd_http2_stream,queue);
				h2c->recv.stream = stream;
				stream->listener->reset(ev);
				jhd_queue_only_remove(&stream->flow_control);
				jhd_queue_only_remove(q);
				jhd_queue_insert_tail(&free_queue,q);
			}
		}
		h2c->processing = 0;
	}
	frame = h2c->send.head;
	h2c->send.head = h2c->send.tail = NULL;
	c->close(c);
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}

static void server_ssl_connection_cleanup_with_timer(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_http2_frame *frame;
	jhd_tls_ssl_context *ssl;
	u_char i;
	u_char *p;
	void (*frame_free_func)(void*);

	jhd_queue_init(&free_queue);
	frame = NULL;

	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  || jhd_quit){
		if (h2c->processing) {
			for (i = 0, head = h2c->streams;((i < 32) && (h2c->processing)); ++i, ++head) {
				while (jhd_queue_has_item(head)) {
					q = jhd_queue_next(head);
					stream = jhd_queue_data(q, jhd_http2_stream, queue);
					h2c->recv.stream = stream;
					stream->listener->reset(ev);
					jhd_queue_only_remove(&stream->flow_control);
					jhd_queue_only_remove(q);
					jhd_queue_insert_tail(&free_queue,q);
				}
			}
		}
		frame = h2c->send.head;
		h2c->send.head = h2c->send.tail = NULL;
		goto func_close;
	}else{
		if(h2c->processing){
			head = &h2c->flow_control;
			while(jhd_queue_has_item(head)){
				q = jhd_queue_next(head);
				stream = jhd_queue_data(q,jhd_http2_stream,flow_control);
				h2c->recv.stream = stream;
				stream->listener->reset(ev);
				h2c->recv.stream = &jhd_http2_invalid_stream;
				jhd_queue_only_remove(&stream->queue);
				jhd_queue_only_remove(q);
				jhd_queue_insert_tail(&free_queue,q);
				--h2c->processing;
			}
		}
		if(h2c->processing){
			//500 1000  2000  4000 8000  16000 32000 64000 128000 256000  512000  1024000
			if(h2c->recv.state <1024000){
				h2c->recv.state *=2;
				jhd_event_add_timer(ev,h2c->recv.state);
				goto func_free;
			}
			for(i = 0, head = h2c->streams; ((i < 32) && (h2c->processing)) ; ++i,++head){
				while(jhd_queue_has_item(head)){
					q = jhd_queue_next(head);
					stream = jhd_queue_data(q,jhd_http2_stream,queue);
					h2c->recv.stream = stream;
					stream->listener->reset(ev);
					jhd_queue_only_remove(&stream->flow_control);
					jhd_queue_only_remove(q);
					jhd_queue_insert_tail(&free_queue,q);
					--h2c->processing;
				}
			}
			log_assert(h2c->processing==0);
			frame = h2c->send.head;
			h2c->send.head = h2c->send.tail = NULL;
			goto func_close;
		}
		if(h2c->send.head != NULL){
			if(h2c->recv.state <1024000){
				h2c->recv.state *=2;
				jhd_event_add_timer(ev,h2c->recv.state);
				goto func_free;
			}
			frame = h2c->send.head;
			h2c->send.head = h2c->send.tail = NULL;
			goto func_close;
		}
		ssl = c->ssl;
		if(ssl->out_msglen){
			if(h2c->recv.state <1024000){
				h2c->recv.state *=2;
				jhd_event_add_timer(ev,h2c->recv.state);
				return;
			}
			goto func_free;
		}
	}

func_close:
	log_assert(h2c->processing ==0);
	log_assert(h2c->send.head == NULL);
	c->close(c);
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}



static void server_ssl_connection_read_event_error_with_timer_clean_after_goaway_sent(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_http2_frame *frame;
	jhd_tls_ssl_context *ssl;
	u_char i;
	u_char *p;
	void (*frame_free_func)(void*);

	jhd_queue_init(&free_queue);
	frame = NULL;

	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  | jhd_quit){
		if (h2c->processing) {
			for (i = 0, head = h2c->streams; ((i < 32) && (h2c->processing)); ++i, ++head) {
				while (jhd_queue_has_item(head)) {
					q = jhd_queue_next(head);
					stream = jhd_queue_data(q, jhd_http2_stream, queue);
					jhd_queue_only_remove(q);
					jhd_queue_only_remove(&stream->flow_control);
					jhd_queue_insert_tail(&free_queue,q);
					--h2c->processing;
					h2c->recv.stream = stream;
					stream->listener->reset(ev);
				}
			}
		}
		frame = h2c->send.head;
		h2c->send.head = h2c->send.tail = NULL;
	}else{
		if(h2c->processing){
			head = &h2c->flow_control;
			while(jhd_queue_has_item(head)){
				q = jhd_queue_next(head);
				stream = jhd_queue_data(q,jhd_http2_stream,flow_control);

				jhd_queue_only_remove(q);
				jhd_queue_only_remove(&stream->queue);
				jhd_queue_insert_tail(&free_queue,&stream->queue);
				--h2c->processing;

				h2c->recv.stream = stream;
				stream->listener->reset(ev);
				h2c->recv.stream = &jhd_http2_invalid_stream;
			}
			if(h2c->processing){
				for(i = 0, head = h2c->streams; ((i < 32) && (h2c->processing)) ; ++i,++head){
					for(q = jhd_queue_next(head); q!= head;){
						stream = jhd_queue_data(q,jhd_http2_stream,queue);
						q = jhd_queue_next(q);
						if((stream->in_close==0)){
							jhd_queue_only_remove(&stream->flow_control);
							jhd_queue_only_remove(&stream->queue);
							jhd_queue_insert_tail(&free_queue,&stream->queue);
							--h2c->processing;

							h2c->recv.stream = stream;
							stream->listener->reset(ev);
							h2c->recv.stream = &jhd_http2_invalid_stream;
						}
					}
				}
			}
		}
		if(h2c->processing){
			h2c->recv.state = 1000;
			ev->handler = server_ssl_connection_cleanup_with_timer;
			jhd_event_add_timer(ev,h2c->recv.state);
			goto func_free;
		}else if(h2c->send.head != NULL){
			h2c->recv.state = 1000;
			ev->handler = server_ssl_connection_cleanup_with_timer;
			jhd_event_add_timer(ev,h2c->recv.state);
			goto func_free;
		} else {
			ssl = c->ssl;
			if(ssl->out_msglen){
				h2c->recv.state = 1000;
				ev->handler = server_ssl_connection_cleanup_with_timer;
				jhd_event_add_timer(ev,h2c->recv.state);
				goto func_free;
			}
		}
	}
	log_assert(h2c->processing ==0);
	log_assert(h2c->send.head == NULL);
	c->close(c);
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}


static void server_ssl_connection_read_event_error_with_timer_clean(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	c = ev->data;
	h2c = c->data;
	h2c->recv_error = 1;
	if(h2c->send_error  | jhd_quit | h2c->goaway_sent){
		ev->handler = server_ssl_connection_read_event_error_with_timer_clean_after_goaway_sent;
		server_ssl_connection_read_event_error_with_timer_clean_after_goaway_sent(ev);
	}else {
		log_assert(ev->timedout == 0);
		h2c->recv.state = jhd_http2_error_code;
		h2c->recv.state_param = server_ssl_connection_read_event_error_with_timer_clean_after_goaway_sent;
		ev->handler= server_send_goaway_with_read_error;
		server_send_goaway_with_read_error(ev);
	}
}



static void server_connection_cleanup_with_write_tigger(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_http2_frame *frame;
	u_char i;
	u_char *p;
	void (*frame_free_func)(void*);


	jhd_queue_init(&free_queue);
	frame = NULL;

	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  || jhd_quit){
		if (h2c->processing) {
			for (i = 0, head = h2c->streams;((i < 32) && (h2c->processing)); ++i, ++head) {
				while (jhd_queue_has_item(head)) {
					q = jhd_queue_next(head);
					stream = jhd_queue_data(q, jhd_http2_stream, queue);
					jhd_queue_only_remove(q);
					jhd_queue_only_remove(&stream->flow_control);
					jhd_queue_insert_tail(&free_queue,q);
					--h2c->processing;
					h2c->recv.stream = stream;
					stream->listener->reset(ev);

				}
			}
		}
		frame = h2c->send.head;
		h2c->send.head = h2c->send.tail = NULL;
	}else{
		if(h2c->processing){
			head = &h2c->flow_control;
			while(jhd_queue_has_item(head)){
				q = jhd_queue_next(head);
				stream = jhd_queue_data(q,jhd_http2_stream,flow_control);

				jhd_queue_only_remove(q);
				jhd_queue_only_remove(&stream->queue);
				jhd_queue_insert_tail(&free_queue,&stream->queue);
				--h2c->processing;

				h2c->recv.stream = stream;
				stream->listener->reset(ev);
				h2c->recv.stream = &jhd_http2_invalid_stream;
			}
		}
		if(h2c->processing){
			goto func_free;
		}
	}
	log_assert(h2c->processing ==0);
	log_assert(h2c->send.head == NULL);
	c->close(c);
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}



static void server_ssl_connection_read_event_error_with_writer_clean_after_goaway(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_stream *stream;
	jhd_queue_t *head,*q,free_queue;
	jhd_http2_frame *frame;
	jhd_tls_ssl_context *ssl;
	u_char i;
	u_char *p;
	void (*frame_free_func)(void*);

	frame = NULL;
	jhd_queue_init(&free_queue);
	c = ev->data;
	h2c = c->data;
	if(h2c->send_error  | jhd_quit){
		if (h2c->processing) {
			for (i = 0, head = h2c->streams; ((i < 32) && (h2c->processing)); ++i, ++head) {
				while (jhd_queue_has_item(head)) {
					q = jhd_queue_next(head);
					stream = jhd_queue_data(q, jhd_http2_stream, queue);
					jhd_queue_only_remove(q);
					jhd_queue_only_remove(&stream->flow_control);
					jhd_queue_insert_tail(&free_queue,q);
					--h2c->processing;
					h2c->recv.stream = stream;
					stream->listener->reset(ev);
				}
			}
		}
		frame = h2c->send.head;
		h2c->send.head = h2c->send.tail = NULL;
	}else{
		if(h2c->processing){
			head = &h2c->flow_control;
			while(jhd_queue_has_item(head)){
				q = jhd_queue_next(head);
				stream = jhd_queue_data(q,jhd_http2_stream,flow_control);
				jhd_queue_only_remove(q);
				jhd_queue_only_remove(&stream->queue);
				jhd_queue_insert_tail(&free_queue,&stream->queue);
				--h2c->processing;
				h2c->recv.stream = stream;
				stream->listener->reset(ev);
				h2c->recv.stream = &jhd_http2_invalid_stream;
			}
			if(h2c->processing){
				for(i = 0, head = h2c->streams; ((i < 32) && (h2c->processing)) ; ++i,++head){
					for(q = jhd_queue_next(head); q!= head;){
						stream = jhd_queue_data(q,jhd_http2_stream,queue);
						q = jhd_queue_next(q);
						if((stream->in_close==0)){
							jhd_queue_only_remove(&stream->queue);
							jhd_queue_insert_tail(&free_queue,&stream->queue);
							jhd_queue_only_remove(&stream->flow_control);
							--h2c->processing;
							h2c->recv.stream = stream;
							stream->listener->reset(ev);
							h2c->recv.stream = &jhd_http2_invalid_stream;
						}
					}
				}
			}
		}
		if(h2c->processing){
			ev->handler = server_connection_cleanup_with_write_tigger;
			if(ev->timer.key){
				jhd_event_del_timer(ev);
			}
			goto func_free;
		}else if(h2c->send.head != NULL){
			ev->handler = server_connection_cleanup_with_write_tigger;
			if(ev->timer.key){
				jhd_event_del_timer(ev);
			}
			goto func_free;
		} else {
			ssl = c->ssl;
			if(ssl->out_msglen){
				ev->handler = server_connection_cleanup_with_write_tigger;
				if(ev->timer.key){
					jhd_event_del_timer(ev);
				}
				goto func_free;
			}
		}
	}
	log_assert(h2c->processing ==0);
	log_assert(h2c->send.head = NULL);
	c->close(c);
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
func_free:
	while(jhd_queue_has_item(&free_queue)){
		q = jhd_queue_next(&free_queue);
		jhd_queue_only_remove(q);
		stream = jhd_queue_data(q,jhd_http2_stream,queue);
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}




static void server_ssl_connection_read_event_error_with_writer_clean(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	c = ev->data;
	h2c = c->data;
	h2c->recv_error = 1;
	if(h2c->send_error  | jhd_quit | h2c->goaway_sent){
		ev->handler = server_ssl_connection_read_event_error_with_writer_clean_after_goaway;
		server_ssl_connection_read_event_error_with_writer_clean_after_goaway(ev);
	}else {
		log_assert(ev->timedout == 0);
		h2c->recv.state = jhd_http2_error_code;
		h2c->recv.state_param = server_ssl_connection_read_event_error_with_writer_clean_after_goaway;
		ev->handler= server_send_goaway_with_read_error;
		server_send_goaway_with_read_error(ev);
	}
}







static void server_headers_frame_header_check(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(event_h2c = event_c->data);
	log_assert(jhd_queue_empty(&event_h2c->recv.headers));
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	if(event_h2c->recv.payload_len == 0){
		log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_HEADERS_PAYLOAD);
		event_h2c->conf->connection_read_error(ev);
	}else if((event_h2c->recv.sid & 0X80000001) != 1){
		log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_STREAM_ID);
		event_h2c->conf->connection_read_error(ev);
	}else if(event_h2c->recv.sid <= event_h2c->recv.last_stream_id){
		log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_STREAM_ID);
		event_h2c->conf->connection_read_error(ev);
	}else{
		event_h2c->recv.last_stream_id = event_h2c->recv.sid;
		ev->handler = jhd_http2_headers_frame_payload_handler;
		jhd_http2_headers_frame_payload_handler(ev);
	}
}



jhd_inline static jhd_bool server_send_all_over_with_ssl(jhd_connection_t *c,jhd_http2_connection *h2c){
	if(h2c->processing){
		return jhd_false;
	}else if(h2c->send.head != NULL){
		return jhd_false;
	}else if((((jhd_tls_ssl_context*)(c->ssl))->out_msglen)){
		return jhd_false;
	}
	return jhd_true;
}



void server_frame_header_read_after_goaway_with_ssl(jhd_event_t *ev){
	ssize_t ret;
	ssize_t len;
	u_char frame_type;
	log_notice("==>%s",__FUNCTION__);
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;

	if(ev->timedout){
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_ENHANCE_YOUR_CALM_READ_FRAME_HEADER);
		event_h2c->conf->connection_read_error(ev);
		log_notice("<==%s with timedout",__FUNCTION__);
		return;
	}
	len = 9 - event_h2c->recv.state;
	log_assert(len > 0);
	ret = event_c->recv(event_c,event_h2c->recv.buffer+ event_h2c->recv.state,len);
	if(ret >0){
		if(ret == len){
			event_h2c->recv.payload_len = (event_h2c->recv.buffer[0] << 16) | (event_h2c->recv.buffer[1] << 8) | (event_h2c->recv.buffer[2]);
			if(event_h2c->recv.payload_len> 16384){
				log_http2_err(JHD_HTTP2_FRAME_MAX_SIZE_ERROR);
				log_err("invalid frame payload length[%u]",event_h2c->recv.payload_len);
				event_h2c->conf->connection_read_error(ev);
				log_notice("<==%s with timedout",__FUNCTION__);
				return;
			}
			frame_type= event_h2c->recv.buffer[3];
			if(frame_type > JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME){
				log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_FRAME_TYPE);
				log_err("invalid frame type[0X%02X]",frame_type);
				event_h2c->conf->connection_read_error(ev);
				log_notice("<==%s with timedout",__FUNCTION__);
				return;
			}
			event_h2c->recv.frame_flag = event_h2c->recv.buffer[4];
			event_h2c->recv.state = 0;

			if(frame_type == JHD_HTTP2_FRAME_TYPE_HEADERS_FRAME  || frame_type == JHD_HTTP2_FRAME_TYPE_CONTINUATION_FRAME){
				jhd_http2_do_recv_skip(ev,event_h2c,event_h2c->recv.payload_len,server_frame_header_read_after_goaway_with_ssl);
			}else{
				ev->handler = event_h2c->conf->frame_payload_handler_pts[frame_type];
				ev->handler(ev);
			}
			log_notice("<==%s with timedout",__FUNCTION__);
		}else{
			event_h2c->recv.state +=ret;
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
			log_notice("<==%s EAGAIN",__FUNCTION__);
		}
	}else if(ret == JHD_AGAIN){
		if(event_h2c->recv.state==0 ){
			if(server_send_all_over_with_ssl(event_c,event_h2c)){
				event_c->close(event_c);
			}else if(event_h2c->send_error){
				server_connection_read_event_error_with_clean_force(ev);
			}else if(ev->timer.key){
				jhd_event_del_timer(ev);
			}
		}else{
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
		}
		log_notice("<==%s EAGAIN",__FUNCTION__);
	}else{
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
		event_h2c->conf->connection_read_error(ev);
		log_notice("<==%s error",__FUNCTION__);
	}
}















void server_goaway_frame_handler(jhd_event_t *ev){
	jhd_http2_frame *frame;
	u_char *p;
	log_assert_worker();
	event_c = ev->data;
	event_h2c = event_c->data;
	if (ev->timedout) {
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_read_error(ev);
	}else if(event_h2c->goaway_sent==0){
		frame = jhd_alloc(sizeof(jhd_http2_frame)+ 17);
		if(frame != ((void *)0)){
			jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+17);
			frame->type =JHD_HTTP2_FRAME_TYPE_GOAWAY_FRAME;
			p = frame->pos;
			*((uint32_t*)p) = 0x07080000;
			p[4] = 0;
			p += 5;
			*((uint32_t*)p) = 0x0;
			p += 4;
			jhd_http2_set_stream_id(p,event_h2c->recv.last_stream_id);
			p += 4;
			*((uint32_t*)p) = 0x0;
			jhd_http2_send_queue_frame(event_c,event_h2c,frame);
			event_h2c->goaway_sent = 1;
			event_h2c->recv.connection_frame_header_read = event_h2c->conf->connection_frame_header_read_after_goaway;
			event_h2c->recv.connection_frame_header_read(ev);
		}else{
			jhd_wait_mem(ev,sizeof(jhd_http2_frame)+17);
			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		}
	}else{
		ev->handler= event_h2c->recv.connection_frame_header_read;
		ev->handler(ev);
	}
}

void server_goaway_frame_header_check(jhd_event_t *ev){
	log_assert(event_c  = ev->data);
	log_assert(&event_c->read == ev);
	log_assert(event_h2c = event_c->data);
#if !defined(JHD_LOG_ASSERT_ENABLE)
	(void*) ev;
#endif
	event_h2c->goaway_recved = 1;
	if(event_h2c->recv.payload_len <8){
		log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_GOAWAY_PAYLOAD);
		event_h2c->conf->connection_read_error(ev);
	}else{
		event_h2c->recv.state_param = server_goaway_frame_handler;
		jhd_http2_goaway_payload_recv(ev);
	}
}



static void server_send_goaway_in_idle_handler(jhd_event_t *ev){
	jhd_http2_frame *frame;
    u_char *p;
	event_c = ev->data;
	event_h2c = event_c->data;
	log_assert(event_h2c->goaway_sent =0);
	if (ev->timedout) {
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_h2c->conf->connection_read_error(ev);
	} else {
		frame = jhd_alloc(sizeof(jhd_http2_frame)+ 17);
		if(frame != NULL){
			jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+17);
			frame->type = JHD_HTTP2_FRAME_TYPE_GOAWAY_FRAME;
			p = frame->pos;
			*((uint32_t*)p) = 0x07080000;
			p[4] = 0;
			p += 5;
			*((uint32_t*)p) = 0x0;
			p += 4;
			jhd_http2_set_stream_id(p,event_h2c->recv.last_stream_id);
			p += 4;
			*((uint32_t*)p) = 0x0;
			jhd_http2_send_queue_frame(event_c,event_h2c,frame);
			event_h2c->goaway_sent = 1;
			event_h2c->recv.connection_frame_header_read = event_h2c->conf->connection_frame_header_read_after_goaway;
			event_h2c->recv.connection_frame_header_read(ev);
		}else{
			jhd_wait_mem(ev,sizeof(jhd_http2_frame)+17);
			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
		}
	}
}

static void server_idle_check_handler(jhd_event_t *ev){
	log_assert_worker();
	event_h2c =((jhd_connection_t*)(ev->data))->data;
	if (ev->timedout) {
		ev->timedout = 0;
		if(event_h2c->send_error){
			event_h2c->conf->connection_read_error(ev);
		}else{
			ev->handler = server_send_goaway_in_idle_handler;
			server_send_goaway_in_idle_handler(ev);
		}
	}else {
        ev->handler = event_h2c->recv.connection_frame_header_read;
        ev->handler(ev);
	}
}
static void server_idle_handler(jhd_event_t *ev){
	log_assert(event_c == ev->data);
	log_assert(event_h2c== event_c->data);
	ev->handler = server_idle_check_handler;
	jhd_event_add_timer(ev,event_h2c->conf->idle_timeout);
}

//static void server_connection_close_stream_with_read_fail(jhd_event_t *ev){
//	jhd_connection_t *c;
//	jhd_http2_connection *h2c;
//	jhd_http2_stream *stream;
//	jhd_queue_t *head,*q;
//	u_char i;
//	c = ev->data;
//	h2c = c->data;
//	if(h2c->processing){
//		head = &h2c->flow_control;
//		while(jhd_queue_has_item(head)){
//			q = jhd_queue_next(head);
//			jhd_queue_only_remove(q);
//			stream = jhd_queue_data(q,jhd_http2_stream,flow_control);
//			jhd_queue_only_remove(&stream->queue);
//			--h2c->processing;
//			h2c->recv.stream = stream;
//			stream->listener->reset(ev);
//			jhd_free_with_size(stream,sizeof(jhd_http2_stream));
//		}
//
//	}
//	if(h2c->processing){
//		for(i = 0, head = &h2c->streams; i < 32 ; ++i,++head){
//			for(q = jhd_queue_next(head); q != head ;){
//				stream = jhd_queue_data(q,jhd_http2_stream,queue);
//				q = q->next;
//
//				if((stream->state & JHD_HTTP2_STREAM_STATE_CLOSE_REMOTE) == 0){
//					jhd_queue_only_remove(&stream->queue);
//					--h2c->processing;
//					h2c->recv.stream = stream;
//					stream->listener->reset(ev);
//					jhd_free_with_size(stream,sizeof(jhd_http2_stream));
//				}
//			}
//		}
//	}
//	h2c->recv.stream = &jhd_http2_invalid_stream;
//}
//
//
//static void server_connection_read_event_handler_after_read_error(jhd_event_t *ev){
//	jhd_connection_t *c;
//	jhd_http2_connection *h2c;
//	jhd_http2_stream *stream;
//	jhd_queue_t *head,*q;
//	u_char i;
//	u_char *p;
//	int rc;
//	void (*free_func)(void* data);
//	jhd_http2_frame *frame;
//
//	c = ev->data;
//	h2c = c->data;
//
//	if( (h2c->send_error) ||  (jhd_quit)){
//		if(h2c->processing){
//			for(i = 0, head = &h2c->streams; i < 32 ; ++i,++head){
//				while(jhd_queue_has_item(head)){
//					q = jhd_queue_next(head);
//					jhd_queue_only_remove(q);
//					stream = jhd_queue_data(q,jhd_http2_stream,queue);
//					jhd_queue_init(&stream->flow_control);
//					h2c->recv.stream = stream;
//					stream->listener->reset(ev);
//					jhd_free_with_size(stream,sizeof(jhd_http2_stream));
//				}
//			}
//			h2c->processing = 0;
//		}
//		frame = h2c->send.head;
//		while(frame != NULL){
//			p = frame;
//			free_func = frame->free_func;
//			frame = frame->next;
//			free_func(p);
//		}
//		//free http2_connection;
//		h2c->close_pt(c);
//	}else{
//		head = &h2c->flow_control;
//		while(jhd_queue_has_item(head)){
//			q = jhd_queue_next(head);
//			jhd_queue_only_remove(q);
//			stream = jhd_queue_data(q,jhd_http2_stream,flow_control);
//			jhd_queue_only_remove(&stream->queue);
//			--h2c->processing;
//			h2c->recv.stream = stream;
//			stream->listener->reset(ev);
//			jhd_free_with_size(stream,sizeof(jhd_http2_stream));
//		}
//		h2c->recv.stream = &jhd_http2_invalid_stream;
//		if(!h2c->processing){
//			if(h2c->send.tail == NULL){
//            if(h2c->conf->ssl){
//            	log_assert(c->ssl!= NULL);
//            	rc=jhd_tls_ssl_flush(c,(jhd_tls_ssl_context*)c->ssl);
//            	if(rc == JHD_AGAIN){
//
//            	}
//
//
//            }
//			//free http2_connection;
//			h2c->close_pt(c);
//		}
//	}
//}









void jhd_http2_only_by_clean_server_connection_start(jhd_connection_t *c){

}
void jhd_http2_only_by_tls_server_connection_start(jhd_connection_t *c){

}


static char *jhd_http_alpn_list[]={"h2","http/1.1",NULL};


static void jhd_http2_server_connection_close_with_ssl(jhd_connection_t *c){
		jhd_http2_connection *h2c;
		h2c = c->data;
		jhd_connection_tls_close(c);
		if(h2c->recv.hpack.capacity){
			jhd_http2_hpack_free(&h2c->recv.hpack);
		}
		if(h2c->send.hpack.capacity){
			jhd_http2_hpack_free(&h2c->send.hpack);
		}
		jhd_free_with_size(h2c,sizeof(jhd_http2_connection));
	}

static int jhd_http2_server_connection_alloc_with_ssl(jhd_event_t *ev){
	u_char i;
	jhd_queue_t *head;
	jhd_http2_connection_conf *conf;
	log_assert_worker();
	log_notice("==>%s",__FUNCTION__);
	event_c = ev->data;
	event_h2c = event_c->data;
	conf = &((jhd_http_listenning_ctx*)(event_c->listening->lis_ctx))->h2_conf;
	if(event_h2c == NULL){
		event_c->data = event_h2c = jhd_alloc(sizeof(jhd_http2_connection));
		if(event_h2c == NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_connection));
			return JHD_AGAIN;
		}else{
			memset(event_h2c,0,sizeof(jhd_http2_connection));
			jhd_queue_init(&event_h2c->flow_control);
			for(i = 0,head = event_h2c->streams;i < 32;++i,++head){
				jhd_queue_init(head);
			}
			event_h2c->recv.stream = &jhd_http2_invalid_stream;
			event_h2c->recv.init_window_size = 65535;
			event_h2c->recv.window_size = 65535;
			jhd_queue_init(&event_h2c->recv.headers);
			event_h2c->send.initial_window_size = 65536;
			event_h2c->send.window_size = 65535;

			if(event_c->send == jhd_tls_ssl_write_512){
				event_h2c->send.max_fragmentation = 512;
			}else if(event_c->send == jhd_tls_ssl_write_1024){
				event_h2c->send.max_fragmentation = 1024;
			}else if(event_c->send == jhd_tls_ssl_write_2048){
				event_h2c->send.max_fragmentation = 2048;
			}else if(event_c->send == jhd_tls_ssl_write_4096){
				event_h2c->send.max_fragmentation = 4096;
			}else{
				log_assert(event_c->send == jhd_tls_ssl_write);
				event_h2c->send.max_fragmentation = 15 * 1024;	// 5+ iv+ msg+tag;
			}
			event_h2c->recv.connection_frame_header_read = jhd_http2_frame_header_read;
			event_h2c->recv.connection_end_headers_handler = server_end_headers_handler;
			event_h2c->conf = conf;
			event_c->close = jhd_http2_server_connection_close_with_ssl;
		}
	}
	if(event_h2c->recv.hpack.capacity ==0){
		if(JHD_OK !=jhd_http2_hpack_init(&event_h2c->recv.hpack,4096)){
			jhd_wait_mem(ev,4096);
			return JHD_AGAIN;
		}
	}
	if(event_h2c->send.hpack.capacity ==0){
		if(JHD_OK !=jhd_http2_hpack_init(&event_h2c->send.hpack,4096)){
			jhd_wait_mem(ev,4096);
			return JHD_AGAIN;
		}
	}
	return JHD_OK;
}


void jhd_http11_init_with_alpn(jhd_event_t *ev){
//	jhd_connection_t *c;
//	jhd_http2_connection_conf *conf;
//	int ret;
//	log_assert_worker();
//	c = ev->data;
//
//	jhd_event_with_timeout(ev){
//		c->close(c);
//		return;
//	}
//
//	conf = &((jhd_listening_config_ctx_with_alpn*)(c->listening->lis_ctx))->h2_conf;
//
//	if(JHD_OK !=jhd_http2_server_connection_alloc(&c->data,ev,conf)){
//		return;
//	}
//
//




}

static void server_recv_first_setting_frame(jhd_event_t *ev){
	ssize_t rc;
	event_c = ev->data;
	event_h2c = event_c->data;
	if (ev->timedout) {
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_TIMEOUT);
		jhd_free_with_size(event_h2c->send.head, sizeof(jhd_http2_frame) + 9 + 12);
		event_c->close(event_c);
	} else {
		rc = event_c->recv(event_c,event_h2c->recv.buffer+ event_h2c->recv.state,8 - event_h2c->recv.state);
		if(rc >0){
			event_h2c->recv.state +=rc;
			if(event_h2c->recv.state > 4){
				if(event_h2c->recv.buffer[3] == JHD_HTTP2_FRAME_TYPE_SETTINGS_FRAME){
					if(event_h2c->recv.buffer[4] == 0x0){
						rc = event_h2c->recv.buffer[0] <<16 ||  event_h2c->recv.buffer[1] <<8 || event_h2c->recv.buffer[2];
						if(rc % 6 == 0){
							log_assert_code(event_h2c->first_frame_header_read = 1;)
							ev->handler = event_h2c->recv.connection_frame_header_read = jhd_http2_frame_header_read;
							event_c->write.handler = event_h2c->conf->connection_write;
							jhd_unshift_event(&event_c->write,&jhd_posted_events);
							jhd_unshift_event(ev,&jhd_posted_events);
							return;
						}

					}
				}
				log_http2_err(JHD_HTTP2_PROTOCOL_ERROR_INVALID_FIRST_FRAME);
				jhd_free_with_size(event_h2c->send.head, sizeof(jhd_http2_frame) + 9 + 12);
				event_c->close(event_c);
			}else{
				jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
			}
		}else if(rc == JHD_AGAIN){
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
		}else{
			log_http2_err(JHD_HTTP2_INTERNAL_ERROR_READ_IO);
			jhd_free_with_size(event_h2c->send.head, sizeof(jhd_http2_frame) + 9 + 12);
			event_c->close(event_c);
		}
	}
}

static void server_send_setting_frame(jhd_event_t *ev){
	u_char *p;
	jhd_http2_frame *frame;
	event_c = ev->data;
	event_h2c = event_c->data;
	if(ev->timedout){
		ev->timedout = 0;
		log_http2_err(JHD_HTTP2_INTERNAL_ERROR_MEM_TIMEOUT);
		event_c->close(event_c);
	}else{
		frame = jhd_alloc(sizeof(jhd_http2_frame)+9+12);
		if(frame == NULL){
			jhd_wait_mem(ev,sizeof(jhd_http2_frame)+9+12);
			jhd_event_add_timer(ev,event_h2c->conf->wait_mem_timeout);
			return;
		}
		jhd_http2_single_frame_init(frame,sizeof(jhd_http2_frame)+9+12);
		frame->type = JHD_HTTP2_FRAME_TYPE_SETTINGS_FRAME;
		p = frame->pos;
		//000018  len  type 04
		*((uint32_t*)p) = 0x040C0000;
		p[4] = 0;
		p+=5;
		*((uint32_t*)p) = 0;
		p+=4;
		//SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
		*p= 0;
		++p;
		*p = 0x03;
		++p;
		*((uint32_t*)p) = 0x0FF00000;
		p+=4;
		//SETTINGS_INITIAL_WINDOW_SIZE (0x4)
		*p= 0;
		++p;
		*p = 0x04;
		++p;
		*((uint32_t*)p) = 0x00400000; //16384
		event_h2c->send.head = frame;
		event_h2c->send.tail = frame;
		ev->handler = server_recv_first_setting_frame;
		server_recv_first_setting_frame(ev);
	}
}

void jhd_http2_read_preface(jhd_event_t *ev){
		u_char preface[24];
		int ret;
		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		event_c = ev->data;
		event_h2c = event_c->data;
		jhd_event_with_timeout(ev){
			log_err("timedout");
			event_c->close(event_c);
			log_notice("<==%s with timedout",__FUNCTION__);
			return;
		}
		event_h2c = event_c->data;
		log_assert(event_h2c->recv.state< 24);
		ret = event_c->recv(event_c,preface,24 - event_h2c->recv.state);
		if(ret >0){
			log_buf_info("read buf=>",preface,ret);
			if(memcmp(preface,jhd_http2_preface+ event_h2c->recv.state,ret)!=0){
				log_err("invalid http2 preface");
				event_c->close(event_c);
				log_notice("<==% with invalid httppreface",__FUNCTION__);
				return;
			}
			event_h2c->recv.state += ret;
			if(event_h2c->recv.state == 24){
				log_info("read http2 preface success");
				event_h2c->recv.state = 0;
				ev->handler =server_send_setting_frame;
				server_send_setting_frame(ev);
			}else{
				jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
			}
		}else if(ret == JHD_AGAIN){
			jhd_event_add_timer(ev,event_h2c->conf->read_timeout);
		}else{
			event_c->close(event_c);
		}
		log_notice("<==%s",__FUNCTION__);
}

void jhd_http2_init_with_alpn(jhd_event_t *ev){
	log_assert_worker();
	event_c = ev->data;
	if(ev->timedout){
		ev->timedout = 0;
		event_c->close(event_c);
	}else{
		if(JHD_OK ==jhd_http2_server_connection_alloc_with_ssl(ev)){
			ev->handler = jhd_http2_read_preface;
			jhd_http2_read_preface(ev);
		}else{
			jhd_event_add_timer(ev,((jhd_http_listenning_ctx*)(event_c->listening->lis_ctx))->h2_conf.wait_mem_timeout);
		}
	}
}


void jhd_http2_alpn_handshake(jhd_event_t *ev){
	jhd_connection_t *c;
	int ret;
	log_assert_worker();
	c = ev->data;
	if(ev->timedout){
		ev->timedout = 0;
		c->close(c);
	}else{
		ret = jhd_connection_tls_handshark(c);
		if(ret == JHD_OK){
			if(((jhd_tls_ssl_context*)(c->ssl))->alpn_chosen ==jhd_http_alpn_list[0]){
				ev->handler = jhd_http2_init_with_alpn;
				jhd_http2_init_with_alpn(ev);
			}else{
				ev->handler = jhd_http11_init_with_alpn;
				jhd_http11_init_with_alpn(ev);
			}
		}else if(ret != JHD_AGAIN){
			c->close(c);
		}
	}
}

void jhd_http2_alpn_recv_start(jhd_event_t *ev){
	int ret;
	log_assert_worker();
	event_c = ev->data;
	if(ev->timedout){
		ev->timedout = 0;
		event_c->close(event_c);
		return;
	}
	if(event_c->ssl == NULL){
		if(JHD_OK != jhd_tls_ssl_context_alloc(ev)){
			jhd_event_add_timer(ev,event_c->listening->wait_mem_timeout);
			return;
		}
	}
	ret = jhd_connection_tls_handshark(event_c);
	if(ret == JHD_AGAIN){
		ev->handler = jhd_http2_alpn_handshake;
		jhd_event_add_timer(ev,event_c->listening->read_timeout);
	}else if(ret == JHD_OK){
		if(((jhd_tls_ssl_context*)(event_c->ssl))->alpn_chosen ==jhd_http_alpn_list[0]){
			ev->handler = jhd_http2_init_with_alpn;
			jhd_http2_init_with_alpn(ev);
		}else{
			ev->handler = jhd_http11_init;
			jhd_http11_init(ev);
		}
	}else{
		event_c->close(event_c);
	}
}
void jhd_http2_with_alpn_server_connection_start(jhd_connection_t *c){
	log_assert_worker();
	log_assert(((jhd_tls_ssl_config*) c->listening->ssl)->server_side == JHD_TLS_SSL_IS_SERVER);
	c->write.handler = jhd_connection_tls_empty_write;
	c->read.handler = jhd_http2_alpn_recv_start;
	c->read.queue.next = NULL;
	c->write.queue.next = NULL;
    c->ssl = NULL;
    c->close = jhd_connection_tls_close;
	jhd_post_event(&c->read,&jhd_posted_events);
}















static jhd_event_handler_pt server_frame_handlers[]={
		jhd_http2_data_frame_header_check,//DATA
		server_headers_frame_header_check,//HEADERS
		jhd_http2_priority_frame_header_check,//PRIORITY
		jhd_http2_rst_stream_frame_header_check,//RST_STREAM
		jhd_http2_setting_frame_header_check,//SETTING
		jhd_http2_unsupported_frame_type,//PUSH_PROMISE
		jhd_http2_ping_frame_header_check,//PING
		server_goaway_frame_header_check,//GO_AWAY
		jhd_http2_window_update_frame_header_check,//WINDOW_UPDATE
		jhd_http2_unsupported_frame_type,//CONTINUATION
};




void jhd_http2_server_connection_conf_init(jhd_http2_connection_conf *conf,jhd_http2_error_handler_type type){
	jhd_http2_servcer_service *service;

	memset(conf,0,sizeof(jhd_http2_connection_conf));
	conf->wait_mem_timeout = 1000;
	conf->read_timeout = 1000;
	conf->idle_timeout = 60 * 1000;
	conf->write_timeout = 1000;
	conf->server_side = 1;
	conf->ssl = 1;
	conf->recv_window_size_threshold = 50*1024*1024;
	conf->frame_payload_handler_pts =server_frame_handlers;
	conf->connection_idle = server_idle_handler;
	conf->connection_frame_header_read_after_goaway = server_frame_header_read_after_goaway_with_ssl;
	if(type == JHD_HTTP2_ERROR_CLOSE_BY_FORCE){
		conf->connection_read_error = server_connection_read_event_error_with_clean_force;
		conf->connection_write = jhd_http2_server_send_event_handler_with_ssl_clean_force;
	}else if(type == JHD_HTTP2_ERROR_CLOSE_BY_TIMER){
		conf->connection_read_error = server_ssl_connection_read_event_error_with_timer_clean;
		conf->connection_write = jhd_http2_server_send_event_handler_with_ssl_clean_by_timer;
	}else{
		conf->connection_read_error = server_ssl_connection_read_event_error_with_writer_clean;
		conf->connection_write = jhd_http2_server_send_event_handler_with_ssl_clean_by_trigger;
	}
	conf->extend_param = service = malloc(sizeof(jhd_http2_servcer_service));
	service->servcie = server_service;

}


















