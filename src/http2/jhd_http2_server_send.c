#include <http2/jhd_http2_server.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_queue.h>
#include <jhd_core.h>
#include <tls/jhd_tls_ssl.h>



void jhd_http2_server_send_event_handler_with_ssl_clean_force(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
		jhd_queue_t *q;
		ssize_t rc;
		int err;
		uint16_t len;
		jhd_http2_frame *frame,free_frame;
		jhd_tls_ssl_context *ssl;
		u_char *p;
		void (*frame_free_func)(void*);


		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		c = ev->data;
		h2c = c->data;

		if(ev->timedout){
			ev->timedout = 0;
			log_err("http2(ssl) write timedout");
			free_frame.next = h2c->send.head;
			h2c->send.head = h2c->send.tail = NULL;
			goto func_error;
		}
		ssl = c->ssl;
		if (ssl->out_msglen) {
			for (;;) {
				rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
				if (rc >= 0) {
					log_assert(rc<= ssl->out_msglen);
					ssl->out_msglen -= rc;
					ssl->out_offt += rc;
					if (ssl->out_msglen) {
						return;
					}else{
						break;
					}
				} else {
					err = errno;
					if (err == EAGAIN) {
						return;
					} else if (err != EINTR) {
						free_frame.next = h2c->send.head;
						h2c->send.head = h2c->send.tail = NULL;
						goto func_error;
					}
				}
			}
		}

		free_frame.next = NULL;
		frame = &free_frame;

		if(h2c->send.head != NULL){
			do{
				len = h2c->send.max_fragmentation;
				for(;;){
					if(len >  h2c->send.head->len){
						memcpy(ssl->out_msg+ssl->out_msglen,h2c->send.head->pos,  h2c->send.head->len);
						len -= h2c->send.head->len;
						ssl->out_msglen+=h2c->send.head->len;
						frame->next = h2c->send.head;
						frame = h2c->send.head;
						if(frame->next){
							h2c->send.head = frame->next;
							frame->next = NULL;
						}else{
							h2c->send.head = h2c->send.tail = NULL;
							break;
						}
					}else if(len == h2c->send.head->len){
						memcpy(ssl->out_msg+ ssl->out_msglen,h2c->send.head->pos, len);
						ssl->out_msglen += len;
						frame->next = h2c->send.head;
						frame = h2c->send.head;
						if(frame->next){
							h2c->send.head = frame->next;
							frame->next = NULL;
						}else{
							h2c->send.head = h2c->send.tail = NULL;
						}
						break;
					}else{
						memcpy(ssl->out_msg + ssl->out_msglen,h2c->send.head->pos, len);
						ssl->out_msglen += len;
						h2c->send.head->pos +=len;
						h2c->send.head->len-=len;
						break;
					}
				}
				ssl->encrypt_func(ssl);
				ssl->out_offt = ssl->out_hdr;
				ssl->out_msglen += 5;
				for (;;) {
					rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
					if (rc >= 0) {
						log_assert(rc<= ssl->out_msglen);
						ssl->out_msglen -= rc;
						ssl->out_offt += rc;
						if (ssl->out_msglen) {
							goto func_do_free;
						}else{
							break;
						}
					} else {
						err = errno;
						if (err == EAGAIN) {
							goto func_do_free;
						} else if (err != EINTR) {
							frame->next = h2c->send.head;
							h2c->send.head = h2c->send.tail = NULL;
							goto func_error;
						}
					}
				}
			}while(h2c->send.head != NULL);
		}
		if((h2c->processing ==0) && (c->read.timer.key == 0) && (jhd_queue_not_queued(&c->read.queue))){
			jhd_unshift_event(&c->read);
		}

func_do_free:
		frame = free_frame.next;
		while(frame != NULL){
			p = frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		return;
func_error:
		h2c->send_error = 1;

		frame = free_frame.next;

		while(frame != NULL){
			p = frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		if(h2c->recv_error){
			jhd_unshift_event(&c->read,&jhd_posted_events);
		}else{
			ev = &c->read;
			q = &c->read.queue;
			if(jhd_queue_queued(q)){
				jhd_queue_only_remove(q);
			}
			if(ev->timer.key){
				jhd_event_del_timer(ev);
			}
			ev->timedout = 1;
			jhd_unshift_event(&c->read,&jhd_posted_events);
		}
}






void jhd_http2_server_send_event_handler_with_ssl_clean_by_timer(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
		jhd_queue_t *q;
		ssize_t rc;
		int err;
		uint16_t len;
		jhd_http2_frame *frame,free_frame;
		jhd_tls_ssl_context *ssl;
		u_char *p;
		void (*frame_free_func)(void*);


		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		c = ev->data;
		h2c = c->data;

		if(ev->timedout){
			ev->timedout = 0;
			log_err("http2(ssl) write timedout");
			free_frame.next = h2c->send.head;
			h2c->send.head = h2c->send.tail = NULL;
			goto func_error;
		}
		ssl = c->ssl;
		if (ssl->out_msglen) {
			for (;;) {
				rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
				if (rc >= 0) {
					log_assert(rc<= ssl->out_msglen);
					ssl->out_msglen -= rc;
					ssl->out_offt += rc;
					if (ssl->out_msglen) {
						return;
					}else{
						break;
					}
				} else {
					err = errno;
					if (err == EAGAIN) {
						return;
					} else if (err != EINTR) {
						free_frame.next = h2c->send.head;
						h2c->send.head = h2c->send.tail = NULL;
						goto func_error;
					}
				}
			}
		}

		free_frame.next = NULL;
		frame = &free_frame;

		if(h2c->send.head != NULL){
			do{
				len = h2c->send.max_fragmentation;
				for(;;){
					if(len >  h2c->send.head->len){
						memcpy(ssl->out_msg+ssl->out_msglen,h2c->send.head->pos,  h2c->send.head->len);
						len -=h2c->send.head->len;
						ssl->out_msglen+=h2c->send.head->len;
						frame->next = h2c->send.head;
						frame = h2c->send.head;
						if(frame->next){
							h2c->send.head = frame->next;
							frame->next = NULL;
						}else{
							h2c->send.head = h2c->send.tail = NULL;
						}
					}else if(len == h2c->send.head->len){
						memcpy(ssl->out_msg+ssl->out_msglen,h2c->send.head->pos, len);
						ssl->out_msglen += len;
						frame->next = h2c->send.head;
						frame = h2c->send.head;
						if(frame->next){
							h2c->send.head = frame->next;
							frame->next = NULL;
						}else{
							h2c->send.head = h2c->send.tail = NULL;
						}
						break;
					}else{
						memcpy(ssl->out_msg+ssl->out_msglen,h2c->send.head->pos, len);
						ssl->out_msglen += len;
						h2c->send.head->pos +=len;
						h2c->send.head->len-=len;
						break;
					}
				}
				ssl->encrypt_func(ssl);
				ssl->out_offt = ssl->out_hdr;
				ssl->out_msglen += 5;
				for (;;) {
					rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
					if (rc >= 0) {
						log_assert(rc<= ssl->out_msglen);
						ssl->out_msglen -= rc;
						ssl->out_offt += rc;
						if (ssl->out_msglen) {
							goto func_do_free;
						}else{
							break;
						}
					} else {
						err = errno;
						if (err == EAGAIN) {
							goto func_do_free;
						} else if (err != EINTR) {
							frame->next = h2c->send.head;
							h2c->send.head = h2c->send.tail = NULL;
							goto func_error;
						}
					}
				}
			}while(h2c->send.head != NULL);
		}
		if(h2c->processing ==0){
			if(h2c->recv_error){
				if(c->read.timer.key){
					jhd_event_del_timer(&c->read);
				}
				if(jhd_queue_not_queued(&c->read.queue)){
					jhd_unshift_event(&c->read);
				}
			}else if((c->read.timer.key == 0) && (jhd_queue_not_queued(&c->read.queue))){
				jhd_unshift_event(&c->read);
			}
		}

func_do_free:
		frame = free_frame.next;
		while(frame != NULL){
			p = frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		return;
func_error:
		h2c->send_error = 1;

		frame = free_frame.next;

		while(frame != NULL){
			p = frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		if(h2c->recv_error){
			jhd_unshift_event(&c->read,&jhd_posted_events);
		}else{
			ev = &c->read;
			q = &c->read.queue;
			if(jhd_queue_queued(q)){
				jhd_queue_only_remove(q);
			}
			if(ev->timer.key){
				jhd_event_del_timer(ev);
			}
			ev->timedout = 1;
			jhd_unshift_event(&c->read,&jhd_posted_events);
		}
}






void jhd_http2_server_send_event_handler_with_ssl_clean_by_trigger(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
		jhd_queue_t *q;
		ssize_t rc;
		int err;
		uint16_t len;
		jhd_http2_frame *frame,free_frame;
		jhd_tls_ssl_context *ssl;
		u_char *p;
		void (*frame_free_func)(void*);

		log_notice("==>%s",__FUNCTION__);
		log_assert_worker();
		c = ev->data;
		h2c = c->data;

		if(ev->timedout){
			ev->timedout = 0;
			log_err("http2(ssl) write timedout");
			free_frame.next = h2c->send.head;
			h2c->send.head = h2c->send.tail = NULL;
			goto func_error;
		}
		ssl = c->ssl;
		if (ssl->out_msglen) {
			for (;;) {
				rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
				if (rc >= 0) {
					log_assert(rc<= ssl->out_msglen);
					ssl->out_msglen -= rc;
					ssl->out_offt += rc;
					if (ssl->out_msglen) {
						return;
					}else{
						break;
					}
				} else {
					err = errno;
					if (err == EAGAIN) {
						return;
					} else if (err != EINTR) {
						free_frame.next = h2c->send.head;
						h2c->send.head = h2c->send.tail = NULL;
						goto func_error;
					}
				}
			}
		}

		free_frame.next = NULL;
		frame = &free_frame;

		if(h2c->send.head != NULL){
			do{
				len = h2c->send.max_fragmentation;
				for(;;){
					if(len >  h2c->send.head->len){
						memcpy(ssl->out_msg+ssl->out_msglen,h2c->send.head->pos,  h2c->send.head->len);
						len -=h2c->send.head->len;
						ssl->out_msglen+=h2c->send.head->len;
						frame->next = h2c->send.head;
						frame = h2c->send.head;
						if(frame->next){
							h2c->send.head = frame->next;
							frame->next = NULL;
						}else{
							h2c->send.head = h2c->send.tail = NULL;
						}
					}else if(len == h2c->send.head->len){
						memcpy(ssl->out_msg+ssl->out_msglen,h2c->send.head->pos, len);
						ssl->out_msglen += len;
						frame->next = h2c->send.head;
						frame = h2c->send.head;
						if(frame->next){
							h2c->send.head = frame->next;
							frame->next = NULL;
						}else{
							h2c->send.head = h2c->send.tail = NULL;
						}
						break;
					}else{
						memcpy(ssl->out_msg+ssl->out_msglen,h2c->send.head->pos, len);
						ssl->out_msglen += len;
						h2c->send.head->pos +=len;
						h2c->send.head->len-=len;
						break;
					}
				}
				ssl->encrypt_func(ssl);
				ssl->out_offt = ssl->out_hdr;
				ssl->out_msglen += 5;
				for (;;) {
					rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
					if (rc >= 0) {
						log_assert(rc<= ssl->out_msglen);
						ssl->out_msglen -= rc;
						ssl->out_offt += rc;
						if (ssl->out_msglen) {
							goto func_do_free;
						}else{
							break;
						}
					} else {
						err = errno;
						if (err == EAGAIN) {
							goto func_do_free;
						} else if (err != EINTR) {
							frame->next = h2c->send.head;
							h2c->send.head = h2c->send.tail = NULL;
							goto func_error;
						}
					}
				}
			}while(h2c->send.head != NULL);
		}
		if(h2c->recv_error){
			if(c->read.timer.key){
				jhd_event_del_timer(&c->read);
			}
			if(jhd_queue_not_queued(&c->read.queue)){
				jhd_unshift_event(&c->read);
			}
		}else if((h2c->processing ==0) && (c->read.timer.key == 0) && (jhd_queue_not_queued(&c->read.queue))){
			jhd_unshift_event(&c->read);
		}
func_do_free:
		frame = free_frame.next;
		while(frame != NULL){
			p = frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		return;
func_error:
		h2c->send_error = 1;

		frame = free_frame.next;

		while(frame != NULL){
			p = frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		if(h2c->recv_error){
			jhd_unshift_event(&c->read,&jhd_posted_events);
		}else{
			ev = &c->read;
			q = &c->read.queue;
			if(jhd_queue_queued(q)){
				jhd_queue_only_remove(q);
			}
			if(ev->timer.key){
				ev->timer.key = 0;
				jhd_event_del_timer(ev);
			}
			ev->timedout = 1;
			jhd_unshift_event(&c->read,&jhd_posted_events);
		}
}

