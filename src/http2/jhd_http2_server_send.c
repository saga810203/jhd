#include <http2/jhd_http2_server.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_queue.h>
#include <jhd_core.h>
#include <tls/jhd_tls_ssl.h>

void jhd_http2_server_send_event_handler_error_force(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_frame *frame,free_frame;
	u_char *p;
	jhd_event_handler_pt timeout;
	void (*frame_free_func)(void*);

	c= ev->data;
	h2c = c->data;

	free_frame.next = h2c->send.head;
	h2c->send.head = h2c->send.tail = NULL;

	ev->handler = jhd_connection_empty_write;
	h2c->send_error = 1;

	if(c->read.timer.key){
		log_assert(c->read.timeout != NULL);
		timeout = c->read.timeout;
		jhd_event_del_timer(&c->read);
		timeout(&c->read);
	}else{
		c->recv = jhd_connection_error_recv;
		jhd_unshift_event(&c->read,&jhd_posted_events);
	}

	frame = free_frame.next;

	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
}

void jhd_http2_server_send_event_handler_with_ssl_clean_force(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
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

		ssl = c->ssl;
		if (ssl->out_msglen) {
			for (;;) {
				rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
				if (rc >= 0) {
					log_assert(rc<= ssl->out_msglen);
					ssl->out_msglen -= rc;
					ssl->out_offt += rc;
					if (ssl->out_msglen) {
						jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_force);
						return;
					}else{
						break;
					}
				} else {
					err = errno;
					if (err == EAGAIN) {
						jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_force);
						return;
					} else if (err != EINTR) {
						jhd_http2_server_send_event_handler_error_force(ev);
						return;
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
							jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_force);
							goto func_do_free;
						}else{
							break;
						}
					} else {
						err = errno;
						if (err == EAGAIN) {
							jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_force);
							goto func_do_free;
						} else if (err != EINTR) {
							frame->next = h2c->send.head;
							h2c->send.head = free_frame.next;
							jhd_http2_server_send_event_handler_error_force(ev);
							return;
						}
					}
				}
			}while(h2c->send.head != NULL);
		}
//		if((h2c->processing ==0) && (c->read.timer.key == 0) && (jhd_queue_not_queued(&c->read.queue))){
//			jhd_unshift_event(&c->read,&jhd_posted_events);
//		}

func_do_free:
		frame = free_frame.next;
		while(frame != NULL){
			p = (u_char*)frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		return;

}


void jhd_http2_server_send_event_handler_error_timer(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_frame *frame,free_frame;
	u_char *p;
	jhd_event_handler_pt timeout;
	void (*frame_free_func)(void*);

	c = ev->data;
	h2c = c->data;

	free_frame.next = h2c->send.head;
	h2c->send.head = h2c->send.tail = NULL;

	ev->handler = jhd_connection_empty_write;

	h2c->send_error = 1;

	if(h2c->recv_error){
		log_assert(c->read.timeout != NULL);
		timeout = c->read.timeout;
		jhd_event_del_timer(&c->read);
		timeout(&c->read);
	}else if(c->read.timer.key){
		log_assert(c->read.timeout != NULL);
		timeout = c->read.timeout;
		jhd_event_del_timer(&c->read);
		timeout(&c->read);
	}else{
		c->recv = jhd_connection_error_recv;
		jhd_unshift_event(&c->read,&jhd_posted_events);
	}
	frame = free_frame.next;
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
}



void jhd_http2_server_send_event_handler_with_ssl_clean_by_timer(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
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

		ssl = c->ssl;
		if (ssl->out_msglen) {
			for (;;) {
				rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
				if (rc >= 0) {
					log_assert(rc<= ssl->out_msglen);
					ssl->out_msglen -= rc;
					ssl->out_offt += rc;
					if (ssl->out_msglen) {
						jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_timer);
						return;
					}else{
						break;
					}
				} else {
					err = errno;
					if (err == EAGAIN) {
						return;
					} else if (err != EINTR) {
						jhd_http2_server_send_event_handler_error_timer(ev);
						return;
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
							jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_timer);
							goto func_do_free;
						}else{
							break;
						}
					} else {
						err = errno;
						if (err == EAGAIN) {
							jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_timer);
							goto func_do_free;
						} else if (err != EINTR) {
							frame->next = h2c->send.head;
							h2c->send.head = free_frame.next;
							jhd_http2_server_send_event_handler_error_timer(ev);
							return;
						}
					}
				}
			}while(h2c->send.head != NULL);
		}

func_do_free:
		frame = free_frame.next;
		while(frame != NULL){
			p = (u_char*)frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
		return;
}



void jhd_http2_server_send_event_handler_error_trigger(jhd_event_t *ev){
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	jhd_http2_frame *frame,free_frame;
	u_char *p;
	jhd_event_handler_pt timeout;
	void (*frame_free_func)(void*);

	c = ev->data;
	h2c = c->data;

	free_frame.next = h2c->send.head;
	h2c->send.head = h2c->send.tail = NULL;

	ev->handler = jhd_connection_empty_write;

	h2c->send_error = 1;

	if(h2c->recv_error){
		jhd_unshift_event(&c->read,&jhd_posted_events);
	}else if(c->read.timer.key){
		log_assert(c->read.timeout != NULL);
		timeout = c->read.timeout;
		jhd_event_del_timer(&c->read);
		timeout(&c->read);
	}else{
		c->recv = jhd_connection_error_recv;
		jhd_unshift_event(&c->read,&jhd_posted_events);
	}
	frame = free_frame.next;
	while(frame != NULL){
		p = (u_char*)frame;
		frame_free_func = frame->free_func;
		frame = frame->next;
		frame_free_func(p);
	}
}


void jhd_http2_server_send_event_handler_with_ssl_clean_by_trigger(jhd_event_t *ev){
		jhd_connection_t *c;
		jhd_http2_connection *h2c;
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


		ssl = c->ssl;
		if (ssl->out_msglen) {
			for (;;) {
				rc = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
				if (rc >= 0) {
					log_assert(rc<= ssl->out_msglen);
					ssl->out_msglen -= rc;
					ssl->out_offt += rc;
					if (ssl->out_msglen) {
						jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_trigger);
						return;
					}else{
						break;
					}
				} else {
					err = errno;
					if (err == EAGAIN) {
						jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_trigger);
						return;
					} else if (err != EINTR) {
						jhd_http2_server_send_event_handler_error_trigger(ev);
						return;
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
							jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_trigger);
							goto func_do_free;
						}else{
							break;
						}
					} else {
						err = errno;
						if (err == EAGAIN) {
							jhd_event_add_timer(ev,h2c->conf->write_timeout,jhd_http2_server_send_event_handler_error_trigger);
							goto func_do_free;
						} else if (err != EINTR) {
							frame->next = h2c->send.head;
							h2c->send.head = free_frame.next;
							jhd_http2_server_send_event_handler_error_trigger(ev);
							return;
						}
					}
				}
			}while(h2c->send.head != NULL);
		}


		if((h2c->recv_error)){
			c->read.handler(&c->read);
		}
func_do_free:
		frame = free_frame.next;
		while(frame != NULL){
			p = (u_char*)frame;
			frame_free_func = frame->free_func;
			frame = frame->next;
			frame_free_func(p);
		}
}

