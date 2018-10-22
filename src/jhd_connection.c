/*
 * jhd_connection.c
 *
 *  Created on: May 25, 2018
 *      Author: root
 */
#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_event.h>
#include <jhd_core.h>
#include <jhd_connection.h>
#include <jhd_http.h>
#include <jhd_log.h>

jhd_connection_t *g_connections;

static jhd_queue_t g_listening_queue;

static jhd_queue_t inherited_listening_queue = { &inherited_listening_queue, &inherited_listening_queue };

static jhd_listener_t m_connection_listener;
static jhd_listener_t w_connection_listener;

static jhd_connection_t *free_connections;

int listening_count;
int connection_count;
int free_connection_count;

jhd_listening_t* jhd_listening_get(char *addr_text, size_t len) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	head = &g_listening_queue;
	for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		if ((lis->addr_text_len == len) && (0 == strncmp(addr_text,lis->addr_text,len))) {
			return lis;
		}
	}
	return NULL;
}

jhd_bool jhd_listening_add_server(jhd_listening_t *lis, void *http_server) {
	void **old_http_servers;
	old_http_servers = lis->http_servers;
	lis->http_servers = malloc(sizeof(void*) * (lis->http_server_count + 1));
	if (lis->http_servers == NULL) {
		lis->http_servers = old_http_servers;
		return jhd_false;
	}
	if (old_http_servers) {
		memcpy(lis->http_servers, old_http_servers, sizeof(void*) * lis->http_server_count);
		free(old_http_servers);
	}
	lis->http_servers[lis->http_server_count] = http_server;
	++lis->http_server_count;
	return jhd_true;

}
void jhd_listening_free(jhd_listening_t* lis, jhd_bool close_socket) {

	if (close_socket && (lis->fd != -1)) {
		close(lis->fd);
		lis->fd = -1;
	}
	if (lis->addr_text) {
		free(lis->addr_text);
	}
	if (lis->http_servers) {
		free(lis->http_servers);
	}
	free(lis);
}

int jhd_open_listening_sockets(jhd_listening_t *lis) {
	int reuseaddr, reuseport;
	jhd_queue_t *q;
	struct sockaddr *saddr;
	int fd;
	reuseaddr = 1;
	reuseport = 1;
	jhd_listening_t *o_lis;
	if (lis->fd != -1) {
		return JHD_OK;
	}
	for (q = jhd_queue_head(&inherited_listening_queue); q != &inherited_listening_queue; q = jhd_queue_next(q)) {
		o_lis = jhd_queue_data(q, jhd_listening_t, queue);
		if ((lis->addr_text_len == o_lis->addr_text_len) && (strncmp(lis->addr_text, o_lis->addr_text, lis->addr_text_len) == 0)) {
			lis->fd = o_lis->fd;
			lis->bind = jhd_true;
			jhd_queue_only_remove(q);
			jhd_listening_free(o_lis, jhd_false);
			return JHD_OK;
		}
	}

	saddr = (struct sockaddr *)&lis->sockaddr;

	fd = socket(saddr->sa_family, SOCK_STREAM, 0);

	if (fd == -1) {
		log_stderr("systemcall socket(,SOCK_STREAM,0) failed  with %s",lis->addr_text);
		return JHD_ERROR;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuseaddr, sizeof(int)) == -1) {
		log_stderr("systemcall setsockopt(SO_REUSEADDR) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *) &reuseport, sizeof(int)) == -1) {
		log_stderr("systemcall setsockopt(SO_REUSEPORT) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}

#if (JHD_HAVE_INET6 && defined IPV6_V6ONLY)
	if (saddr->sa_family == AF_INET6) {
		int ipv6only;
		ipv6only = lis->ipv6only ? 1 : 0;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *) &ipv6only, sizeof(int)) == -1) {
			log_stderr("systemcall setsockopt(IPPROTO_IPV6) failed with %s, ignored", lis->addr_text);
		}
	}
#endif
	reuseport = 1;
	if (ioctl(fd, FIONBIO, &reuseport) == -1) {
		log_stderr("systemcall ioctl(FIONBIO) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}
	lis->fd = fd;
	return JHD_OK;
}
int32_t jhd_bind_listening_sockets() {
	struct sockaddr *saddr;
	int fd;
	uint32_t tries, failed;
	int err;
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	head = &g_listening_queue;
	for (tries = 5; tries; tries--) {
		failed = 0;
		for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
			lis = jhd_queue_data(q, jhd_listening_t, queue);
			saddr = (struct sockaddr *)&lis->sockaddr;
			fd = lis->fd;
			if (lis->bind) {
				continue;
			}
			if (bind(fd, saddr, lis->socklen) == -1) {
				err = errno;
				if (err == EADDRINUSE) {
					log_stderr("exec socket bind() failed  to exit  with %s", lis->addr_text);
					return JHD_ERROR;
				} else {
					log_err("exec socket bind() failed  to retry  with %s", lis->addr_text);
					failed = 1;
					continue;
				}
			}
			if (listen(fd, lis->backlog) == -1) {
				err = errno;
				if (err == EADDRINUSE) {
					log_stderr("exec socket listen(%d) failed  to exit  with %s", lis->backlog, lis->addr_text);
					return JHD_ERROR;
				}
				log_err("exec socket listen(%d) failed  to retry  with %s", lis->backlog, lis->addr_text);
				failed = 1;
				continue;

			}

			lis->bind = jhd_true;
		}
		if (!failed) {
			break;
		}
		usleep(500 * 1000);
	}

	if (failed) {
		log_stderr("listen socket failed to exit  with %s", lis->addr_text);
		return JHD_ERROR;
	}
	return JHD_OK;
}

static int jhd_connection_master_close_listening(jhd_listener_t* listener) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	if (jhd_process == JHD_PROCESS_MASTER || (jhd_process == JHD_PROCESS_SINGLE)) {
		head = &g_listening_queue;
		while (!jhd_queue_empty(head)) {
			q = jhd_queue_head(head);
			jhd_queue_remove(q);
			lis = jhd_queue_data(q,jhd_listening_t,queue);
			if (jhd_quit) {
				jhd_listening_free(lis,jhd_true);
			} else {
				jhd_queue_only_remove(q);
				jhd_queue_insert_tail(&inherited_listening_queue, q);
			}
		}
	}
	return JHD_OK;
}

static int jhd_connection_master_startup_listening(jhd_listener_t* listener) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	head = &g_listening_queue;
	for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
		++listening_count;
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		if (JHD_OK != jhd_open_listening_sockets(lis)) {
			goto failed;
		}
	}

	if (listening_count == 0) {
		log_stderr("listening count is %d", (int )0);
		return JHD_ERROR;
	}
	if (jhd_bind_listening_sockets() != JHD_OK) {
		goto failed;
	}

	for (q = jhd_queue_head(&inherited_listening_queue); q != &inherited_listening_queue; q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		jhd_queue_only_remove(q);
		jhd_listening_free(lis, jhd_true);
	}

	listener->handler = jhd_connection_master_close_listening;
	jhd_add_master_shutdown_listener(listener);
	return JHD_OK;

	failed:
	for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		jhd_queue_only_remove(q);
		jhd_listening_free(lis, jhd_true);
	}
	return JHD_ERROR;

}

static int jhd_connection_worker_close_listening(jhd_listener_t* listener) {
	jhd_connection_t * c;
	jhd_event_t *ev;

	int i;
	for (i = listening_count; i < connection_count; ++i) {
		c = &g_connections[i];
		if (c->fd != -1) {
			c->recv = jhd_connection_error_recv;
			ev = &c->read;
			if (ev->timer.key) {
				jhd_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
				ev->timer.key = 0;
				ev->timedout = 1;
			}
			if (ev->queue.next) {
				jhd_queue_only_remove(&ev->queue);
			}
			jhd_queue_insert_tail(&jhd_posted_events, &(ev)->queue);

			c->send = jhd_connection_error_send;
			ev = &c->write;
			if (ev->timer.key) {
				jhd_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
				ev->timer.key = 0;
				ev->timedout = 1;
			}
			if (ev->queue.next) {
				jhd_queue_only_remove(&ev->queue);
			}
			jhd_queue_insert_tail(&jhd_posted_events, &(ev)->queue);
		}
	}
	jhd_event_process_posted(&jhd_posted_events);
	jhd_event_expire_all();

	free(g_connections);
	g_connections = NULL;

	free(event_list);
	event_list = NULL;
	close(epoll_fd);
	epoll_fd = -1;
	return JHD_OK;
}







static int jhd_connection_worker_startup_listening(jhd_listener_t* listener) {
	int i;
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	jhd_connection_t *connection;
	if (connection_count == 0) {
		connection_count = 1024;
	}
	connection_count &= 0x7FFFFFFF;


	if (event_count == 0) {
		event_count = connection_count;
	}
	event_count &= 0x7FFFFFFF;;

	epoll_fd = epoll_create(event_count);
	if (epoll_fd == -1) {
		log_stderr("systemcall epoll_create(%d) failed to exit", (int ) connection_count);
		goto failed;
	}
	event_list = malloc(sizeof(struct epoll_event) * event_count);
	if (event_list == NULL) {
		log_stderr("malloc event_list(count = %u) failed with ", event_count);
		goto failed;
	}
	memset(event_list,0,sizeof(struct epoll_event) * event_count);
	i = 0;
	g_connections = malloc(sizeof(jhd_connection_t) * connection_count);
	if (g_connections) {
		memset(event_list,0,sizeof(jhd_connection_t) * connection_count);
		head = &g_listening_queue;
		i = 0;
		for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
			lis = jhd_queue_data(q, jhd_listening_t, queue);
			lis->connection = &g_connections[i];
			lis->connection->idx = i;
			lis->connection->listening = lis;
			++i;
			lis->connection->read.data = lis->connection;
			lis->connection->read.handler = jhd_connection_accept;
			lis->connection->write.data = lis->connection;
			lis->connection->write.handler = jhd_event_noop;
		}
		for (; i < connection_count;) {
			connection = &g_connections[i];
			connection->idx = i;
			connection->read.data = connection;
			connection->write.data = connection;
			++i;
			connection->data = free_connections;
			free_connections = connection;
		}

		free_connection_count = connection_count - listening_count;
		listener->handler = jhd_connection_worker_close_listening;
		jhd_add_worker_shutdown_listener(listener);
	} else {
		goto failed;
	}
	return JHD_OK;

	failed:

	if (epoll_fd != (-1)) {
		close(epoll_fd);
		epoll_fd = (-1);
	}
	if (event_list) {
		free(event_list);
		event_list = NULL;
	}
	return JHD_ERROR;

}

void jhd_connection_init() {
	epoll_fd = -1;

	listening_count = 0;
	connection_count = 0;
	g_connections = NULL;
	free_connections = NULL;
	event_count = 0;
	event_list = NULL;

	jhd_queue_init(&g_listening_queue);

	memset(&m_connection_listener, 0, sizeof(jhd_listener_t));

	m_connection_listener.handler = jhd_connection_master_startup_listening;

	jhd_add_master_startup_listener(&m_connection_listener);

	memset(&w_connection_listener, 0, sizeof(jhd_listener_t));

	w_connection_listener.handler = jhd_connection_worker_startup_listening;

	jhd_add_worker_startup_listener(&w_connection_listener);
}
ssize_t jhd_connection_error_recv(jhd_connection_t *c,u_char *buf,size_t size){
	log_notice("==>jhd_connection_error_recv<==  ");
	return JHD_ERROR;
}
ssize_t jhd_connection_error_send(jhd_connection_t *c,u_char *buf,size_t size){
	log_notice("==>jhd_connection_error_send<==  ");
	return JHD_ERROR;
}

void jhd_connection_empty_read(jhd_event_t *rv){}
void jhd_connection_empty_write(jhd_event_t *wv){}
void jhd_connection_empty_ssl_write(jhd_event_t *wv){
	//FIXME: impl
}


ssize_t jhd_connection_recv(jhd_connection_t *c, u_char *buf, size_t size) {
	ssize_t n,ret;
	int err;
	log_notice("==>jhd_connection_recv(,buf:%lu,size:%lu)",(uint64_t)buf,size);
	n = 0;
	for (;;) {
		ret = recv(c->fd, buf, size, 0);
		if (ret == 0) {
			log_debug("syscall(recv(%d,%lu,%lu,0)==0", c->fd, (uint64_t )buf, size);
			c->shutdown_remote = 1;
			if(n == 0){
				c->recv = jhd_connection_error_recv;
				n = JHD_ERROR;
			}
			break;
		} else if (ret > 0) {
			log_debug("syscall(recv(%d,%lu,%lu,0)==%ld", c->fd, (uint64_t )buf, size,ret);
			n+=ret;
			size -=ret;
			if(size ==0){
				break;
			}
			buf +=ret;
		} else {
			err = errno;
			if (err == EAGAIN) {
				log_debug("syscall(recv(fd:%d,buf:%lu,size:%lu,0)==%ld,errno=%s", c->fd, (u_int64_t )buf, size, ret, "EAGAIN");
				if(n ==0){
					n = JHD_AGAIN;
				}
				break;
			} else if (err != EINTR) {
				log_warn("syscall(recv(fd:%d,buf:%lu,size:%lu,0)==%ld,errno=%d", c->fd, (u_int64_t )buf, size,ret, err);
				if(n == 0){
					c->recv = jhd_connection_error_recv;
					n = JHD_ERROR;
				}
				break;
			}
			log_debug("syscall recv(fd:%d,buf:%lu,size:%lu,0)==%ld,errno=%s", c->fd, (u_int64_t )buf, size, ret, "EINTR");
		}
	}
	log_notice("<= jhd_connection_recv(...) = %ld",n);
	return n;
}

ssize_t jhd_connection_send(jhd_connection_t *c, u_char *buf, size_t size) {
	ssize_t ret;
	int err;
	log_notice("==>jhd_connection_send(,buf:%lu,size:%lu)",(uint64_t)buf,size);
	for (;;) {
		ret = send(c->fd, buf, size, 0);
		if (ret >= 0) {
			log_debug("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld",c->fd, (u_int64_t )buf, size, ret);
			break;
		} else {
			err = errno;
			if (err == EAGAIN) {
				log_debug("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld,errno==EAGAIN", c->fd, (u_int64_t )buf, size,ret);
				ret= JHD_AGAIN;
				break;
			} else if (err != EINTR) {
				log_warn("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld,errno==%d", c->fd, (u_int64_t )buf, size, ret, err);
				ret = JHD_ERROR;
				break;
			}
			log_debug("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld,errno==EINTR", c->fd, (u_int64_t )buf, size, ret);

		}
	}
	log_notice("<==jhd_connection_send(...) = %ld",ret);
	return ret;
}

void jhd_connection_accept_use_accept(jhd_event_t *ev) {
	jhd_listening_t* lis;
	jhd_connection_t *c, *sc;
	int fd;
	int err;
	int nb;
	log_notice("==>jhd_connection_accept_use_accept");
	if (ev->timedout) {
		ev->timedout = 0;
		return;
	}
	sc = ev->data;
	lis = sc->listening;
	log_info("begin connection acccept[%s]", lis->addr_text);
	for (;;) {
		c = NULL;
		c = free_connections;
		if (c) {
			--free_connection_count;
			free_connections = c->data;
		} else {
			log_assert(free_connection_count==0);
			log_notice("<==jhd_connection_accept_use_accept : free_connections_count ==%d", free_connection_count);
			return;
		}
		log_assert(free_connection_count>=0);
		c->socklen = sizeof(jhd_sockaddr_t);
		fd = accept(lis->fd,(struct sockaddr *) &c->sockaddr, &c->socklen);
		log_debug("exec accept(...)==%d", fd);
		if (fd == (-1)) {
			++free_connection_count;
			c->data = free_connections;
			free_connections = c;
			err = errno;
			if ((err == EAGAIN)) {
				log_notice("<== jhd_connection_accept_use_accept accept(...) ==-1,errno = EAGAIN");
				return;
			}else if(err != EINTR){
				log_err("connection acccept[%s] error with:%s", lis->addr_text, "accept(...)");
				log_notice("<== jhd_connection_accept_use_accept accept(...) ==-1,errno != EINTR");
				return;
			}else{
				continue;
			}
		}
		nb = 1;
		err = ioctl(fd, FIONBIO, &nb);
		log_debug("exec ioctl(,FIONBIO,)==%d", err);
		if (err == (-1)) {
			++free_connection_count;
			c->data = free_connections;
			free_connections = c;
			close(fd);
			log_err("connection acccept[%s] error with:%s", lis->addr_text, "ioctl(,FIONBIO,)== -1");
			log_notice("<== jhd_connection_accept_use_accept with:%s", "ioctl(,FIONBIO,)== -1");
			return;
		}
		c->fd = fd;
		if(jhd_event_add_connection(c)){
			c->close = jhd_connection_close;
			c->listening = sc->listening;
			sc->listening->connection_start(c);
		}else{
			close(fd);
			c->fd = -1;
			++free_connection_count;
			c->data = free_connections;
			free_connections = c;
		}
	}
}

void jhd_connection_accept_use_accept4(jhd_event_t *ev) {
	jhd_listening_t *lis;
	jhd_connection_t *c, *sc;
	int fd;
	int err;

	int nb;
	log_notice("==>jhd_connection_accept_use_accept4");
	if (ev->timedout) {
		ev->timedout = 0;
		return;
	}
	sc = ev->data;
	lis = sc->listening;
	log_info("begin connection acccept[%s]", lis->addr_text);
	for (;;) {
		c = NULL;
		c = free_connections;
		if (c) {
			--free_connection_count;
			free_connections = c->data;
		} else {
			log_assert(free_connection_count==0);
			log_notice("<==jhd_connection_accept_use_accept4 : free_connections_count ==%d", free_connection_count);
			return;
		}
		log_assert(free_connection_count>=0);
		c->socklen = sizeof(jhd_sockaddr_t);
		fd = accept4(lis->fd,(struct sockaddr *) &c->sockaddr, &c->socklen, SOCK_NONBLOCK);
		log_debug("exec accept4(...)==%d", fd);
		if (fd == (-1)) {
			++free_connection_count;
			c->data = free_connections;
			free_connections = c;
			err = errno;
			if ((err == EAGAIN)) {
				log_notice("<== jhd_connection_accept_use_accept4 accept4(...) ==-1,errno = EAGAIN");
				return;
			}else if(err != EINTR){
				log_err("connection acccept[%s] error with:%s", lis->addr_text, "accept(...)");
				log_notice("<== jhd_connection_accept_use_accept4 accept4(...) ==-1,errno != EINTR");
				return;
			}else{
				continue;
			}
		}
		nb = 1;
		err = ioctl(fd, FIONBIO, &nb);
		log_debug("exec ioctl(,FIONBIO,)==%d", err);
		if (err == (-1)) {
			++free_connection_count;
			c->data = free_connections;
			free_connections = c;
			close(fd);
			log_err("connection acccept[%s] error with:%s", lis->addr_text, "ioctl(,FIONBIO,)== -1");
			log_notice("<== jhd_connection_accept_use_accept4 with:%s", "ioctl(,FIONBIO,)== -1");
			return;
		}
		c->fd = fd;
		if(jhd_event_add_connection(c)){
			c->close = jhd_connection_close;
			c->listening = sc->listening;
			sc->listening->connection_start(c);
		}else{
			close(fd);
			c->fd = -1;
			++free_connection_count;
			c->data = free_connections;
			free_connections = c;
		}
	}
}
void jhd_connection_accept(jhd_event_t *ev) {
	jhd_listening_t *lis;
	jhd_connection_t *c, *sc;
	int fd;
	int err;
	int nb;
	jhd_queue_t *head,*q;
	log_notice("==>jhd_connection_accept_use_accept4");
	if (ev->timedout) {
		ev->timedout = 0;
		return;
	}
	sc = ev->data;
	lis = sc->listening;
	log_info("begin connection acccept[%s]", lis->addr_text);
	c = NULL;
	c = free_connections;

	if (c) {
		--free_connection_count;
		free_connections = c->data;
	} else {
		log_assert(free_connection_count==0);
		log_notice("<==jhd_connection_accept: free_connections_count ==%d", free_connection_count);
		return;
	}
	fd = accept4(lis->fd, (struct sockaddr *)&c->sockaddr, &c->socklen, SOCK_NONBLOCK);
	log_debug("exec accept4(...)==%d", fd);



	if (fd == (-1)) {
		++free_connection_count;
		c->data = free_connections;
		free_connections = c;
		err = errno;
		if ((err == EAGAIN)) {
			head = &g_listening_queue;
			nb = 0;
			for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
				lis = jhd_queue_data(q, jhd_listening_t, queue);
				++nb;
				lis->connection->read.handler = jhd_connection_accept_use_accept4;
			}
			log_notice("<== jhd_connection_accept accept4(...) ==-1,errno = EAGAIN");
			return;
		}else if (err == ENOSYS) {
			log_err("connection acccept[%s] error with:%s", lis->addr_text, "accept4(...)==-1,errno = ENOSYS");
			head = &g_listening_queue;
			nb = 0;
			for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
				lis = jhd_queue_data(q, jhd_listening_t, queue);
				++nb;
				lis->connection->read.handler = jhd_connection_accept_use_accept;
			}
			jhd_post_event(ev,&jhd_posted_accept_events);
			return;
		}else if(err == EINTR){
			jhd_post_event(ev,&jhd_posted_accept_events);
			return;
		}
	}
	head = &g_listening_queue;
	nb = 0;
	for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		++nb;
		lis->connection->read.handler = jhd_connection_accept_use_accept4;
	}
	c->listening = sc->listening;
	nb = 1;
	err = ioctl(fd, FIONBIO, &nb);
	log_debug("exec ioctl(,FIONBIO,)==%d", err);
	if (err == (-1)) {
		++free_connection_count;
		c->data = free_connections;
		free_connections = c;
		close(fd);
		log_err("connection acccept[%s] error with:%s", lis->addr_text, "ioctl(,FIONBIO,)== -1");
		log_notice("leave function return with:%s", "ioctl(,FIONBIO,)== -1");
		return;
	}
    c->fd = fd;
	if(jhd_event_add_connection(c)){
		c->close = jhd_connection_close;
		c->listening = sc->listening;
		sc->listening->connection_start(c);
	}else{
		close(fd);
		c->fd = -1;
		++free_connection_count;
		c->data = free_connections;
		free_connections = c;
	}
	jhd_post_event(ev,&jhd_posted_accept_events);
	log_notice("<== jhd_connection_accept OK ");
}


void jhd_connection_close(jhd_connection_t *c) {
	int op;
	struct epoll_event ee;
	if (c->fd != (-1)) {
		op = EPOLL_CTL_DEL;
		ee.events = 0;
		ee.data.ptr = NULL;
		epoll_ctl(epoll_fd, op, c->fd, &ee);
		close(c->fd);
		c->fd = -1;
	}
	++free_connection_count;
	c->data = free_connections;
	free_connections = c;
	log_notice("%s", "exec function");
}
