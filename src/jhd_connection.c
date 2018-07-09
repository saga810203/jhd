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

uint32_t listening_count;
uint32_t connection_count;
uint32_t free_connection_count;

jhd_listening_t* jhd_listening_get(u_char *addr_text, size_t len) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	head = &g_listening_queue;
	for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		if ((lis->addr_text_len == len) && (0 == strncmp(addr_text, lis->addr_text, len))) {
			return lis;
		}

	}
	return NULL;
}

jhd_bool jhd_listening_add_server(jhd_listening_t *lis, void *http_server) {
	void **old_http_servers;
	old_http_servers = lis->http_servers;

	lis->http_servers = calloc(sizeof(void*) * (lis->http_server_count + 1));
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
		if (lis->sockaddr.sockaddr.sa_family == AF_UNIX) {
			//TODO delete file  unix socket

		}
	}

	if (lis->ssl) {
		//TODO free ssl
	}
	if (lis->addr_text) {
		free(lis->addr_text);
	}

	if (lis->http_servers) {
		free(lis->http_servers);
	}
	free(lis);

}

int32_t jhd_open_listening_sockets(jhd_listening_t *lis) {
	int reuseaddr, reuseport;
	jhd_queue_t *q;
	size_t len;

	struct sockaddr *saddr;
	int fd;
	reuseaddr = 1;
	reuseport = 1;
	int err;
	jhd_listening_t o_lis;

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

	saddr = &lis->sockaddr;

	fd = socket(saddr->sa_family, SOCK_STREAM, 0);

	if (fd == -1) {
		fd = saddr->sa_family;
		log_stderr("exec socket(%d,SOCK_STREAM,0) failed  with %s", fd, lis->addr_text);
		return JHD_ERROR;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuseaddr, sizeof(int)) == -1) {
		log_stderr("setsockopt(SO_REUSEADDR) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *) &reuseport, sizeof(int)) == -1) {
		log_stderr("setsockopt(SO_REUSEPORT) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}

#if (JHD_HAVE_INET6 && defined IPV6_V6ONLY)

	if (saddr->sa_family == AF_INET6) {
		int ipv6only;

		ipv6only = lis.ipv6only ? 1 : 0;

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *) &ipv6only, sizeof(int)) == -1) {
			log_err("setsockopt(IPPROTO_IPV6) failed with %s", lis->addr_text);
		}
	}
#endif

	reuseport = 1;

	if (ioctl(fd, FIONBIO, &reuseport) == -1) {
		log_stderr("ioctl(FIONBIO) failed with %s", lis->addr_text);

		close(fd);
		return JHD_ERROR;
	}
	lis->fd = fd;
	return JHD_OK;
}
int32_t jhd_bind_listening_sockets() {

	struct sockaddr *saddr;
	int fd;
	uint32_t i, tries, failed;
	int err;

	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	head = &g_listening_queue;
	for (tries = 5; tries; tries--) {
		failed = 0;
		for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
			lis = jhd_listening_from_queue(q);
			saddr = &lis->sockaddr;
			fd = lis->fd;

			if (lis->bind) {
				continue;
			}

			if (bind(fd, saddr, lis.socklen) == -1) {
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
			if (jhd_quit) {
				jhd_listening_free(lis, jhd_true);
			} else {
				jhd_queue_only_remove(q);
				jhd_queue_insert_tail(&inherited_listening_queue, q);
			}
		}
	} else {
		head = &g_listening_queue;
		while (!jhd_queue_empty(head)) {
			q = jhd_queue_head(head);
			jhd_queue_remove(q);
			jhd_listening_free(lis, jhd_false);
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

	failed: for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		jhd_queue_only_remove(q);
		jhd_listening_free(lis, jhd_true);
	}
	return JHD_ERROR;

}

static ssize_t jhd_error_connection_io(jhd_connection_t *c, u_char *buf, size_t size) {
	return JHD_ERROR;
}

static int jhd_connection_worker_close_listening(jhd_listener_t* listener) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	jhd_connection_t * c;
	jhd_event_t *ev;

	int op;
	struct epoll_event ee;

	uint32_t i;
	for (i = listening_count; i < connection_count; ++i) {
		c = &g_connections[i];
		if (c->fd != -1) {
			c->recv = jhd_error_connection_io;
			ev = &c->read;
			if (ev->timer.key) {
				ngx_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
				ev->timer.key = 0;
				ev->timedout = 1;
			}
			if (ev->queue.next) {
				jhd_queue_only_remove(&ev->queue);
			}

			jhd_queue_insert_tail(&jhd_posted_events, &(ev)->queue);

			c->send = jhd_error_connection_io;
			ev = &c->write;
			if (ev->timer.key) {
				ngx_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);

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
	uint32_t i;
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	jhd_connection_t *connection;

	if (connection_count == 0) {
		connection_count = 1024;
	}
	if (event_count == 0) {
		event_count = connection_count;
	}

	epoll_fd = epoll_create(connection_count);
	if (epoll_fd == -1) {
		log_stderr("epoll_create(%d) failed to exit", (int ) connection_count);
		goto failed;
	}

	event_list = calloc(sizeof(struct epoll_event) * event_count);
	if (event_list == NULL) {
		log_stderr("calloc event_list failed with ", event_count);
		goto failed;
	}

	i = 0;
	g_connections = calloc(sizeof(jhd_connection_t) * connection_count);
	if (g_connections) {
		head = &g_listening_queue;
		for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
			lis = jhd_queue_data(q, jhd_listening_t, queue);
			lis->connection = &g_connections[i];
			lis->connection->idx = i;
			lis->connection->listening = lis;
			++i;
			lis->connection->read.data = lis->connection;
			lis->connection->read.handler = jhd_connection_accept;
			lis->connection->write.data = lis->connection;
			lis->connection->write.handler = jhd_event_noop();

		}

		for (; i < connection_count;) {

			connection = &g_connections[i];
			connection->idx = i;
			connection->read.data = connection;
			connection->write.data = connection;
			++i;
			connection->data = free_connections;
			free_connection = connection;
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

	jhd_add_master_start_listener(&m_connection_listener);

	memset(&w_connection_listener, 0, sizeof(jhd_listener_t));

	w_connection_listener.handler = jhd_connection_worker_startup_listening;

	jhd_add_worker_startup_listener(&w_connection_listener);
}

ssize_t jhd_connection_recv(jhd_connection_t *c, u_char *buf, size_t size) {
	ssize_t n;
	int err;
	log_notice("%s", "enter function");

	for (;;) {
		n = recv(c->fd, buf, size, 0);
		if (n == 0) {
			log_debug("exec recv(%d,%"PRIu64",%"PRIu64",0)==0", c->fd, (uint64_t )buf, size);
			log_notice("leave function return :%"PRId64, n);
			break;
		} else if (n > 0) {
			log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64, c->fd, (u_int64_t )buf, size, n);
			log_notice("leave function return :%"PRId64, n);
			break;
		} else {
			err = errno;
			if (err == EAGAIN) {
				log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64",errno=%s", c->fd, (u_int64_t )buf, size, n, "EAGAIN");
				log_notice("leave function return :%s", "JHD_AGAIN");
				n = JHD_AGAIN;
				break;
			} else if (err != EINTR) {
				log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64",errno=%d", c->fd, (u_int64_t )buf, size, n, err);
				log_notice("leave function return :%s", "JHD_ERROR");
				n = JHD_ERROR;
				break;
			}
			log_debug("exec recv(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64",errno=%s", c->fd, (u_int64_t )buf, size, n, "EINTR");
		}
	}
	return n;
}

ssize_t jhd_connection_send(jhd_connection_t *c, u_char *buf, size_t size) {
	ssize_t n;
	int err;

	log_notice("%s", "enter function");

	for (;;) {
		n = send(c->fd, buf, size, 0);
		if (n >= 0) {
			log_debug("exec send(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64, c->fd, (u_int64_t )buf, size, n);
			log_notice("leave function return :%"PRId64, n);
			break;
		} else {
			err = errno;
			if (err == EAGAIN) {
				log_debug("exec send(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64 ",errno==EAGAIN", c->fd, (u_int64_t )buf, size, n);
				log_notice("leave function return :%s", "JHD_AGAIN");
				n = JHD_AGAIN;
				break;
			} else if (err != EINTR) {
				log_debug("exec send(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64 ",errno==%d", c->fd, (u_int64_t )buf, size, n, err);
				log_notice("leave function return :%s", "JHD_ERROR");
				n = JHD_ERROR;
				break;

			}

			log_debug("exec send(fd:%d,buf:%"PRIu64",size:%"PRIu64",0)==%"PRId64 ",errno==EINTR", c->fd, (u_int64_t )buf, size, n);

		}
	}
	return n;
}

void jhd_connection_accept(jhd_event_t *ev) {
	static int use_accept4 = 1;

	jhd_listening_t lis;

	jhd_connection_t *c, *sc;
	int fd;
	int err;
	size_t idx;
	int nb;

	log_notice("%s", "enter function");

	c = NULL;
	if (ev->timedout) {
		return;
		ev->timedout = 0;
	}
	c = free_connections;
	if (c) {
		--free_connection_count;
		free_connections = c->data;
	} else {
		log_notice("leave function return with:%s", "free_connections_count == 0");
		return;
	}

	sc = ev->data;
	lis = sc->listening;

	log_info("begin connection acccept[%s]", lis->addr_text);

	for (;;) {

		c->socklen = sizeof(jhd_sockaddr_t);
		if (use_accept4) {
			fd = accept4(lis->fd, &c->sockaddr, &c->socklen, SOCK_NONBLOCK);
			log_debug("exec accept4(...)==%d", fd);
		} else {
			fd = accept(lis->fd, &c->sockaddr, &c->socklen);
			log_debug("exec accept(...)==%d", fd);
		}

		if (fd == (-1)) {
			err = errno;
			if ((err == EAGAIN)) {
				++free_connection_count;
				c->data = free_connections;
				free_connections = c;
				log_notice("leave function return with:%s", "accept(...) ==-1,errno = EAGAIN");
				return;
			}
			if (use_accept4 && err == ENOSYS) {
				use_accept4 = 0;
				log_warn("exec accept4(...)==-1,errno == ENOSYS so:%s", "change use_accept4[static] = 0");
				continue;
			}
			++free_connection_count;
			c->data = free_connections;
			free_connections = c;
			log_err("connection acccept[%s] error with:%s", lis->addr_text, "accept(...)");
			log_notice("leave function return with:%s", "accept(...)==-1,errno != EAGAIN ");
			return;
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
		c->data = NULL;
		c->fd = fd;
		c->close = jhd_connection_close;
		jhd_http_init_connection(c);

	}

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
