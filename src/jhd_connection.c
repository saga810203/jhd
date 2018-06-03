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

jhd_connection_t *g_connections;

static jhd_queue_t g_listening_queue;



static jhd_listener_t m_connection_listener;
static jhd_listener_t w_connection_listener;

static jhd_connection_t *free_connections;

uint32_t listening_count;
uint32_t connection_count;
uint32_t free_connection_count;

int32_t jhd_open_listening_sockets(jhd_listening_t *lis) {
	int reuseaddr, reuseport;
	struct sockaddr *saddr;
	int fd;
	reuseaddr = 1;
	reuseport = 1;
	int err;
	if(lis->fd!=-1){
		return JHD_OK;
	}

	saddr = (struct sockaddr *) lis->sockaddr;

	fd = socket(saddr->sa_family, SOCK_STREAM, 0);

	if (fd == -1) {
		//TODO LOG
		//log_error(NGX_LOG_EMERG, log, ngx_socket_errno, 			ngx_socket_n " %V failed", &ls[i].addr_text);
		return JHD_ERROR;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuseaddr, sizeof(int)) == -1) {

		//TODO LOG
		//ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno, 						"setsockopt(SO_REUSEADDR) %V failed", &ls[i].addr_text);

		if (close(fd) == -1) {
			//ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,ngx_close_socket_n " %V failed", &ls[i].addr_text);
			//TODO LOG
		}

		return JHD_ERROR;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *) &reuseport, sizeof(int)) == -1) {
		//	ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,				"setsockopt(SO_REUSEPORT) %V failed",	&ls[i].addr_text);
		//TODO LOG

		if (close(fd) == -1) {
			//	ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,	ngx_close_socket_n " %V failed",&ls[i].addr_text);
			//TODO LOG
		}
		return JHD_ERROR;
	}

#if (JHD_HAVE_INET6 && defined IPV6_V6ONLY)

	if (saddr->sa_family == AF_INET6) {
		int ipv6only;

		ipv6only = lis.ipv6only ? 1 : 0;

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *) &ipv6only, sizeof(int)) == -1) {
			//ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,		"setsockopt(IPV6_V6ONLY) %V failed, ignored",	&ls[i].addr_text);
			//TODO log
		}
	}
#endif

	reuseport = 1;

	if (ioctl(fd, FIONBIO, &reuseport) == -1) {

		//ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno, ngx_nonblocking_n " %V failed", &ls[i].addr_text);

		//TODO: LOG

		if (close(fd) == -1) {
			//		ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,				ngx_close_socket_n " %V failed", &ls[i].addr_text);
			//TODO: LOG
		}

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
			saddr = (struct sockaddr *) lis->sockaddr;
			fd = lis->fd;

			if (lis->bind) {
				continue;
			}

			if (bind(fd, saddr, lis.socklen) == -1) {
				err = errno;

				if (err == EADDRINUSE) {
					//ngx_log_error(NGX_LOG_EMERG, log, err, "bind() to %V failed", &ls[i].addr_text);
					//TODO:LOG
					return JHD_ERROR;
				} else {
					failed = 1;
					continue;
				}
			}

			if (listen(fd, lis->backlog) == -1) {
				err = errno;
				if (err != EADDRINUSE) {
					//ngx_log_error(NGX_LOG_EMERG, log, err, "listen() to %V, backlog %d failed", &ls[i].addr_text, ls[i].backlog);
					//TODO LOG
					return JHD_ERROR;
				}

				if (err != EADDRINUSE) {
					return JHD_ERROR;
				} else {
					failed = 1;
					continue;
				}

			}

			lis->bind = jhd_true;
		}
		if (!failed) {
			break;
		}

		usleep(500 * 1000);
	}

	if (failed) {
//ngx_log_error(NGX_LOG_EMERG, log, 0, "still could not bind()");
		//TODO:LOG
		return JHD_ERROR;
	}

	return JHD_OK;
}

static int jhd_connection_master_close_listening(jhd_listener_t* listener) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	head = &g_listening_queue;
	while (!jhd_queue_empty(head)) {
		q = jhd_queue_head(head);
		lis = jhd_queue_data(q, jhd_listening_t, queue);

		if (lis->fd != -1) {
			close(lis->fd);
			lis->fd = -1;
			if (((struct sockaddr *) (lis->sockaddr))->sa_family == AF_UNIX) {
				//TODO delete file  unix socket

			}
			if (lis->ssl) {
				//TODO free ssl
			}
		}

		free(lis);
	}
	return JHD_OK;
}

static int jhd_connection_master_startup_listening(jhd_listener_t* listener) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	head = &g_listening_queue;

	for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q))
		++listening_count;
	lis = jhd_queue_data(q, jhd_listening_t, queue);
	if (JHD_OK != jhd_open_listening_sockets(lis)) {
		goto failed;
	}

	if (listening_count == 0) {
		//TODO LOG
		return JHD_ERROR;
	}
	if (jhd_bind_listening_sockets() != JHD_OK) {
		goto failed;
	}

	listener->handler = jhd_connection_master_close_listening;
	jhd_add_master_shutdown_listener(listener);
	return JHD_OK;

	failed: for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		if (lis->fd != (-1)) {
			close(lis->fd);
			lis->fd = (-1);
		}
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

//			jhd_post_event(ev, &jhd_posted_events);

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
//TODO:LOG
		goto failed;
	}

	event_list = calloc(sizeof(struct epoll_event) * event_count);
	if (event_list == NULL) {
		//TODO:LOG
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
		}

		for (; i < connection_count;) {

			connection = &g_connections[i];
			connection->idx = i;
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

