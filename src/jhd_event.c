/*
 * jhd_event.c
 *
 *  Created on: May 30, 2018
 *      Author: root
 */

#include <jhd_event.h>
#include <jhd_shm.h>
#include <jhd_connection.h>

static jhd_shm_t g_event_lock;

jhd_queue_t jhd_posted_accept_events;
jhd_queue_t jhd_posted_events;
int epoll_fd;
jhd_rbtree_t jhd_event_timer_rbtree;
jhd_rbtree_node_t jhd_event_timer_sentinel;

static jhd_listener_t w_event_listener;

static jhd_bool accepted;



void jhd_process_events_and_timers() {
	uint64_t timer, delta;
	uint32_t revents;
	int i;
	struct epoll_event ee;
	jhd_connection_t *c;
	int events;

	timer = ngx_event_find_timer();
	if (free_connection_count) {
		if ((__sync_fetch_and_or(g_event_lock.addr, (uint64_t) 1)) == 0) {
			accepted = jhd_true;
			for (i = 0; i < listening_count; ++i) {
				c = &g_connections[i];
				ee.events = EPOLLIN | EPOLLRDHUP;
				ee.data.u32 = c->idx;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->fd, &ee) == -1) {

					while (i > 0) {
						c = &g_connections[--i];
						ee.events = 0;
						ee.data.ptr = NULL;
						epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->fd, &ee);
					}
					accepted = jhd_false;
				}
			}
		}
	}
	delta = jhd_current_msec;

	events = epoll_wait(epoll_fd, event_list, (int) event_count, timer);
	if (events > 0) {
		for (i = 0; i < events; ++i) {
			c = &g_connections[event_list[i].data.u32];
			revents = event_list[i].events;
			if (revents & (EPOLLERR | EPOLLHUP)) {
				revents |= EPOLLIN | EPOLLOUT;
			}
			if ((revents & EPOLLIN)) {
				if (c->read.queue.next == NULL) {
					if (c->idx < listening_count) {
						jhd_queue_insert_tail(&jhd_posted_accept_events, &c->read.queue);
					} else {
						jhd_queue_insert_tail(&jhd_posted_events, &c->read.queue);
					}
				}
			}
			if (revents & EPOLLOUT) {
				if (c->read.queue.next == NULL) {
					jhd_queue_insert_tail(&jhd_posted_events, &c->read.queue);
				}
			}
		}
	}
	if (accepted) {
		jhd_event_process_posted(&jhd_posted_accept_events);
		accepted = jhd_false;
		__sync_fetch_and_set(g_event_lock.addr, (uint64_t) 0);
	}
	jhd_event_process_posted(&jhd_posted_events);

	jhd_update_time();
	delta = jhd_current_msec - delta;
	if (delta > timer) {
		jhd_event_expire_timers();
	}
}

jhd_bool jhd_event_add_connection(jhd_connection_t *c) {

	struct epoll_event ee;

	ee.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
	ee.data.u32 = c->idx;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
		//TODO:LOG
		return jhd_false;
	}
	return jhd_true;

}
jhd_bool jhd_event_del_connection(jhd_connection_t *c) {
	int op;
	struct epoll_event ee;
	ee.events = 0;
	ee.data.ptr = NULL;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->fd, &ee) == -1) {
		//TODO:LOG
		return jhd_false;
	}
	return jhd_true;
}

uint64_t jhd_event_find_timer(void) {
	int64_t timer;
	jhd_rbtree_node_t *node, *root, *sentinel;

	if (jhd_event_timer_rbtree.root == &jhd_event_timer_sentinel) {
		return 500;
	}

	root = jhd_event_timer_rbtree.root;
	sentinel = jhd_event_timer_rbtree.sentinel;

	node = jhd_rbtree_min(root, sentinel);

	timer = (node->key - jhd_current_msec);
	return (timer > 0 ? timer : 0);
}
void jhd_event_expire_timers(void) {
	jhd_event_t *ev;
	jhd_rbtree_node_t *node, *root, *sentinel;
	int64_t timer;

	sentinel = jhd_event_timer_rbtree.sentinel;

	for (;;) {
		root = jhd_event_timer_rbtree.root;

		if (root == sentinel) {
			return;
		}

		node = jhd_rbtree_min(root, sentinel);

		/* node->key > ngx_current_msec */
		timer = node->key - jhd_current_msec;

		if (timer > 0) {
			return;
		}

		ev = (jhd_event_t *) ((char *) node - offsetof(jhd_event_t, timer));

		ngx_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);

		ev->timer.key = 0;

		ev->timedout = 1;
		if (ev->queue.next) {
			jhd_queue_remove(&ev->queue);
		}

		ev->handler(ev);
	}

}
void jhd_event_expire_all() {
	jhd_event_t *ev;
	jhd_rbtree_node_t *node, *root, *sentinel;
	int64_t timer;

	sentinel = jhd_event_timer_rbtree.sentinel;

	for (;;) {
		root = jhd_event_timer_rbtree.root;

		if (root == sentinel) {
			return;
		}

		node = jhd_rbtree_min(root, sentinel);

		ev = (jhd_event_t *) ((char *) node - offsetof(jhd_event_t, timer));

		ngx_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);

		ev->timer.key = 0;
		ev->timedout = 1;
		if (ev->queue.next) {
			jhd_queue_remove(&ev->queue);
		}
		ev->handler(ev);
	}
}

static int jhd_event_master_startup_listening(jhd_listener_t* listener) {
	g_event_lock.addr = NULL;
	g_event_lock.size = sizeof(uint64_t);
	jhd_request_shm(&g_event_lock);
	if (!g_event_lock.addr) {
		//TODO:LOG
		return JHD_ERROR;
	}
	__sync_fetch_and_or(g_event_lock.addr, (uint64_t) 0);
	return JHD_OK;
}

void jhd_event_init() {

	w_event_listener.data = NULL;
	w_event_listener.handler = jhd_event_master_startup_listening;

	jhd_add_master_start_listener(&w_event_listener);

	jhd_queue_init(&jhd_posted_accept_events);
	jhd_queue_init(&jhd_posted_events);
	jhd_rbtree_init(&jhd_event_timer_rbtree, &jhd_event_timer_sentinel, jhd_rbtree_insert_timer_value);
	accepted = jhd_false;
}

