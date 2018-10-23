#ifndef JHD_EVENT_H_
#define JHD_EVENT_H_
#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_rbtree.h>
#include <jhd_time.h>

#define jhd_event_timer_set(ev)  ((ev)->timer.key)

typedef struct jhd_event_s jhd_event_t;
typedef struct jhd_listener_s jhd_listener_t;

typedef void (*jhd_event_handler_pt)(jhd_event_t *ev);

/**
 * return JHD_OK ,JHD_ERROR, JHD_AGAIN
 */
typedef int (*jhd_listener_handler_pt)(jhd_listener_t *lis);

struct jhd_event_s {
	void *data;
	jhd_event_handler_pt handler;
	jhd_queue_t queue;
	jhd_rbtree_node_t timer;
	unsigned write :1;
	unsigned error :1;
	/* to test on worker exit */
	unsigned channel :1;
	unsigned timedout :1;
};

struct jhd_listener_s {
	jhd_queue_t queue;
	void *data;
	jhd_listener_handler_pt handler;
};

typedef struct {
	volatile char value;
} jhd_atomic_flag;


jhd_inline char jhd_atomic_test_set_flag(volatile jhd_atomic_flag *ptr)
{
	register char _res = 1;
	__asm__ __volatile__(
		"	lock			\n"
		"	xchgb	%0,%1	\n"
:		"+q"(_res), "+m"(ptr->value)
:
:		"memory");
	return _res == 0;
}
jhd_inline void jhd_atomic_clear_flag(volatile jhd_atomic_flag *ptr)
{
	__asm__ __volatile__("" ::: "memory");
	ptr->value = 0;
}




/* =========================begin extern var======================== */

extern jhd_queue_t jhd_posted_accept_events;
extern jhd_queue_t jhd_posted_events;
extern int event_count;
extern int *event_accept_fds;
extern struct epoll_event *event_list;

extern jhd_rbtree_t jhd_event_timer_rbtree;
extern int epoll_fd;

/* =========================end extern var======================== */

void jhd_event_init();
void jhd_event_noop(jhd_event_t *ev);
void jhd_process_events_and_timers();

uint64_t jhd_event_find_timer(void);
void jhd_event_expire_timers(void);

void jhd_event_expire_all(void);

jhd_bool  jhd_event_add_connection(void  *c);
jhd_bool  jhd_event_del_connection(void  *c);



#define jhd_event_del_timer(EVENT) ngx_rbtree_delete(&jhd_event_timer_rbtree, &(EVENT)->timer); (EVENT)->timer.key = 0



static jhd_inline void jhd_event_add_timer(jhd_event_t *ev, uint64_t timer) {
	uint64_t key;
	int64_t diff;

	key = jhd_current_msec + timer;

	if (ev->timer.key) {
		diff = (int64_t) (key - ev->timer.key);

		if (diff > 999 || diff > (-999)) {
			jhd_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
		} else {
			return;
		}
	}
	ev->timer.key = key;
	jhd_rbtree_insert(&jhd_event_timer_rbtree, &ev->timer);
}

#define jhd_post_event(EVENT, QUEUE)  if (!((EVENT)->queue.next)) { jhd_queue_insert_tail(QUEUE, &(EVENT)->queue);}

#define jhd_delete_posted_event(EVENT)   jhd_queue_remove(&(EVENT)->queue)

#define jhd_event_from_queue(QUEUE)    jhd_queue_data(QUEUE,jhd_event_t,queue);

#define jhd_post_listener(LIS,QUEUE) ngx_queue_insert_tail(QUEUE,&(LIS)->queue);

#define jhd_delete_listener(LIS)  jhd_queue_only_remove(LIS)

#define jhd_listener_from_queue(QUEUE)   jhd_queue_data(QUEUE,jhd_listener_t,queue);

jhd_inline void  jhd_event_process_posted(jhd_queue_t *posted) {
	jhd_queue_t *q;
	jhd_event_t *ev;

	while (!jhd_queue_empty(posted)) {
		q = jhd_queue_head(posted);
		ev = jhd_queue_data(q, jhd_event_t, queue);
		jhd_delete_posted_event(ev);
		ev->handler(ev);
	}
}

#endif /* JHD_EVENT_H_ */
