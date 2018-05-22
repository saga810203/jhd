/*
 * jhd_event.h
 *
 *  Created on: 2018年5月19日
 *      Author: root
 */

#ifndef JHD_EVENT_H_
#define JHD_EVENT_H_

#include <jhd_queue.h>
#include <jhd_rbtree.h>

#define jhd_event_timer_set(ev)  ((ev)->timer.key)

typedef struct jhd_event_s jhd_event_t;
typedef struct jhd_listener_s jhd_listener_t;

typedef void (*jhd_event_handler_pt)(jhd_event_t  *ev);
typedef void (*jhd_listener_handler_pt)(jhd_listener_t  *ev);

struct jhd_event_s {
    void            *data;
    jhd_event_handler_pt handler;
    jhd_queue_t     queue;
    jhd_rbtree_node_t   timer;
    unsigned         write:1;
    unsigned         error:1;
    /* to test on worker exit */
    unsigned         channel:1;
};


struct jhd_listener_s{
		jhd_queue_t	   queue;
		void           *data;
		jhd_listener_handler_pt  handler;
};


int jhd_event_init();
void ngx_event_accept(jhd_event_t *ev);
void ngx_event_recvmsg(jhd_event_t *ev);
int ngx_trylock_accept_mutex();
void ngx_process_events_and_timers();


int ngx_event_timer_init();
uint64_t ngx_event_find_timer(void);
void ngx_event_expire_timers(void);
int64_t ngx_event_no_timers_left(void);


extern jhd_rbtree_t  jhd_event_timer_rbtree;


static jhd_inline void jhd_event_del_timer(jhd_event_t *ev)
{
    ngx_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
    ev->timer.key = 0;
}


static jhd_inline void jhd_event_add_timer(jhd_event_t *ev, uint64_t timer)
{
    uint64_t      key;
    int64_t  diff;

    key = jhd_current_msec + timer;

    if (ev->timer.key) {
        diff = (int64_t) (key - ev->timer.key);

        if(diff >999 || diff > (-999)){
        	ngx_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
        }else{
        	return;
        }
    }
    ev->timer.key = key;
    jhd_rbtree_insert(&jhd_event_timer_rbtree, &ev->timer);
}

#define jhd_post_event(ev, queue)  if (!(ev)->queue.next) { ngx_queue_insert_tail(queue, &(ev)->queue);}


#define jhd_delete_posted_event(ev)   jhd_queue_remove(&(ev)->queue)

#define jhd_event_from_queue(q)    jhd_queue_data(q,jhd_event_t,queue);

#define jhd_post_listener(lis,queue) ngx_queue_insert_tail(queue,&(lis)->queue);

#define jhd_delete_listener(lis)  jhd_queue_only_remove(lis)

#define jhd_listener_from_queue(q)   jhd_queue_data(q,jhd_listener_t,queue);

void ngx_event_process_posted(jhd_queue_t *posted);


extern jhd_queue_t  jhd_posted_accept_events;
extern jhd_queue_t  jhd_posted_events;

#endif /* JHD_EVENT_H_ */
