/*
 * jhd_event.c
 *
 *  Created on: May 30, 2018
 *      Author: root
 */


#include <jhd_event.h>
#include <jhd_shm.h>




static jhd_shm_t  g_event_lock;



 jhd_queue_t  jhd_posted_accept_events;
 jhd_queue_t  jhd_posted_events;
 int epoll_fd;
 jhd_rbtree_t  jhd_event_timer_rbtree;
 static jhd_rbtree_node_t  jhd_event_timer_sentinel;

void ngx_event_accept(jhd_event_t *ev);
void ngx_event_recvmsg(jhd_event_t *ev);
jhd_bool ngx_trylock_accept_mutex(){
	return __sync_fetch_and_or(g_event_lock.addr,(uint64_t)1)== 0 ? jhd_true:jhd_false;
}

void ngx_process_events_and_timers(){




}



uint64_t jhd_event_find_timer(void)
{
    int64_t      timer;
    jhd_rbtree_node_t  *node, *root, *sentinel;

    if (jhd_event_timer_rbtree.root == &jhd_event_timer_sentinel) {
        return 500;
    }

    root = jhd_event_timer_rbtree.root;
    sentinel = jhd_event_timer_rbtree.sentinel;

    node = jhd_rbtree_min(root, sentinel);

    timer = (node->key - jhd_current_msec);
    return (timer > 0 ? timer : 0);
}
void jhd_event_expire_timers(void){
    jhd_event_t        *ev;
    jhd_rbtree_node_t  *node, *root, *sentinel;
    int64_t  timer;

    sentinel = jhd_event_timer_rbtree.sentinel;

    for ( ;; ) {
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
        if(ev->queue.next){
        	jhd_queue_remove(&ev->queue);
        }

        ev->handler(ev);
    }



}





int jhd_event_init(){
	g_event_lock.addr = NULL;
	g_event_lock.size = sizeof(uint64_t);
	jhd_request_shm(&g_event_lock);
	if(!g_event_lock.addr){
		//TODO
		return JHD_ERROR;
	}

	__sync_fetch_and_or(g_event_lock.addr,(uint64_t)0);

	jhd_queue_init(&jhd_posted_accept_events);
	jhd_queue_init(&jhd_posted_events);
	jhd_rbtree_init(&jhd_event_timer_rbtree, &jhd_event_timer_sentinel,jhd_rbtree_insert_timer_value);
}


