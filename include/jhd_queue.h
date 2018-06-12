
/*
 * jhd_queue.h
 *
 *  Created on: 2018年5月17日
 *      Author: root
 */

#ifndef JHD_QUEUE_H_
#define JHD_QUEUE_H_

#include <jhd_config.h>

typedef struct jhd_queue_s  jhd_queue_t;
typedef struct jhd_queue_ptr_s jhd_queue_ptr_t;

struct jhd_queue_s {
    jhd_queue_t  *prev;
    jhd_queue_t  *next;
};

struct jhd_queue_ptr_s{
		jhd_queue_t  	queue;
		void			*data;
};


#define jhd_queue_init(queue)                                                     \
    (queue)->prev = queue;                                                            \
    (queue)->next = queue


#define jhd_queue_empty(queue)                                                    \
    (queue == (queue)->prev)


#define jhd_queue_insert_head(queue, ele)                                           \
    (ele)->next = (queue)->next;                                                    \
    (ele)->next->prev = ele;                                                      \
    (ele)->prev = queue;                                                            \
    (queue)->next = ele


#define jhd_queue_insert_after   jhd_queue_insert_head


#define jhd_queue_insert_tail(queue, ele)                                           \
    (ele)->prev = (queue)->prev;                                                    \
    (ele)->prev->next = (ele);                                                      \
    (ele)->next = (queue);                                                            \
    (queue)->prev = (ele)


#define jhd_queue_head(queue)                                                     \
    (queue)->next


#define jhd_queue_last(queue)                                                     \
    (queue)->prev


#define jhd_queue_sentinel(queue)                                                 \
    (queue)


#define jhd_queue_next(queue)                                                     \
    (queue)->next


#define jhd_queue_prev(queue)                                                     \
    (queue)->prev



#define jhd_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->next = NULL

#define jhd_queue_only_remove(x)   (x)->next->prev = (x)->prev; (x)->prev->next = (x)->next;


#define jhd_queue_data(q, type, link)   (type *) ((u_char *) q - offsetof(type, link))

#define jhd_queue_ptr(q,type) 	((type *)(((jhd_queue_ptr_t*)((u_char *) q - offsetof(jhd_queue_ptr_t, queue)))->data))


#endif /* JHD_QUEUE_H_ */
