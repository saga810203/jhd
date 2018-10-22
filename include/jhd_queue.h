#ifndef JHD_QUEUE_H_
#define JHD_QUEUE_H_

//#include <jhd_config.h>

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


#define jhd_queue_init(QUEUE)    (QUEUE)->prev = QUEUE; (QUEUE)->next = QUEUE


#define jhd_queue_empty(QUEUE)   (QUEUE == (QUEUE)->prev)


#define jhd_queue_insert_head(QUEUE, ELE) (ELE)->next = (QUEUE)->next;(ELE)->next->prev = (ELE);(ELE)->prev = (QUEUE);(QUEUE)->next = (ELE)


#define jhd_queue_insert_after   jhd_queue_insert_head


#define jhd_queue_insert_tail(QUEUE,ELE)                                           \
    (ELE)->prev = (QUEUE)->prev;                                                    \
    (ELE)->prev->next = (ELE);                                                      \
    (ELE)->next = (QUEUE);                                                            \
    (QUEUE)->prev = (ELE)


#define jhd_queue_head(QUEUE)                                                     \
    (QUEUE)->next


#define jhd_queue_last(QUEUE)                                                     \
    (QUEUE)->prev


#define jhd_queue_sentinel(QUEUE)                                                 \
    (QUEUE)


#define jhd_queue_next(QUEUE)                                                     \
    (QUEUE)->next


#define jhd_queue_prev(QUEUE)                                                     \
    (QUEUE)->prev



#define jhd_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->next = NULL

#define jhd_queue_only_remove(x)   (x)->next->prev = (x)->prev; (x)->prev->next = (x)->next;


#define jhd_queue_data(q, type, link)   (type *) ((u_char *) q - offsetof(type, link))


#endif /* JHD_QUEUE_H_ */
