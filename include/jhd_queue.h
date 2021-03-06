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


#define jhd_queue_data(q, type, link)   (type *) ((u_char *) q - offsetof(type, link))

#ifdef JHD_INLINE
#define jhd_queue_init(QUEUE)    (QUEUE)->prev = QUEUE; (QUEUE)->next = QUEUE


#define jhd_queue_empty(QUEUE)   (QUEUE == (QUEUE)->prev)

#define jhd_queue_has_item(QUEUE) (QUEUE) != ((QUEUE)->prev)

#define jhd_queue_queued(QUEUE) (QUEUE) != ((QUEUE)->prev)

#define jhd_queue_not_queued(QUEUE) (QUEUE) == (QUEUE)->prev

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

#define jhd_queue_only_remove(x)   (x)->next->prev = (x)->prev; (x)->prev->next = (x)->next


#define jhd_queue_move(dst,src) (dst)->next = (src)->next;(dst)->prev = (src)->prev;\
	(src)->next->prev = dst;(src)->prev->next = dst;\
	(src)->prev = src;(src)->next = src;

#define jhd_queue_merge(dst,src) (src)->next->prev = dst; (src)->prev->next = (dst)->next; (dst)->next->prev = (src)->prev; (dst)->next = (src)->next


#else
static jhd_inline void jhd_queue_init(jhd_queue_t *QUEUE){
	(QUEUE)->prev = QUEUE;
	(QUEUE)->next = QUEUE;
}


static jhd_inline int jhd_queue_empty(jhd_queue_t *QUEUE){
	return QUEUE == QUEUE->prev;
}

static jhd_inline int jhd_queue_has_item(jhd_queue_t *QUEUE){
	return QUEUE != QUEUE->prev;
}

static jhd_inline int jhd_queue_queued(jhd_queue_t *QUEUE){
	return QUEUE != QUEUE->prev;
}

static jhd_inline int jhd_queue_not_queued(jhd_queue_t *QUEUE){
	return QUEUE == QUEUE->prev;
}

static jhd_inline void jhd_queue_move(jhd_queue_t *dst,jhd_queue_t *src){
	dst->next = src ->next;
	dst->prev = src->prev;
	src->next->prev = dst;
	src->prev->next = dst;
	src->prev = src;
	src->next = src;
}

static jhd_inline void jhd_queue_merge(jhd_queue_t *dst,jhd_queue_t *src){
	src->next->prev = dst;

	src->prev->next = dst->next;

	dst->next->prev = src->prev;

	dst->next = src->next;
}


static jhd_inline void jhd_queue_insert_head(jhd_queue_t *QUEUE,jhd_queue_t *ELE){
	(ELE)->next = (QUEUE)->next;
	(ELE)->next->prev = (ELE);
	(ELE)->prev = (QUEUE);
	(QUEUE)->next = (ELE);
}
static jhd_inline void jhd_queue_insert_after(jhd_queue_t *QUEUE,jhd_queue_t *ELE){
	(ELE)->next = (QUEUE)->next;
	(ELE)->next->prev = (ELE);
	(ELE)->prev = (QUEUE);
	(QUEUE)->next = (ELE);
}



static jhd_inline void jhd_queue_insert_tail(jhd_queue_t *QUEUE,jhd_queue_t *ELE){
	(ELE)->prev = (QUEUE)->prev;
	(ELE)->prev->next = (ELE);
	(ELE)->next = (QUEUE);
	(QUEUE)->prev = (ELE);
}


static jhd_inline jhd_queue_t* jhd_queue_head(jhd_queue_t *QUEUE){
	return (QUEUE)->next;
}

static jhd_inline jhd_queue_t* jhd_queue_last(jhd_queue_t *QUEUE){
	return (QUEUE)->prev;
}


static jhd_inline jhd_queue_t* jhd_queue_sentinel(jhd_queue_t *QUEUE) {
	return QUEUE;
}

static jhd_inline jhd_queue_t* jhd_queue_next(jhd_queue_t *QUEUE){ return  (QUEUE)->next;}
static jhd_inline jhd_queue_t* jhd_queue_prev(jhd_queue_t *QUEUE){ return  (QUEUE)->prev;}
static jhd_inline void jhd_queue_remove(jhd_queue_t *x){
	x->next->prev =x->prev;
	x->prev->next =x->next;
	x->next = NULL;
}

static jhd_inline void jhd_queue_only_remove(jhd_queue_t *x){
	x->next->prev = x->prev;
	x->prev->next = x->next;
}


#endif

#endif /* JHD_QUEUE_H_ */
