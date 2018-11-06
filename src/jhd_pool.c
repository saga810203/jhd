/*
 * jhd_pool.c
 *
 *  Created on: 2018年5月17日
 *      Author: root
 */
#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_queue.h>
#include <jhd_pool.h>

#define JHD_BUFFER_SIZE 8192
#define JHD_MAX_POOL_SIZE (JHD_BUFFER_SIZE + sizeof(void*))
#define JHD_DEFAULT_BUFFER_COUNT  10240
static jhd_pool_t** jhd_pool_data;
static jhd_queue_t jhd_pool_config_queue = { &jhd_pool_config_queue, &jhd_pool_config_queue };

static jhd_pool_t *jhd_max_pool = NULL;
static jhd_pool_t *jhd_min_pool = NULL;

int jhd_add_pool_config(uint16_t size, uint32_t page_size,uint32_t page_count) {
	jhd_queue_t *queue, *q;
	jhd_pool_t *new_pool, *pool;

	log_assert(size >= 8);
	log_assert(page_size >0);
	log_assert(page_size % size == 0);
	log_assert(page_count > 0);

	new_pool = malloc(sizeof(jhd_pool_t));
	if (new_pool) {
		new_pool->size = size;
		new_pool->page_size = page_size;
		new_pool->page_count = page_count;
		new_pool->page_used  = 0;
		new_pool->data  = NULL;
		if (jhd_max_pool) {
			if (jhd_max_pool->size < size) {
				jhd_max_pool = new_pool;
			}
		} else {
			jhd_max_pool = new_pool;
		}
		if(jhd_min_pool){
			if (jhd_min_pool->size > size) {
				jhd_min_pool = new_pool;
			}
		}else{
			jhd_min_pool = new_pool;
		}
		queue = &jhd_pool_config_queue;
		for (q = jhd_queue_next(queue); q != jhd_queue_sentinel(queue); q =	jhd_queue_next(q)) {
			pool = jhd_queue_data(q, jhd_pool_t, queue);
			if(pool->size == size){
				free(new_pool);
				return JHD_OK;
			}else if (pool->size > size) {
				q = jhd_queue_prev(q);
				jhd_queue_insert_after(q,&new_pool->queue);
				return JHD_OK;
			}
		}
		jhd_queue_insert_tail(queue, &new_pool->queue);
		return JHD_OK;
	}
	return JHD_ERROR;
}

int jhd_pool_init() {
	jhd_queue_t *head;
	jhd_pool_t *pool;
	int i;

	log_assert_worker();
	head = &jhd_pool_config_queue;

	if(jhd_max_pool != NULL){
		jhd_pool_data =(jhd_pool_t **) malloc(sizeof(jhd_pool_t*) * jhd_max_pool->size);
		if(jhd_pool_data != NULL){
			memset(jhd_pool_data,0,sizeof(jhd_pool_t*) * jhd_max_pool->size);
			pool = jhd_queue_data(head->next,jhd_pool_t,queue);

			for(i =1;i<= jhd_max_pool->size;++i){
				if(pool->size < i){
					jhd_queue_only_remove(&pool->queue);
					jhd_queue_init(&pool->queue);
					pool =  jhd_queue_data(head->next,jhd_pool_t,queue);
				}
				jhd_pool_data[i] = pool;
			}

			log_assert(head->next == &jhd_max_pool->queue);
			log_assert(jhd_pool_data[jhd_max_pool->size] == jhd_max_pool);
			jhd_queue_only_remove(&jhd_max_pool->queue);
			jhd_queue_init(&jhd_max_pool->queue);
			log_assert(jhd_queue_empty(head));
			return JHD_OK;
		}
	}
	return JHD_ERROR;
}

void jhd_pool_free() {
	jhd_queue_t *head;
	jhd_pool_t *pool;
	log_assert_master();
	head = &jhd_pool_config_queue;
	while(jhd_queue_has_item(head)){
		pool = jhd_queue_data(head->next,jhd_pool_t,queue);
		jhd_queue_only_remove(&pool->queue);
		free(pool);
	}
	jhd_max_pool = NULL;
	jhd_min_pool = NULL;
}

void* jhd_alloc(size_t size) {
	u_char *ret, *begin, *end;
	jhd_pool_t *pool = jhd_pool_data[size];
	log_assert_worker();
	log_assert(size <= jhd_max_pool->size);
	log_assert(size>0);
	if (pool->data) {
		ret = pool->data;
		pool->data = *((u_char**)ret);
		return ret;
	}
	if (pool->page_count < pool->page_used) {
		ret = malloc(pool->page_size);
		if (ret) {
			++pool->page_used;
			end = ret + pool->page_size;
			begin = ret + pool->size;
			for (; (begin + pool->size) <= end; begin += pool->size) {
				*((u_char**) begin) = pool->data;
				pool->data = begin;
			}
			return ret;
		}
	}
	return NULL;
}

void jhd_free(void* ptr,size_t size) {
	jhd_pool_t *pool;
	jhd_event_t *ev;
	jhd_queue_t *q;
	log_assert_worker();
	log_assert(size <= jhd_max_pool->size);
	log_assert(size>0);
	pool = jhd_pool_data[size];
	*((u_char**) ptr) = pool->data;
	pool->data = ptr;
	if(jhd_queue_has_item(&pool->queue)){
		q = pool->queue.next;
		jhd_queue_remove(q);
		ev = jhd_queue_data(q,jhd_event_t,queue);
		ev->handler(ev);
	}

}
void jhd_free_with_size(void* ptr,size_t size) {
	jhd_pool_t *pool;
	jhd_event_t *ev;
	jhd_queue_t *q;
	log_assert_worker();
	log_assert(size <= jhd_max_pool->size);
	log_assert(size>0);
	pool = jhd_pool_data[size];
	*((u_char**) ptr) = pool->data;
	pool->data = ptr;
	if(jhd_queue_has_item(&pool->queue)){
		q = pool->queue.next;
		jhd_queue_remove(q);
		ev = jhd_queue_data(q,jhd_event_t,queue);
		ev->handler(ev);
	}
}


void  jhd_wait_mem(jhd_event_t *ev,size_t size){
	jhd_pool_t *pool;
	log_assert_worker();
	pool = jhd_pool_data[size];
	log_assert(ev->queue.next == NULL);
	jhd_queue_insert_tail(&pool->queue,&ev->queue);

}
