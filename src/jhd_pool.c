/*
 * jhd_pool.c
 *
 *  Created on: 2018年5月17日
 *      Author: root
 */
#include <jhd_core.h>

#define JHD_BUFFER_SIZE 8192
#define JHD_MAX_POOL_SIZE (JHD_BUFFER_SIZE + sizeof(void*))
#define JHD_DEFAULT_BUFFER_COUNT  10240
static jhd_pool_t** jhd_pool_data;
static jhd_queue_t jhd_pool_config_queue = { NULL, NULL };

static jhd_pool_t *jhd_max_pool = NULL;

int jhd_add_pool_config(uint16_t size, uint32_t page_size,
		uint32_t page_count) {
	jhd_queue_t *queue, *q;
	jhd_pool_t *new_pool, *pool;

	new_pool = calloc(sizeof(jhd_pool_t));
	if (new_pool) {
		new_pool->size = size;
		new_pool->real_size = size + sizeof(uint16_t);
		if (new_pool->real_size < (sizeof(void*) + sizeof(uint16_t))) {
			new_pool->real_size = (sizeof(void*) + sizeof(uint16_t));
		}

		new_pool->page_size = page_size;
		if (new_pool->page_size < new_pool->real_size) {
			new_pool->page_size = new_pool->real_size;
		}
		new_pool->page_count = page_count;

		if (jhd_max_pool) {
			if (jhd_max_pool->size < size) {
				jhd_max_pool = new_pool;
			}
		} else {
			jhd_max_pool = new_pool;
		}

		queue = &jhd_pool_config_queue;

		if (!queue->next) {
			jhd_queue_init(queue);
		}
		for (q = jhd_queue_next(queue); q != jhd_queue_sentinel(queue); q =
				jhd_queue_next(q)) {
			pool = jhd_queue_data(q, jhd_pool_t, queue);
			if (pool->size > size) {
				q = jhd_queue_prev(q);
				jhd_queue_insert_after(q,&new_pool->queue)
				;
				return JHD_OK;
			}
		}
		jhd_queue_insert_tail(queue, &new_pool->queue);
		return JHD_OK;
	}
	return JHD_ERROR;
}

int jhd_pool_init() {
	jhd_queue_t *queue, *q;
	jhd_pool_t *pool;
	int i;

	queue = &jhd_pool_config_queue;

	if ((!jhd_max_pool) || (jhd_max_pool->size < JHD_MAX_POOL_SIZE)) {
		jhd_max_pool = calloc(sizeof(jhd_pool_t));
		if (!jhd_max_pool) {
			return JHD_ERROR;
		}

		jhd_max_pool->size = JHD_MAX_POOL_SIZE;
		jhd_max_pool->real_size = JHD_MAX_POOL_SIZE + sizeof(uint16_t);
		jhd_max_pool->page_size = jhd_max_pool->real_size * 1024;
		jhd_max_pool->page_count = 1;
		jhd_queue_init(queue);
		jhd_queue_insert_head(queue, &jhd_max_pool->queue);
	}

	jhd_pool_data = calloc(JHD_MAX_POOL_SIZE, sizeof(jhd_pool_t*));
	if (jhd_pool_data) {
		i = 1;
		for (q = jhd_queue_next(queue); q != jhd_queue_sentinel(queue); q =
				jhd_queue_next(q)) {
			pool = jhd_queue_data(q, jhd_pool_t, queue);
			for (; i <= pool->size; ++i) {
				jhd_pool_data[i] = pool;
			}
		}
		return JHD_OK;
	}
	return JHD_ERROR;

}

void* jhd_malloc(size_t size) {
	u_char *ret, *begin, *end;
	jhd_pool_t *pool = jhd_pool_data[size];
	if (pool->data) {
		ret = pool->data;
		pool->data = *((u_char**) pool->data);
		return ret;
	}
	if (pool->page_count < pool->page_used) {
		ret = calloc(pool->page_size);
		if (ret) {
			++pool->page_used;
			end = ret + pool->page_size;
			*((uint16_t*) ret) = pool->size;
			ret += sizeof(uint16_t);
			begin = ret + pool->real_size;
			for (; (begin + pool->real_size) <= end; begin += pool->real_size) {
				*((uint16_t*) begin) = pool->size;
				begin += sizeof(uint16_t);
				*((u_char**) begin) = pool->data;
				pool->data = begin;
			}
			return ret;
		}
	}
	return NULL;
}
void* jhd_calloc(size_t size) {
	u_char* ret = jhd_malloc(size_t);
	if (ret) {
		memset(ret, 0, size);
	}
	return ret;
}
void jhd_free(void* ptr) {
	jhd_pool_t *pool;
	uint16_t size = *((uint16_t*) (((u_char*) ptr) - 2));
	pool = jhd_pool_data[size];
	*((u_char**) ptr) = pool->data;
	pool->data = ptr;
}
void jhd_free_with_size(size_t size, void* ptr) {
	jhd_pool_t *pool = jhd_pool_data[size];
	*((u_char**) ptr) = pool->data;
	pool->data = ptr;
}

void  jhd_free_original(void* ptr,uint16_t size){
	jhd_pool_t *pool = jhd_pool_data[size];
	*((uint16_t*) ptr) = pool->size;
	((u_char*)ptr) +=2;
	*((u_char**) ptr) = pool->data;
	pool->data = (u_char*)ptr;
}
