/*
 * jhd_pool.h
 *
 *  Created on: May 14, 2018
 *      Author: root
 */

#ifndef JHD_POOL_H_
#define JHD_POOL_H_
#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_event.h>


#define MEM_SIZE_PTR(p) (((u_char*)(p))-2)

#define  MEM_SIZE(p)   (*((uint16_t*)MEM_SIZE_PTR(p)))

typedef struct jhd_pool_s jhd_pool_t;

struct jhd_pool_s{
	u_int16_t size;
	u_int32_t page_size;
	u_int32_t page_count;
	u_int32_t page_used;
	u_char* data;
	jhd_queue_t queue;
};


	int  jhd_pool_init();

	void* jhd_alloc(size_t size);
	void  jhd_free(void* ptr,size_t size);
	void  jhd_free_with_size(void* ptr,size_t size);
	void  jhd_free_original(void* ptr,uint16_t size);

	void  jhd_wait_mem(jhd_event_t *ev,size_t size);


	int	jhd_add_pool_config(uint16_t size,uint32_t page_size,uint32_t page_count);


#endif /* JHD_POOL_H_ */
